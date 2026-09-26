/* pico_exporter.c - entry point, config, push cycle loop.
 *
 * --metrics-once / --dump one-shot paths, then a 15 s cycle that collects
 * samples, batches them (BATCH) into OTLP payloads over a keep-alive
 * connection (GW_URL/GW_USER/GW_PASS), and logs the exact
 * `cycle epoch_s=... samples=... blks=... payloadB=... pushed=... http=...`
 * line.
 *
 * No stdio (issue #2): the cycle line is built with the fmt appends and
 * goes out through write(); stderr messages likewise. */

#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "arena.h"
#include "bearglue.h"
#include "collectors.h"
#include "fmt.h"
#include "idle.h"
#include "otlp.h"
#include "push.h"

/* Per-cycle arena size: virtual mapping backed by anonymous memory, evicted
   with MADV_DONTNEED each cycle. A 633-sample collection reaches ~113 kB of
   it, so this is ~9x headroom; a pathological >cap collection falls back to
   malloc but that never happens in production. Deliberately under 2 MiB: a
   larger mapping is eligible for a transparent hugepage, and on a THP
   `always` kernel the first byte touched then faults 2 MiB at once, turning a
   113 kB cycle into a 2 MiB RSS spike. arena_init also asks for
   MADV_NOHUGEPAGE. */
#define ARENA_CAP (1u << 20)

/* write-all to a fd (EINTR-safe). */
static void xwrite(int fd, const char *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w <= 0) return;
        off += (size_t)w;
    }
}

static void usage(int fd) {
    char buf[1024];
    char *o = buf;
    fmt_str_append(&o,
        "pico_exporter - OTLP/HTTP metrics push (C11)\n"
        "Usage: pico_exporter [--help] [--metrics-once] [--path.rootfs=<dir>]\n"
        "                     [--dump=<substr>]\n\n"
        "Environment:\n"
        "  GW_URL       push endpoint (https://... or http://...)\n"
        "  GW_USER      Basic-auth username\n"
        "  GW_PASS      Basic-auth password/token\n"
        "  JOB          OTel service.name (-> Prometheus job)\n"
        "  INSTANCE     OTel service.instance.id (default: uname -n)\n"
        "  INTERVAL     push interval seconds (default 15)\n"
        "  BATCH        samples per request (default 100)\n"
        "  TEXTFILE_DIR directory of *.prom files to include (default: off)\n");
#ifdef ENABLE_SYSTEMD
    fmt_str_append(&o,
        "  (built with systemd support: node_systemd_units via systemctl)\n");
#endif
    xwrite(fd, buf, (size_t)(o - buf));
}

/* Parses env var ENV as a long, or FALLBACK when unset/unparseable. */
static long parse_env_long(const char *env, long fallback) {
    const char *v = getenv(env);
    if (!v || !*v) return fallback;
    const char *end;
    long n = (long)fmt_parse_ll(v, &end);
    if (end == v || *end) return fallback;
    return n;
}

/* Reports a hit bound once, on stderr, for the one-shot modes. */
static void report_capped(const struct metrics *m) {
    if (m->ndropped || m->nlabels_capped) {
        char buf[160];
        char *o = buf;
        fmt_str_append(&o,
            "WARN sample caps hit: dropped=");
        fmt_u64_append(&o, m->ndropped);
        fmt_str_append(&o, " labels_capped=");
        fmt_u64_append(&o, m->nlabels_capped);
        fmt_str_append(&o,
            " (raise COLLECT_MAX_SAMPLES / COLLECT_MAX_LABELS)\n");
        xwrite(2, buf, (size_t)(o - buf));
    }
}

static int64_t now_wall_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (int64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static int64_t wall_seconds(void) { return (int64_t)time(NULL); }

/* pushMain() port: collects on an INTERVAL cycle and pushes OTLP batches. */
static void push_loop(const struct rw_url *u, const char *auth,
                      const char *rootfs) {
    idle_stack_floor();
    const char *job = getenv("JOB");
    if (!job || !*job) job = "integrations/node_exporter";
    /* service.instance.id defaults to the node name, which is what a node
       exporter should report. INSTANCE overrides it for the case the
       default cannot express: two exporters on one host, where identical
       instance labels would collide into one series. */
    char inst[256];
    inst[0] = 0;
    const char *inst_env = getenv("INSTANCE");
    if (inst_env && *inst_env) {
        size_t n = strlen(inst_env);
        if (n >= sizeof inst) n = sizeof inst - 1;
        memcpy(inst, inst_env, n);
        inst[n] = 0;
    } else {
        struct utsname uts;
        if (uname(&uts) == 0) {
            size_t n = strlen(uts.nodename);
            if (n >= sizeof inst) n = sizeof inst - 1;
            memcpy(inst, uts.nodename, n);
            inst[n] = 0;
        }
    }
    long interval_ms = parse_env_long("INTERVAL", 15) * 1000;
    long batch = parse_env_long("BATCH", 100);
    if (batch < 1) batch = 100;

    if (u->use_tls && bg_seed() == 0) {
        static const char msg[] = "push: entropy seeding failed, OTLP push disabled\n";
        xwrite(2, msg, sizeof msg - 1);
        return;
    }

    struct otlp_kv res[2];
    res[0].k = "service.name";
    res[0].v = job;
    res[1].k = "service.instance.id";
    res[1].v = inst;

    struct arena ar;
    arena_init(&ar, ARENA_CAP);
    collectors_set_arena(&ar);
    struct otlp_buf wbuf = { .ar = &ar };

    /* Held across cycles, not merely across the batches of one cycle. The
       handshake was 24.5 ms of the Pi's 45 ms cycle -- more CPU than the
       entire collection -- and it bought nothing: the gateway keeps an idle
       connection well past the interval (measured >200 s). A peer that does
       not is covered by the retry in the batch loop. */
    struct rw_conn conn;
    memset(&conn, 0, sizeof conn);
    conn.fd = -1;
    bool had_conn = false;      /* the process has held one at least once */

    for (;;) {
        int64_t ts_ns = now_wall_ns();
        int64_t now_sec = ts_ns / 1000000000;

        struct metrics m;
        metrics_init(&m, false, rootfs);
        m.ar = &ar;
        collect_all(&m);
        metrics_add(&m, "up", 1.0);
        size_t emitted = m.n;

        if (emitted == 0) {
            static const char msg[] = "cycle push: no samples\n";
            xwrite(2, msg, sizeof msg - 1);
            metrics_free(&m);
            otlp_buf_reset(&wbuf);
            idle_sleep(interval_ms);
            continue;
        }

        /* The OTLP view is the msamples directly: otlp_encode reads
           msample{.name,.labels,.nlabels,.value}, no per-cycle copy. */

        size_t blks = 0, tot_payload = 0, reopens = 0;
        int last_code = 0;
        const char *last_err = "";

        while (blks * (size_t)batch < emitted) {
            size_t first = blks * (size_t)batch;
            otlp_encode(&wbuf, m.samples, emitted, res, 2, ts_ns,
                        first, (size_t)batch);
            tot_payload += wbuf.len;

            /* Two attempts. A connection held across the sleep can have been
               dropped by the peer, and nothing says so until the write fails
               -- without the retry every such drop would silently cost a
               batch, which is exactly what the old code did on any mid-cycle
               failure. */
            int code = 0;
            bool no_conn = false;
            for (int attempt = 0; attempt < 2 && code <= 0; attempt++) {
                if (!conn_alive(&conn)) {
                    conn_close(&conn);      /* release a half-dead fd first */
                    conn_open(&conn, u, auth, now_sec, 8);
                    if (!conn_alive(&conn)) {
                        no_conn = true;
                        break;
                    }
                    /* The very first open of the process is not a reopen;
                       only a connection the peer took from us is. */
                    if (had_conn) reopens++;
                    had_conn = true;
                }
                code = conn_push(&conn, wbuf.data, wbuf.len);
            }
            if (no_conn) {
                last_code = 0;
                last_err = conn.err[0] ? conn.err : "connect failed";
                break;
            }
            last_code = code;
            last_err = code > 0 ? "" : "push error";
            blks++;
        }

        int ok = last_code >= 200 && last_code < 300;
        /* Only shown when it fires: a bound that is never hit should not add a
           field to every line. */
        char capped[80];
        capped[0] = 0;
        if (m.ndropped || m.nlabels_capped) {
            char *o = capped;
            fmt_str_append(&o, " dropped=");
            fmt_u64_append(&o, m.ndropped);
            fmt_str_append(&o, " labels_capped=");
            fmt_u64_append(&o, m.nlabels_capped);
            *o = 0;
        }
        /* Only when it fires. In the steady state the connection survives the
           sleep, so a reopen means the peer dropped it -- the one thing worth
           knowing about a connection now held across cycles. */
        char reop[32];
        reop[0] = 0;
        if (reopens) {
            char *o = reop;
            fmt_str_append(&o, " reopen=");
            fmt_u64_append(&o, reopens);
            *o = 0;
        }
        char line[256];
        char *o = line;
        fmt_str_append(&o, "cycle epoch_s=");
        fmt_i64_append(&o, wall_seconds());
        fmt_str_append(&o, " samples=");
        fmt_u64_append(&o, emitted);
        fmt_str_append(&o, " blks=");
        fmt_u64_append(&o, blks);
        fmt_str_append(&o, " payloadB=");
        fmt_u64_append(&o, tot_payload);
        fmt_str_append(&o, " pushed=");
        fmt_str_append(&o, ok ? "true" : "false");
        fmt_str_append(&o, " http=");
        fmt_i64_append(&o, last_code);
        if (last_err[0]) {
            fmt_str_append(&o, " err=");
            fmt_str_append(&o, last_err);
        }
        fmt_str_append(&o, capped);
        fmt_str_append(&o, reop);
        fmt_str_append(&o, "\n");
        xwrite(1, line, (size_t)(o - line));

        metrics_free(&m);
        /* After metrics_free, because that is what runs arena_reset: wbuf's
           region belongs to the cycle that just ended. */
        otlp_buf_reset(&wbuf);
        /* After the resets: the arena has already handed its pages back, and
           idle_sleep evicts what is left -- code, rodata, handshake state,
           the deep stack -- before sleeping. */
        idle_sleep(interval_ms);
    }
}

int main(int argc, char **argv) {
    /* A write on a server-closed keep-alive socket must not kill the cycle;
       the push layer turns it into a reconnect. */
    signal(SIGPIPE, SIG_IGN);

    const char *rootfs = "/";
    bool dump_once = false;
    const char *dump = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(1);
            return 0;
        } else if (strcmp(a, "--metrics-once") == 0) {
            dump_once = true;
        } else if (strncmp(a, "--dump=", 7) == 0) {
            dump = a + 7;
        } else if (strncmp(a, "--path.rootfs=", 14) == 0) {
            rootfs = a + 14;
        } else {
            usage(2);
            return 1;
        }
    }

    collectors_set_textfile_dir(getenv("TEXTFILE_DIR"));

    if (dump_once) {
        struct metrics m;
        metrics_init(&m, true, rootfs);
        collect_all(&m);
        /* The text buffer is complete; one write loop replaces fwrite. */
        size_t off = 0;
        while (off < m.tlen) {
            ssize_t w = write(1, m.txt + off, m.tlen - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
        /* No report here: text mode has no sample cap and never parses labels,
           so neither counter can move. */
        metrics_free(&m);
        return 0;
    }
    if (dump) {
        struct metrics m;
        metrics_init(&m, false, rootfs);
        collect_all(&m);
        metrics_dump(&m, dump);
        report_capped(&m);
        metrics_free(&m);
        return 0;
    }

    const char *url = getenv("GW_URL");
    if (!url || !*url) {
        usage(2);
        return 1;
    }

    struct rw_url u;
    if (!parse_rw_url(url, &u)) {
        static const char msg[] = "pico_exporter: bad GW_URL\n";
        xwrite(2, msg, sizeof msg - 1);
        return 1;
    }

    const char *user = getenv("GW_USER");
    const char *pass = getenv("GW_PASS");
    char auth[256];
    if (!basic_auth(user ? user : "", pass ? pass : "", auth, sizeof auth)) {
        static const char msg[] = "pico_exporter: credentials too long\n";
        xwrite(2, msg, sizeof msg - 1);
        return 1;
    }

    push_loop(&u, auth, rootfs);
    return 0;
}
