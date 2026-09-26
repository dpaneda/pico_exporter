/* run_tests.c - single test harness for pico_exporter.
 *
 * One binary, one binary's worth of build time; the subcommands it runs are
 * the checks that used to be separate test programs:
 *
 *   run_tests tls              real-endpoint TLS: valid chain, 405 on a bare
 *                              GET, stale clock rejected
 *   run_tests tls-bad          same, with the wrong trust anchor (must fail
 *                              with error 62)
 *   run_tests fallback         conn_open's oversized-record recovery; also
 *                              proves the handshake pages are dead once the
 *                              connection is up
 *   run_tests resume [URL]     probe, not a gate: reports whether the gateway
 *                              issues a TLS session id (default: the harness
 *                              endpoint), the evidence against resumption
 *   run_tests keepalive        3 POSTs over one connection, against tests/sink.py
 *   run_tests encode TS NRES FIRST COUNT [k=v ...]
 *                              OTLP encode/decode round-trip on stdin sample
 *                              lines; verifies the wire without any golden
 *                              fixture files
 *
 * The encode command is the wire gate: it never compares against frozen bytes.
 * It encodes the samples given on stdin, then decodes its own output with an
 * independent protobuf walker written below and checks every datapoint (name,
 * labels, value, timestamp), the resource attrs, the Sum/Gauge classification
 * and the first/count chunking.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mman.h>

#include "arena.h"
#include "fmt.h"
#include "bearssl.h"
#include "bearglue.h"
#include "collectors.h"
#include "otlp.h"
#include "push.h"

/* --- trust anchors -------------------------------------------------------
   bearglue.c compiles with the production anchor (DigiCert G2) as its default,
   so only the wrong-anchor set (ISRG Root X1, which did not sign this chain)
   is needed here. */

#define TA0_DN    TA0_DN_bad
#define TA0_RSA_N TA0_RSA_N_bad
#define TA0_RSA_E TA0_RSA_E_bad
#define TAs       bad_ta
#include "bearssl_ta_isrg_x1.h"
#undef TA0_DN
#undef TA0_RSA_N
#undef TA0_RSA_E
#undef TAs

/* --- shared test helpers -------------------------------------------------- */

static const char host[] = "prometheus-us-central1.grafana.net";

static void expect(const char *desc, int got, int want, int *failures) {
    if (got == want)
        printf("  ok   %s (%d)\n", desc, got);
    else {
        printf("  FAIL %s: got %d, want %d\n", desc, got, want);
        (*failures)++;
    }
}

static long long now_sec(void) { return (long long)time(NULL); }

static int handshake_only(const char *hst, unsigned long long nowSec) {
    int fd = tcp_connect_host(hst, 443, 10);
    if (fd < 0) return -99;   /* no network: caller treats this as a skip */
    uint32_t days = 719528u + (uint32_t)(nowSec / 86400);
    uint32_t secs = (uint32_t)(nowSec % 86400);
    int hs = bg_handshake(hst, fd, days, secs);
    close(fd);
    return hs;
}

static int get_status(const char *hst, unsigned long long nowSec) {
    int fd = tcp_connect_host(hst, 443, 10);
    if (fd < 0) return -99;
    uint32_t days = 719528u + (uint32_t)(nowSec / 86400);
    uint32_t secs = (uint32_t)(nowSec % 86400);
    if (bg_handshake(hst, fd, days, secs) != 0) {
        close(fd);
        return -1;
    }
    char req[256];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
                     "/api/prom/push", hst);
    int status = 0;
    if (bg_write_all((const unsigned char *)req, n) == 0) {
        unsigned char buf[4096];
        int r = bg_read_some(buf, sizeof buf);
        if (r > 0) {
            char *head = (char *)buf;
            char *nl = memchr(head, '\n', (size_t)r);
            if (nl) *nl = 0;
            const char *sp = strchr(head, ' ');
            if (sp) status = atoi(sp + 1);
        }
    }
    bg_close();
    close(fd);
    return status;
}

/* --- tls / tls-bad -------------------------------------------------------- */

static int cmd_tls(int wrong_ta) {
    if (wrong_ta) bg_set_ta(bad_ta, 1);   /* TAs_NUM == 1, see the TA header */
    if (bg_seed() == 0) {
        fprintf(stderr, "entropy seeding failed (/dev/urandom unreadable)\n");
        return 1;
    }
    printf("iobuf = %d bytes\n", bg_iobuf_size());
    if (bg_iobuf_size() != BG_IOBUF_SIZE) {
        printf("FAIL iobuf is %d, expected %d\n",
               bg_iobuf_size(), BG_IOBUF_SIZE);
        return 1;
    }

    unsigned long long now = (unsigned long long)now_sec();
    int failures = 0;

    int r = handshake_only(host, now);
    if (r == -99) {
        printf("tls_handshake: SKIP (no network)\n");
        return 0;
    }

    if (wrong_ta) {
        /* Built with the ISRG Root X1 anchor, which did not sign this chain. */
        expect("wrong trust anchor is rejected", r, 62, &failures);
    } else {
        expect("valid chain and clock", r, 0, &failures);
        expect("endpoint answers over TLS", get_status(host, now), 405,
               &failures);
        /* 10 years back is well before the leaf's notBefore. */
        expect("stale clock is rejected",
               handshake_only(host, now - 10ULL * 365 * 86400), 54, &failures);
    }

    if (failures == 0)
        printf("tls_handshake: OK\n");
    else {
        printf("tls_handshake: %d FAILURES\n", failures);
        return 1;
    }
    return 0;
}

/* --- fallback: oversized-record recovery ----------------------------------- */

static int cmd_fallback(void) {
    static const char url[] =
        "https://prometheus-us-central1.grafana.net/api/prom/push";

    struct rw_url u;
    if (!parse_rw_url(url, &u)) {
        printf("FAIL cannot parse %s\n", url);
        return 1;
    }

    bg_test_force_too_large(1);
    int before = bg_iobuf_size();
    if (before != BG_IOBUF_SIZE) {
        printf("FAIL iobuf starts at %d, expected %d\n", before, BG_IOBUF_SIZE);
        return 1;
    }

    struct rw_conn c;
    conn_open(&c, &u, "", (int64_t)time(NULL), 10);
    int after = bg_iobuf_size();

    if (!c.open) {
        printf("FAIL recovery did not connect (err='%s', iobuf %d -> %d)\n",
               c.err, before, after);
        return 1;
    }
    if (after <= before) {
        printf("FAIL iobuf did not grow (%d -> %d)\n", before, after);
        return 1;
    }
    if (!bg_hs_base) {
        printf("FAIL handshake mapping not set after TLS open\n");
        return 1;
    }
    if (madvise(bg_hs_base, bg_hs_len, MADV_DONTNEED) != 0) {
        printf("FAIL madvise on the handshake mapping: %s\n", strerror(errno));
        return 1;
    }
    int code = conn_push(&c, "", 0);
    if (code <= 0) {
        printf("FAIL request after evicting the handshake pages "
               "(code=%d, err='%s')\n", code, c.err);
        return 1;
    }
    printf("  ok   request after evicting the handshake pages (http=%d)\n",
           code);
    conn_close(&c);

    printf("tls_fallback: OK (iobuf %d -> %d, reconnected)\n", before, after);
    return 0;
}

/* --- resume: does the gateway issue a TLS session id? --------------------- */

static int cmd_resume(const char *url) {
    struct rw_url u;
    if (!parse_rw_url(url, &u)) {
        printf("FAIL cannot parse %s\n", url);
        return 1;
    }
    struct rw_conn c;
    conn_open(&c, &u, "", (int64_t)time(NULL), 10);
    if (!c.open) {
        if (strncmp(c.err, "connect:", 8) == 0) {
            printf("tls_resume: SKIP (no network: %s)\n", c.err);
            return 0;
        }
        printf("FAIL open: %s\n", c.err);
        return 1;
    }
    int n = bg_session_id_len();
    conn_close(&c);
    printf("  %s\n", u.host);
    if (n <= 0)
        printf("tls_resume: NO SESSION ID (gateway issues none; resumption "
               "cannot help; see AGENTS.md)\n");
    else
        printf("tls_resume: SESSION ID ISSUED (%d B) -- the gateway now caches "
               "sessions; revisit resumption (see AGENTS.md)\n", n);
    return 0;
}

/* --- keepalive: several POSTs on one connection ---------------------------- */

static int cmd_keepalive(void) {
    struct rw_url u;
    if (!parse_rw_url("http://127.0.0.1:31401/rw", &u)) {
        fprintf(stderr, "bad url\n");
        return 2;
    }

    struct rw_conn c;
    conn_open(&c, &u, "dXNlcjpwYXNz", 0, 5);
    if (!conn_alive(&c)) {
        printf("open failed: %s\n", c.err);
        return 1;
    }

    static const char *bodies[3] = { "aaa", "bbbb", "ccccc" };
    int ok = 1;
    for (int i = 0; i < 3; i++) {
        int code = conn_push(&c, bodies[i], strlen(bodies[i]));
        printf("push %d -> http=%d alive=%d\n", i, code, conn_alive(&c));
        if (code != 200) ok = 0;
    }
    conn_close(&c);
    return ok ? 0 : 1;
}

/* --- encode: OTLP encode/decode round-trip without golden fixtures --------- */

/* Independent protobuf wire walker. Never shares code with src/otlp.c; it only
   knows the OTLP schema, so a silent regression in the encoder's field
   numbers or frame order cannot be echoed back by the decoder. */

#define WIRE_VARINT 0
#define WIRE_FIXED64 1
#define WIRE_LEN 2

struct pb_field {
    int num, wire;
    uint64_t vi;
    const unsigned char *p;
    size_t len;
};

static int pb_next(const unsigned char *buf, size_t len, size_t *pos,
                   struct pb_field *f) {
    if (*pos >= len) return 0;
    uint64_t tag = 0;
    int shift = 0;
    for (;;) {
        if (*pos >= len) return 0;
        unsigned char b = buf[(*pos)++];
        tag |= (uint64_t)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    f->num = (int)(tag >> 3);
    f->wire = (int)(tag & 7);
    switch (f->wire) {
    case WIRE_VARINT: {
        f->vi = 0;
        shift = 0;
        for (;;) {
            if (*pos >= len) return 0;
            unsigned char b = buf[(*pos)++];
            f->vi |= (uint64_t)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        break;
    }
    case WIRE_FIXED64:
        if (*pos + 8 > len) return 0;
        f->p = buf + *pos;
        *pos += 8;
        break;
    case WIRE_LEN: {
        uint64_t n = 0;
        shift = 0;
        for (;;) {
            if (*pos >= len) return 0;
            unsigned char b = buf[(*pos)++];
            n |= (uint64_t)(b & 0x7F) << shift;
            shift += 7;
            if (!(b & 0x80)) break;
        }
        if (n > len - *pos) return 0;
        f->p = buf + *pos;
        f->len = (size_t)n;
        *pos += (size_t)n;
        break;
    }
    default:
        return 0;   /* group/32-bit wires never appear in this encoder */
    }
    return 1;
}

static double fixed64_to_double(const struct pb_field *f) {
    double d;
    memcpy(&d, f->p, 8);
    return d;
}

/* Decoded representation of the wire output. Strings point into the encoded
   buffer, which lives for the whole encode check. */
struct mkv;
struct de_point {
    const char *metric;
    struct mkv  attrs[COLLECT_MAX_LABELS];
    int         nattrs;
    int64_t     ts;
    double      val;
};
struct de_metric_kind { const char *name; int is_sum; };

static void kv_from(struct mkv *out, const unsigned char *p, size_t len) {
    /* KeyValue { key=1, value=2=AnyValue{ string_value=1 } } */
    out->k = out->v = "";
    size_t pos = 0;
    struct pb_field f;
    while (pb_next(p, len, &pos, &f)) {
        if (f.num == 1 && f.wire == WIRE_LEN) {
            char *s = malloc(f.len + 1);
            memcpy(s, f.p, f.len);
            s[f.len] = 0;
            out->k = s;
        } else if (f.num == 2 && f.wire == WIRE_LEN) {
            size_t p2 = 0;
            struct pb_field a;
            if (pb_next(f.p, f.len, &p2, &a) && a.num == 1 &&
                a.wire == WIRE_LEN) {
                char *s = malloc(a.len + 1);
                memcpy(s, a.p, a.len);
                s[a.len] = 0;
                out->v = s;
            }
        }
    }
}

/* Walks the encoded request, filling pts[] (in wire order) and res[]. Returns
   the number of datapoints; -1 on a structural error. */
static int decode_request(const unsigned char *buf, size_t len,
                          struct de_point *pts, size_t pts_cap,
                          struct mkv *res, size_t res_cap,
                          size_t *nres, struct de_metric_kind *kinds,
                          size_t kinds_cap, size_t *nkinds) {
    size_t pos = 0, np = 0;
    struct pb_field f;
    *nres = 0;
    *nkinds = 0;
    while (pb_next(buf, len, &pos, &f)) {
        if (f.num != 1 || f.wire != WIRE_LEN) return -1;   /* ResourceMetrics */
        size_t p = 0;
        struct pb_field r;
        while (pb_next(f.p, f.len, &p, &r)) {
            if (r.num == 1 && r.wire == WIRE_LEN) {        /* Resource attrs */
                size_t q = 0;
                struct pb_field a;
                while (pb_next(r.p, r.len, &q, &a)) {
                    if (a.num == 1 && a.wire == WIRE_LEN &&
                        *nres < res_cap)
                        kv_from(&res[(*nres)++], a.p, a.len);
                }
            } else if (r.num == 2 && r.wire == WIRE_LEN) { /* ScopeMetrics */
                size_t q = 0;
                struct pb_field m;
                while (pb_next(r.p, r.len, &q, &m)) {
                    if (m.num != 2 || m.wire != WIRE_LEN) continue; /* Metric */
                    const char *mname = NULL;
                    int is_sum = -1;
                    size_t mp = 0;
                    struct pb_field g;
                    while (pb_next(m.p, m.len, &mp, &g)) {
                        if (g.num == 1 && g.wire == WIRE_LEN) {
                            char *s = malloc(g.len + 1);
                            memcpy(s, g.p, g.len);
                            s[g.len] = 0;
                            mname = s;
                        } else if ((g.num == 5 || g.num == 7) &&
                                   g.wire == WIRE_LEN) {
                            is_sum = (g.num == 7);
                            size_t dpp = 0;
                            struct pb_field dp;
                            while (pb_next(g.p, g.len, &dpp, &dp)) {
                                if (dp.num == 1 && dp.wire == WIRE_LEN) {
                                    /* NumberDataPoint */
                                    if (np >= pts_cap) return -1;
                                    struct de_point *pt = &pts[np];
                                    memset(pt, 0, sizeof *pt);
                                    pt->metric = mname;
                                    size_t ap = 0;
                                    struct pb_field afd;
                                    while (pb_next(dp.p, dp.len, &ap, &afd)) {
                                        if (afd.num == 7 && afd.wire == WIRE_LEN &&
                                            pt->nattrs < COLLECT_MAX_LABELS)
                                            kv_from(&pt->attrs[pt->nattrs++],
                                                    afd.p, afd.len);
                                        else if (afd.num == 3 && afd.wire == WIRE_FIXED64) {
                                            uint64_t t = 0;
                                            memcpy(&t, afd.p, 8);
                                            pt->ts = (int64_t)t;
                                        } else if (afd.num == 4 && afd.wire == WIRE_FIXED64) {
                                            pt->val = fixed64_to_double(&afd);
                                        }
                                    }
                                    np++;
                                }
                            }
                        }
                    }
                    if (mname && is_sum >= 0 && *nkinds < kinds_cap) {
                        kinds[*nkinds].name = mname;
                        kinds[*nkinds].is_sum = is_sum;
                        (*nkinds)++;
                    }
                }
            }
        }
    }
    return (int)np;
}

static char *strip_quotes(char *s) {
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '"' && s[n - 1] == '"') {
        s[n - 1] = 0;
        return s + 1;
    }
    return s;
}

/* Input: `name{lab1=v1,lab2="v2"} value` lines on stdin, '#' lines skipped.
   Labels may be quoted (the --metrics-once text form) and their values can
   contain spaces and commas inside the quotes; only the trailing numeric token
   (the sample value) is guaranteed space-free, so it is split at the last
   space of the line. Fills s[0..n) with strdup'd strings. */
static int read_samples(struct msample *s, size_t cap) {
    char line[16384];
    size_t n = 0;
    while (n < cap && fgets(line, sizeof line, stdin)) {
        char *p = line + strspn(line, " \t");
        if (*p == '#' || *p == '\n' || *p == '\r') continue;
        size_t L = strlen(p);
        while (L > 0 &&
               (p[L - 1] == '\n' || p[L - 1] == '\r')) p[--L] = 0;
        if (L == 0) continue;

        char *val = NULL;
        for (char *q = p; *q; q++)
            if (*q == ' ' || *q == '\t') val = q;
        if (!val) continue;
        *val = 0;
        val++;
        char *vend = NULL;
        double value = strtod(val, &vend);
        if (vend == val || *vend) continue;

        struct msample *sp = &s[n];
        memset(sp, 0, sizeof *sp);
        sp->value = value;

        char *head = p;
        char *lb = strchr(head, '{');
        if (!lb) {
            sp->name = strdup(head);
            n++;
            continue;
        }
        *lb = 0;
        char *rb = strrchr(lb + 1, '}');
        if (!rb) continue;
        *rb = 0;
        sp->name = strdup(head);

        /* msample keeps its labels out of line; the harness owns this array
           and frees it with the strings below. */
        struct mkv *lv = calloc(COLLECT_MAX_LABELS, sizeof *lv);
        if (!lv) return -1;
        sp->labels = lv;
        char *lab = lb + 1;
        while (*lab && sp->nlabels < COLLECT_MAX_LABELS) {
            while (*lab == ' ' || *lab == ',') lab++;
            if (!*lab) break;
            char *start = lab;
            int inq = 0;
            while (*lab && (inq || (*lab != ',' && *lab != ' ')))
                if (*lab++ == '"') inq = !inq;
            if (*lab) { *lab = 0; lab++; }
            char *eq = strchr(start, '=');
            if (eq) {
                *eq = 0;
                lv[sp->nlabels].k = strdup(strip_quotes(start));
                lv[sp->nlabels].v = strdup(strip_quotes(eq + 1));
                sp->nlabels++;
            }
        }
        n++;
    }
    return (int)n;
}

static int is_counter_name(const char *name) {
    size_t l = strlen(name);
    return l > 6 && strcmp(name + l - 6, "_total") == 0;
}

/* Canonical label string `k=v,...` sorted by k, for multiset comparison. */
static int cmp_kv(const void *a, const void *b) {
    const struct mkv *x = a, *y = b;
    int c = strcmp(x->k, y->k);
    return c ? c : strcmp(x->v, y->v);
}

static void labels_key(const struct mkv *labels, int n, char *out, size_t cap) {
    struct mkv sorted[COLLECT_MAX_LABELS];
    out[0] = 0;
    if (n <= 0) return;                 /* labels is NULL for a bare series */
    memcpy(sorted, labels, sizeof(struct mkv) * (size_t)n);
    qsort(sorted, (size_t)n, sizeof(struct mkv), cmp_kv);
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        int w = snprintf(out + used, cap - used, "%s%s%s=%s", used ? "," : "",
                         sorted[i].k, sorted[i].v ? "=" : "", sorted[i].v);
        if (w < 0 || (size_t)w >= cap - used) break;
        used += (size_t)w;
    }
}

static int cmd_encode(int argc, char **argv) {
    /* argc/argv are as given to main: argv[1]=="encode", the parameters
       follow it directly. */
    if (argc < 6) {
        fprintf(stderr,
                "usage: run_tests encode TS NRES FIRST COUNT [k=v ...]\n");
        return 2;
    }
    int64_t ts_ns = strtoll(argv[2], NULL, 10);
    size_t res_n = (size_t)strtoul(argv[3], NULL, 10);
    size_t first = (size_t)strtoul(argv[4], NULL, 10);
    size_t count = (size_t)strtoul(argv[5], NULL, 10);
    if (argc < 6 + (int)res_n) {
        fprintf(stderr, "encode: not enough res attr args\n");
        return 2;
    }

    static struct otlp_kv res[8];
    for (size_t i = 0; i < res_n; i++) {
        char *eq = strchr(argv[6 + i], '=');
        if (!eq) {
            fprintf(stderr, "encode: res attr must be k=v\n");
            return 2;
        }
        *eq = 0;
        res[i].k = argv[6 + i];
        res[i].v = eq + 1;
    }

    static struct msample samples[COLLECT_MAX_SAMPLES];
    int ns = read_samples(samples, COLLECT_MAX_SAMPLES);
    if (ns < 0) return 2;

    struct otlp_buf out = {0};
    size_t got = otlp_encode(&out, samples, (size_t)ns, res, res_n, ts_ns,
                             first, count);

    size_t last = first + count;
    if (last > (size_t)ns) last = (size_t)ns;
    size_t want = last > first ? last - first : 0;
    if (got == 0 && want > 0) {
        fprintf(stderr, "encode: encoder produced nothing (%d source samples)\n",
                ns);
        return 1;
    }

    if (got == 0) {   /* legitimately empty slice */
        if (out.owned) free(out.data);
        printf("encode: OK (%d samples, slice [%zu,%zu), 0 datapoints)\n",
               ns, first, last);
        return 0;
    }

    static struct de_point pts[COLLECT_MAX_SAMPLES];
    static struct mkv dres[16];
    static struct de_metric_kind kinds[COLLECT_MAX_SAMPLES];
    size_t nres = 0, nkinds = 0;
    int np = decode_request((const unsigned char *)out.data, out.len, pts,
                            COLLECT_MAX_SAMPLES, dres, 16, &nres, kinds,
                            COLLECT_MAX_SAMPLES, &nkinds);
    if (np < 0) {
        printf("FAIL encode: malformed wire output\n");
        return 1;
    }

    int fails = 0;

    if ((size_t)np != want) {
        printf("FAIL encode: %d datapoints, want %zu\n", np, want);
        fails++;
    }
    if (nres != res_n) {
        printf("FAIL encode: %zu resource attrs, want %zu\n", nres, res_n);
        fails++;
    }
    for (size_t i = 0; i < nres && i < res_n; i++) {
        int seen = 0;
        for (size_t j = 0; j < res_n; j++)
            if (strcmp(res[j].k, dres[i].k) == 0 &&
                strcmp(res[j].v, dres[i].v) == 0) seen = 1;
        if (!seen) {
            printf("FAIL encode: resource attr %s=%s not on the wire\n",
                   dres[i].k, dres[i].v);
            fails++;
        }
    }

    /* Per-metric Sum/Gauge classification. */
    for (size_t i = 0; i < nkinds; i++) {
        int want_sum = is_counter_name(kinds[i].name) ? 1 : 0;
        if (kinds[i].is_sum != want_sum) {
            printf("FAIL encode: %s encoded as %s, want %s\n", kinds[i].name,
                   kinds[i].is_sum ? "sum" : "gauge",
                   want_sum ? "sum" : "gauge");
            fails++;
        }
    }

    /* Multiset of (name, sorted labels) checks, in matched by key. */
    static int used[COLLECT_MAX_SAMPLES];
    memset(used, 0, sizeof used);
    for (size_t di = 0; di < (size_t)np && di < (size_t)ns; di++) {
        struct de_point *pt = &pts[di];
        if (pt->ts != ts_ns) {
            printf("FAIL encode: point %zu ts=%lld, want %lld\n", di,
                   (long long)pt->ts, (long long)ts_ns);
            fails++;
        }
        char dkey[4096];
        labels_key(pt->attrs, pt->nattrs, dkey, sizeof dkey);
        int found = 0;
        for (size_t si = first; si < last; si++) {
            if (used[si]) continue;
            if (strcmp(samples[si].name, pt->metric) != 0) continue;
            char skey[4096];
            labels_key(samples[si].labels, samples[si].nlabels, skey,
                       sizeof skey);
            if (strcmp(skey, dkey) != 0) continue;
            if (samples[si].value != pt->val) {
                printf("FAIL encode: %s clashing value (input %g, wire %g)\n",
                       pt->metric, samples[si].value, pt->val);
                fails++;
            }
            used[si] = 1;
            found = 1;
            break;
        }
        if (!found) {
            printf("FAIL encode: wire point %s{%s}=%g has no source sample\n",
                   pt->metric, dkey, pt->val);
            fails++;
        }
    }
    for (size_t si = first; si < last; si++) {
        if (!used[si]) {
            printf("FAIL encode: input sample %s not on the wire\n",
                   samples[si].name);
            fails++;
        }
    }

    for (size_t i = 0; i < (size_t)ns; i++)
        if (samples[i].name) {
            free((void *)samples[i].name);
            for (int j = 0; j < samples[i].nlabels; j++) {
                free((void *)samples[i].labels[j].k);
                free((void *)samples[i].labels[j].v);
            }
            free((void *)samples[i].labels);
        }
    if (out.owned) free(out.data);

    if (fails) {
        printf("encode: %d FAILURES\n", fails);
        return 1;
    }
    printf("encode: OK (%d samples, slice [%zu,%zu), %d datapoints)\n",
           ns, first, last, np);
    return 0;
}

/* --- fmt: the stdio-free decimal layer against picolibc -------------------- */

/* fmt_f64_shortest must reproduce the "%.*g"-walk output byte for byte (the
 * text modes' format contract), and fmt_f64_parse must agree bit-for-bit
 * with strtod (the collectors' push-path parser). picolibc's own
 * printf/strtod are the oracle; the sweep is deterministic (xorshift). */

static unsigned long long fmt_rng = 0x243F6A8885A308D3ULL;

static unsigned long long fmt_rnd(void) {
    fmt_rng ^= fmt_rng << 13;
    fmt_rng ^= fmt_rng >> 7;
    fmt_rng ^= fmt_rng << 17;
    return fmt_rng;
}

static double fmt_bitsd(unsigned long long u) {
    double d;
    memcpy(&d, &u, 8);
    return d;
}

/* The fmt_float() walk this branch replaced: snprintf("%.*g") + strtod
 * check; the first precision that round-trips wins. */
static void fmt_walk(double v, char *out) {
    for (int prec = 1; prec <= 17; prec++) {
        snprintf(out, 40, "%.*g", prec, v);
        if (strtod(out, NULL) == v) return;
    }
}

/* Checks one double: my shortest render must byte-match the %.*g walk, and
 * my parser must read both back bit-exact. */
static void fmt_check_value(double v, int *fails, long *ntest) {
    char mine[64], walk[64];
    fmt_walk(v, walk);
    fmt_f64_shortest(mine, v);
    (*ntest)++;
    if (strcmp(mine, walk) != 0) {
        if (*fails < 10)
            printf("  FAIL fmt render: %.17g -> mine %s, %.*g-walk %s\n",
                   v, mine, walk);
        (*fails)++;
        return;
    }
    double back = 0;
    size_t used = fmt_f64_parse(mine, &back);
    unsigned long long bb, wb;
    memcpy(&bb, &back, 8);
    memcpy(&wb, &v, 8);
    if (used != strlen(mine) || bb != wb) {
        if (*fails < 10)
            printf("  FAIL fmt parse-back: %.17g str %s -> %.17g\n",
                   v, mine, back);
        (*fails)++;
    }
}

static int cmd_fmt(void) {
    static const double edges[] = {
        0.0, -0.0, 1.0, -1.0, 0.5, 1.5, 2.5, 0.1, 0.2, 0.3, 0.42, 9.15,
        26.53, 123.456789, 0.30000000000000004, 500.0, 1024.0, 268435456.0,
        1e15, 1e16, 1e17, 1e21, 1e22, 1e23, 999999.5, 99999.5,
        9007199254740992.0, 1e308, 1e-308, 1e-320, 1e-323, 5e-324,
        2.5e-323, 1.7976931348623157e308, 2.2250738585072014e-308,
        2.2250738585072011e-308, 4.9406564584124654e-324,
        123456789012345680.0, 1e30, 1e-30, 6.02e23, 1.2e9, 0.07,
    };
    int fails = 0;
    long ntest = 0;

    for (size_t i = 0; i < sizeof edges / sizeof *edges; i++)
        fmt_check_value(edges[i], &fails, &ntest);

    for (int i = 0; i < 60000; i++) {
        unsigned long long bits = fmt_rnd();
        /* 3/4 realistic exponents, 1/4 full binary64 range */
        if ((i & 3) != 3) {
            unsigned long long mant = bits & 0xFFFFFFFFFFFFFULL;
            int bias = 1023 + (int)(fmt_rnd() % 61) - 30;
            bits = (mant | ((unsigned long long)bias << 52)) |
                   (bits & 0x8000000000000000ULL);
        }
        double v = fmt_bitsd(bits);
        if (isnan(v)) continue;
        fmt_check_value(v, &fails, &ntest);
        if (fails > 10) break;
    }

    /* parser: random decimal strings vs strtod */
    char str[64];
    for (int i = 0; i < 40000; i++) {
        int nd = 1 + (int)(fmt_rnd() % 30);
        int o = 0;
        if (fmt_rnd() & 1) str[o++] = '-';
        str[o++] = (char)('1' + fmt_rnd() % 9);
        for (int j = 1; j < nd; j++) str[o++] = (char)('0' + fmt_rnd() % 10);
        int mode = (int)(fmt_rnd() % 3);
        if (mode == 1) {               /* insert a point */
            int k = 1 + (int)(fmt_rnd() % (unsigned)nd);
            memmove(str + k + 1, str + k, (size_t)(o - k));
            str[k] = '.';
            o++;
        }
        if (mode == 2)
            o += sprintf(str + o, "e%d", (int)(fmt_rnd() % 40) - 20);
        str[o] = 0;

        double want = strtod(str, NULL);
        double got = 123.0;
        size_t used = fmt_f64_parse(str, &got);
        ntest++;
        /* picolibc's strtod is off by 1 ulp on inputs longer than 17
         * significant digits (measured against glibc); inside 17 both are
         * correctly rounded and must agree bit for bit. */
        unsigned long long wg, mg;
        memcpy(&wg, &want, 8);
        memcpy(&mg, &got, 8);
        unsigned long long wl = wg - 1, wh = wg + 1;
        int ok = used == strlen(str) &&
                 (mg == wg || (nd > 17 && (mg == wl || mg == wh)));
        if (!ok) {
            if (fails < 10)
                printf("  FAIL fmt parse: %s -> %.17g (strtod %.17g)\n",
                       str, got, want);
            fails++;
        }
        if (fails > 10) break;
    }

    if (fails == 0)
        printf("fmt: OK (%ld values; render byte-identical to the %.*g walk, "
               "parser bit-equal to strtod)\n", ntest, 17);
    else
        printf("fmt: %d FAILURES (%ld values)\n", fails, ntest);
    return fails != 0;
}

static void usage(void) {
    fprintf(stderr, "usage: run_tests <tls|tls-bad|fallback|resume [URL]|keepalive|encode|fmt ...>\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 2; }
    if (strcmp(argv[1], "tls") == 0) return cmd_tls(0);
    if (strcmp(argv[1], "tls-bad") == 0) return cmd_tls(1);
    if (strcmp(argv[1], "fallback") == 0) return cmd_fallback();
    if (strcmp(argv[1], "resume") == 0)
        return cmd_resume(argc > 2 ? argv[2] :
            "https://prometheus-us-central1.grafana.net/api/prom/push");
    if (strcmp(argv[1], "keepalive") == 0) return cmd_keepalive();
    if (strcmp(argv[1], "encode") == 0) return cmd_encode(argc, argv);
    if (strcmp(argv[1], "fmt") == 0) return cmd_fmt();
    usage();
    return 2;
}