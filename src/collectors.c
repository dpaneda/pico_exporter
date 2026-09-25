/* collectors.c - /proc and /sys collectors under a configurable rootfs.
 *
 * --metrics-once renders Prometheus text lines; push mode collects samples.
 * Collectors detail that matters:
 *   - readProc() strips trailing whitespace; readProcInto() caps at 4096 B
 *   - /proc/stat: ints are floats divided by clkTick (SC_CLK_TCK)
 *   - diskstats/dsk: 512-byte sectors -> *512
 *   - meminfo: kB -> *1024, parens in key become underscores
 *   - fs: only /dev-based devices and overlay, statvfs-walked at rootfs mountpoint
 *   - net: sysfs statistics per device, grouped by metric when emitted */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "collectors.h"
#include "pdir.h"

static double clk_tick;

/* --- helper: path with optional rootfs --- */
static void make_path(char *path, size_t sz, const char *rootfs, const char *rel) {
    if (rootfs[0]) snprintf(path, sz, "%s/%s", rootfs, rel);
    else snprintf(path, sz, "/%s", rel);
}

#define STAT_BUF 4096

/* Every path built here is <rootfs> plus a short /proc or /sys suffix. One cap
   for all of them ends the "grow the buffer until -Wformat-truncation goes
   quiet" cascade that had hbase[2600] feeding cdir[2900] feeding fname[3400];
   512 leaves ~470 bytes for the --path.rootfs prefix. */
#define PATH_CAP 512

/* snprintf into a PATH_CAP buffer; non-zero when the path would have been
   truncated, so the caller skips the entry rather than reading a wrong path.
   Using the return value is also what keeps -Wformat-truncation quiet without
   inflating the buffer. */
#define PATH_FMT(buf, ...) (snprintf((buf), PATH_CAP, __VA_ARGS__) >= PATH_CAP)

/* Copies a kernel object name (interface, block device) into a fixed field.
   Non-zero when it did not fit, so the caller drops the entry instead of
   labelling a metric with a truncated name. IFNAMSIZ is 16 and
   BDEVNAME_SIZE is 32, so the fields are sized to the kernel's own limits. */
#define NAME_CPY(dst, src) \
    ((size_t)snprintf((dst), sizeof (dst), "%s", (src)) >= sizeof (dst))

/* Shared read buffer for the /proc and /sys files. The collectors run
   sequentially from collect_all, single-threaded, and none holds a pointer into
   this buffer past its own call, so one copy replaces a 4-8 kB stack frame in
   each of them -- and stack pages, unlike the arena, are never returned once
   touched.

   In push mode the 4 kB primary is carved from the cycle arena, which hands
   the pages back at the end of every cycle: as 4 kB of .bss it was resident
   for the life of the process, 3% of the whole resting footprint, to serve a
   buffer that is only live while a file is being parsed. The one-shot modes
   have no arena and malloc it once. Either way a file that does not fit grows
   the buffer by doubling rather than being truncated, the way a constant
   8 kB once truncated /proc/net/udp on a host with many sockets. Once the
   heap is in play it stays -- picolibc's malloc keeps whole pages anyway. */
static struct arena *g_rar;      /* cycle arena, NULL in the one-shot modes */
static char   *g_rbuf;
static size_t  g_rcap;
static size_t  g_rhint = STAT_BUF;   /* survives the reset: see rbuf_cycle_end */
static char   *g_rheap;          /* sticky malloc fallback, process-lifetime */

void collectors_set_arena(struct arena *ar) { g_rar = ar; }

/* Invalidates the arena-backed buffer; arena_reset has taken its pages back. */
static void rbuf_cycle_end(void) {
    if (g_rheap) return;
    /* Carry the size forward. A host with a /proc table above 4 kB would
       otherwise re-grow every cycle and strand the undersized block in the
       arena, the same doubling waste the sample array used to pay. */
    if (g_rcap > g_rhint) g_rhint = g_rcap;
    g_rbuf = NULL;
    g_rcap = 0;
}

static int rbuf_reserve(size_t need) {
    if (g_rbuf && need <= g_rcap) return 0;
    size_t nc = g_rcap ? g_rcap : g_rhint;
    while (nc < need) nc *= 2;
    if (!g_rheap && g_rar) {
        char *np = g_rbuf ? arena_realloc(g_rar, g_rbuf, g_rcap, nc)
                          : arena_alloc(g_rar, nc);
        if (np) {
            g_rbuf = np;
            g_rcap = nc;
            return 0;
        }
    }
    /* No arena, or it is exhausted. realloc(NULL) would hand back a fresh
       block and drop what has already been read, so the first move off the
       arena copies by hand. */
    char *np = g_rheap ? realloc(g_rheap, nc) : malloc(nc);
    if (!np) return -1;
    if (!g_rheap && g_rbuf) memcpy(np, g_rbuf, g_rcap);
    g_rheap = np;
    g_rbuf = np;
    g_rcap = nc;
    return 0;
}

/* ---------- small/file helpers ---------- */

/* Read an already-rooted absolute path (avoids re-deriving the rootfs). */
static long read_abs(const char *path, char *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t n = 0;
    while (n < cap - 1) {
        ssize_t r = read(fd, buf + n, cap - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (n == 0) return -1;
    buf[n] = 0;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' '))
        buf[--n] = 0;
    return (long)n;
}

/* readProc() equivalent: whole file, stripped, or empty on error. Buffer is
   the caller's; returns the stripped length. */
/* Reads a whole /proc or /sys file into the shared buffer. Returns it (empty
   when the file is absent), or NULL only if the buffer could not be grown.
   Reading to EOF instead of a fixed cap is what keeps the metrics correct on a
   host whose tables are larger than this one's. */
static const char *read_proc(const char *rootfs, const char *rel) {
    char path[PATH_CAP];
    make_path(path, sizeof path, rootfs, rel);
    if (rbuf_reserve(STAT_BUF) != 0) return NULL;
    g_rbuf[0] = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return g_rbuf;
    size_t n = 0;
    for (;;) {
        size_t room = g_rcap - n - 1;
        if (room == 0) {
            if (rbuf_reserve(g_rcap * 2) != 0) break;
            room = g_rcap - n - 1;
        }
        ssize_t r = read(fd, g_rbuf + n, room);
        if (r <= 0) break;         /* 0: end of file */
        n += (size_t)r;
    }
    close(fd);
    g_rbuf[n] = 0;
    while (n > 0 && (g_rbuf[n - 1] == '\n' || g_rbuf[n - 1] == '\r' ||
                     g_rbuf[n - 1] == ' '))
        g_rbuf[--n] = 0;
    return g_rbuf;
}

static bool is_all_digits(const char *s) {
    if (!*s) return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return false;
    return true;
}

static bool has_prefix(const char *s, const char *p) {
    return strncmp(s, p, strlen(p)) == 0;
}

static bool contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

/* splitWhitespace() into at most max tokens. Returns token count. */
static int split_ws(char *line, char **toks, int max) {
    int n = 0;
    char *save;
    for (char *t = strtok_r(line, " \t\r\n", &save); t && n < max;
         t = strtok_r(NULL, " \t\r\n", &save))
        toks[n++] = t;
    return n;
}

static void fmt_float(char out[40], double v) {
    for (int prec = 1; prec <= 17; prec++) {
        snprintf(out, 40, "%.*g", prec, v);
        if (strtod(out, NULL) == v) return;
    }
}

/* ---------- metrics sink ---------- */

static void txt_grow(struct metrics *m, size_t extra) {
    if (m->tlen + extra + 1 <= m->tcap) return;
    size_t ncap = m->tcap ? m->tcap : 4096;
    while (ncap < m->tlen + extra + 1) ncap *= 2;
    m->txt = realloc(m->txt, ncap);
    m->tcap = ncap;
}

static void txt_add(struct metrics *m, const char *s, size_t n) {
    txt_grow(m, n);
    memcpy(m->txt + m->tlen, s, n);
    m->tlen += n;
}

/* Sample count of the last completed collection. A host's collection is
   near-constant cycle to cycle, so sizing the array from it means the steady
   state allocates once and never copies: the doubling history (256- and
   512-slot arrays left behind in an arena that cannot free) was the single
   largest per-cycle allocation, 117 kB of the 272 kB spent on samples by a
   633-sample host. */
static size_t g_scap_hint;

static void samp_grow(struct metrics *m) {
    if (m->n < m->scap) return;
    size_t ncap = m->scap;
    if (ncap == 0) ncap = g_scap_hint ? g_scap_hint + g_scap_hint / 8 + 16 : 256;
    while (ncap <= m->n) ncap *= 2;
    if (ncap > COLLECT_MAX_SAMPLES) ncap = COLLECT_MAX_SAMPLES;
    if (m->ar) {
        /* Arena path (hot). A heap body from an earlier arena exhaustion is
           not arena_realloc's to grow, so that case copies by hand. Falls back
           to malloc when the arena is exhausted (pathologically large
           collection only). */
        bool heap = false;
        struct msample *na;
        if (m->samples && !m->heap_samples) {
            /* arena_realloc extends in place when it can and copies when it
               cannot, so this branch never copies by hand. */
            na = arena_realloc(m->ar, m->samples, m->scap * sizeof *na,
                               ncap * sizeof *na);
        } else {
            na = arena_alloc(m->ar, ncap * sizeof *na);
            if (na && m->samples)
                memcpy(na, m->samples, m->n * sizeof *m->samples);
        }
        if (!na) {
            na = malloc(ncap * sizeof *na);
            if (!na) return;            /* scap unchanged; caller must recheck */
            heap = true;
            fprintf(stderr, "WARN samp_grow: arena exhausted, malloc %zu\n",
                    ncap * sizeof *na);
            if (m->samples) memcpy(na, m->samples, m->n * sizeof *m->samples);
        }
        if (m->heap_samples) free(m->samples);
        m->samples = na;
        m->heap_samples = heap;
        m->scap = ncap;
        return;
    }
    struct msample *na = realloc(m->samples, ncap * sizeof *na);
    if (!na) return;                    /* scap unchanged; caller must recheck */
    m->samples = na;
    m->heap_samples = true;
    m->scap = ncap;
}

/* Store a <=len string copy; returns a pointer valid until metrics_free.
   Arena mode: carved from the cycle arena (evicted with it). Otherwise a
   strdup tracked in sfree[] so metrics_free can release it. */
/* Records a heap pointer so metrics_free releases it on both paths. */
static int track_heap(struct metrics *m, void *p) {
    if (m->nsfree == m->capsf) {
        size_t nc = m->capsf ? m->capsf * 2 : 16;
        char **nb = realloc(m->sfree, nc * sizeof *nb);
        if (!nb) return -1;
        m->sfree = nb;
        m->capsf = nc;
    }
    m->sfree[m->nsfree++] = p;
    return 0;
}

/* Per-cycle block allocator: the arena in push mode, tracked malloc in the
   one-shot text modes (m->ar == NULL) and when the arena is exhausted. Lets a
   collector size its scratch from the input it just read instead of a fixed
   bound that silently drops entries on a bigger host -- and the arena returns
   the pages at cycle end, unlike .bss. */
static void *m_alloc(struct metrics *m, size_t n) {
    if (n == 0) return NULL;
    if (m->ar) {
        void *p = arena_alloc(m->ar, n);
        if (p) return p;
    }
    void *p = malloc(n);
    if (!p) return NULL;
    if (track_heap(m, p) != 0) {
        free(p);
        return NULL;
    }
    return p;
}

static const char *nm_store(struct metrics *m, const char *s, size_t n) {
    char *p;
    if (m->ar) {
        p = arena_alloc(m->ar, n + 1);
        if (p) {
            memcpy(p, s, n);
            p[n] = 0;
            return p;
        }
    }
    p = malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    if (track_heap(m, p) != 0) {
        free(p);
        return NULL;
    }
    return p;
}

/* Upper bound on the rows a /proc table yields: its line count. Cheap, the
   buffer is already in memory, and it removes the guessed constant. */
static size_t count_lines(const char *s) {
    size_t n = 0;
    for (; *s; s++)
        if (*s == '\n') n++;
    return n + 1;
}

/* parseLabels port: `k="v",k2=v2,..` -> label pairs. */
static int parse_labels(struct metrics *m, const char *labels,
                        struct mkv *out, int max) {
    const char *k = labels;
    int n = 0;
    while (*k && n < max) {
        const char *eq = strchr(k, '=');
        if (!eq) break;
        size_t kl = (size_t)(eq - k);
        while (kl > 0 && (k[kl - 1] == ' ')) kl--;
        const char *v = eq + 1;
        const char *vend;
        if (*v == '"') {
            v++;
            vend = strchr(v, '"');
            if (!vend) vend = v + strlen(v);
        } else {
            vend = strchr(v, ',');
            if (!vend) vend = v + strlen(v);
            while (vend > v && (vend[-1] == ' ')) vend--;
        }
        size_t vl = (size_t)(vend - v);
        const char *ks = nm_store(m, k, kl);
        const char *vs = nm_store(m, v, vl);
        if (!ks || !vs) break;
        out[n].k = ks;
        out[n].v = vs;
        n++;
        const char *next = strchr(vend, ',');
        if (!next) break;
        k = next + 1;
    }
    return n;
}

void metrics_line(struct metrics *m, const char *name, const char *labels,
                  const char *value) {
    if (m->text_mode) {
        txt_add(m, name, strlen(name));
        if (labels[0]) {
            txt_add(m, "{", 1);
            txt_add(m, labels, strlen(labels));
            txt_add(m, "}", 1);
        }
        txt_add(m, " ", 1);
        txt_add(m, value, strlen(value));
        txt_add(m, "\n", 1);
    } else {
        char *end = NULL;
        double v = strtod(value, &end);
        if (end == value || (end && *end)) return;
        if (m->n >= COLLECT_MAX_SAMPLES - COLLECT_RESERVED_SAMPLES) {
            m->ndropped++;
            return;
        }
        samp_grow(m);
        if (m->n >= m->scap) {          /* grow failed */
            m->ndropped++;
            return;
        }
        struct msample *s = &m->samples[m->n];
        s->name = nm_store(m, name, strlen(name));
        if (!s->name) return;
        struct mkv tmp[COLLECT_MAX_LABELS];
        int nl = parse_labels(m, labels, tmp, COLLECT_MAX_LABELS);
        if (nl == COLLECT_MAX_LABELS) m->nlabels_capped++;
        s->labels = NULL;
        s->nlabels = 0;
        if (nl > 0) {
            struct mkv *lv = m_alloc(m, (size_t)nl * sizeof *lv);
            if (!lv) return;
            memcpy(lv, tmp, (size_t)nl * sizeof *lv);
            s->labels = lv;
            s->nlabels = nl;
        }
        s->value = v;
        m->n++;
    }
}

void metrics_add(struct metrics *m, const char *name, double value) {
    if (m->text_mode) return;
    if (m->n >= COLLECT_MAX_SAMPLES) return;
    samp_grow(m);
    if (m->n >= m->scap) return;        /* grow failed */
    struct msample *s = &m->samples[m->n];
    s->name = nm_store(m, name, strlen(name));
    if (!s->name) return;
    s->labels = NULL;
    s->nlabels = 0;
    s->value = value;
    m->n++;
}

/* ---------- individual collectors (same order as getMetrics) ---------- */


static double now_seconds(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static void scrape_done(struct metrics *m, const char *collector, double t0) {
    char d[40], label[80];
    fmt_float(d, now_seconds() - t0);
    snprintf(label, sizeof label, "collector=\"%s\"", collector);
    metrics_line(m, "node_scrape_collector_duration_seconds", label, d);
    metrics_line(m, "node_scrape_collector_success", label, "1");
}

/* Run body exactly once, then emit duration+success. */
#define SCRAPE(cname) \
    for (double _t0c = now_seconds(), _st = 0; !_st; \
         _st = 1, scrape_done(m, cname, _t0c))

static void collect_build(struct metrics *m) {
    metrics_line(m, "node_exporter_build_info",
                 "version=\"1.1.0\",cversion=\"0.1.0\"", "1");
}

static void collect_rss(struct metrics *m) {
    char *p = (char *)read_proc("", "proc/self/status");
    if (!p) return;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        if (has_prefix(p, "VmRSS:")) {
            long rss = 0;
            const char *sp = p + 6;
            while (*sp == ' ' || *sp == '\t') sp++;
            rss = atol(sp) * 1024;
            char val[40];
            snprintf(val, sizeof val, "%ld", rss);
            metrics_line(m, "node_exporter_resident_memory_bytes", "", val);
            break;
        }
        if (!nl) break;
        p = nl + 1;
    }
}

static void collect_uname(struct metrics *m) {
    struct utsname uts;
    if (uname(&uts) != 0) return;
    char labels[1024];
    char val[40];
    snprintf(labels, sizeof labels,
             "machine=\"%s\",nodename=\"%s\",release=\"%s\",sysname=\"%s\","
             "version=\"%s\"",
             uts.machine, uts.nodename, uts.release, uts.sysname, uts.version);
    snprintf(val, sizeof val, "1");
    metrics_line(m, "node_uname_info", labels, val);
}

static void collect_load(struct metrics *m) {
    char *toks[8];
    char *buf = (char *)read_proc(m->rootfs, "proc/loadavg");
    if (!buf) return;
    int n = split_ws(buf, toks, 8);
    if (n >= 3) {
        metrics_line(m, "node_load1", "", toks[0]);
        metrics_line(m, "node_load5", "", toks[1]);
        metrics_line(m, "node_load15", "", toks[2]);
    }
}

static void collect_uptime(struct metrics *m) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        char vbuf[40];
        fmt_float(vbuf, (double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
        metrics_line(m, "node_time_seconds", "", vbuf);
    }
}

static void collect_entropy(struct metrics *m) {
    const char *buf = read_proc(m->rootfs, "proc/sys/kernel/random/entropy_avail");
    if (buf && buf[0])
        metrics_line(m, "node_entropy_available_bits", "", buf);
    buf = read_proc(m->rootfs, "proc/sys/kernel/random/poolsize");
    if (buf && buf[0])
        metrics_line(m, "node_entropy_pool_size_bits", "", buf);
}

static const char *mem_targets[] = {
    "Active", "Buffers", "Cached", "Inactive", "MemAvailable", "MemFree",
    "MemTotal", "SReclaimable", "SwapCached", "SwapFree", "SwapTotal",
};

static void collect_memory(struct metrics *m) {
    char *toks[8];
    char *p = (char *)read_proc(m->rootfs, "proc/meminfo");
    if (!p || !*p) return;
    int found = 0;
    int ntarget = (int)(sizeof mem_targets / sizeof mem_targets[0]);
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        char *line = p;
        if (split_ws(line, toks, 8) >= 2) {
            char key[64];
            size_t kl = strcspn(toks[0], ":");
            if (kl >= sizeof key) kl = sizeof key - 1;
            memcpy(key, toks[0], kl);
            key[kl] = 0;
            for (int i = 0; i < ntarget; i++) {
                if (strcmp(key, mem_targets[i]) == 0) {
                    long long kb = strtoll(toks[1], NULL, 10);
                    char metric[128], val[40];
                    snprintf(metric, sizeof metric, "node_memory_%s_bytes",
                             key);
                    snprintf(val, sizeof val, "%lld", kb * 1024);
                    metrics_line(m, metric, "", val);
                    found++;
                    if (found == ntarget) return;
                    break;
                }
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
}

/* A line of the metricLine() output builder: single pass over /proc/stat. */
static void collect_stat(struct metrics *m) {
    char *toks[16];
    char *p = (char *)read_proc(m->rootfs, "proc/stat");
    if (!p) return;
    static const char *modes[] = {
        "mode=\"user\"", "mode=\"nice\"", "mode=\"system\"", "mode=\"idle\"",
        "mode=\"iowait\"", "mode=\"irq\"", "mode=\"softirq\"", "mode=\"steal\"",
    };
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        char *line = p;
        int n = split_ws(line, toks, 16);
        if (n >= 2) {
            char vbuf[40];
            if (strcmp(toks[0], "cpu") == 0) {
                if (n < 9) goto nextline;
                for (int i = 0; i < 8; i++) {
                    double d = strtod(toks[i + 1], NULL) / clk_tick;
                    fmt_float(vbuf, d);
                    metrics_line(m, "node_cpu_seconds_total", modes[i],
                                 vbuf);
                }
            } else if (strcmp(toks[0], "intr") == 0) {
                metrics_line(m, "node_intr_total", "", toks[1]);
            } else if (strcmp(toks[0], "ctxt") == 0) {
                metrics_line(m, "node_context_switches_total", "", toks[1]);
            } else if (strcmp(toks[0], "btime") == 0) {
                metrics_line(m, "node_boot_time_seconds", "", toks[1]);
            } else if (strcmp(toks[0], "processes") == 0) {
                metrics_line(m, "node_forks_total", "", toks[1]);
            } else if (strcmp(toks[0], "procs_running") == 0) {
                metrics_line(m, "node_procs_running", "", toks[1]);
            } else if (strcmp(toks[0], "procs_blocked") == 0) {
                metrics_line(m, "node_procs_blocked", "", toks[1]);
            }
        }
    nextline:
        if (!nl) break;
        p = nl + 1;
    }
}

static void collect_disk_bytes(struct metrics *m) {
    char *p = (char *)read_proc(m->rootfs, "proc/diskstats");
    if (!p) return;
    /* read+written bytes per device, emitted grouped by metric. */
    struct devv { char dev[32]; char r[40], w[40]; };
    size_t dmax = count_lines(p);
    struct devv *devs = m_alloc(m, dmax * sizeof *devs);
    if (!devs) return;
    int nd = 0;
    char *toks[24];
    while (*p && (size_t)nd < dmax) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        int n = split_ws(p, toks, 24);
        if (n >= 11) {
            const char *dev = toks[2];
            if (has_prefix(dev, "loop") || has_prefix(dev, "ram")) {
                ; /* skip */
            } else {
                struct devv *d = &devs[nd++];
                snprintf(d->dev, sizeof d->dev, "%s", dev);
                snprintf(d->r, sizeof d->r, "%lld",
                         strtoll(toks[5], NULL, 10) * 512);
                snprintf(d->w, sizeof d->w, "%lld",
                         strtoll(toks[9], NULL, 10) * 512);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    char v[300], l[300];
    for (int i = 0; i < nd; i++) {
        snprintf(l, sizeof l, "device=\"%.255s\"", devs[i].dev);
        metrics_line(m, "node_disk_read_bytes_total", l, devs[i].r);
    }
    for (int i = 0; i < nd; i++) {
        snprintf(v, sizeof v, "device=\"%.255s\"", devs[i].dev);
        metrics_line(m, "node_disk_written_bytes_total", v, devs[i].w);
    }
}

static void collect_filefd(struct metrics *m) {
    char *toks[8];
    char *buf = (char *)read_proc(m->rootfs, "proc/sys/fs/file-nr");
    if (!buf) return;
    int n = split_ws(buf, toks, 8);
    if (n >= 3) {
        metrics_line(m, "node_filefd_allocated", "", toks[0]);
        metrics_line(m, "node_filefd_maximum", "", toks[2]);
    }
}

static void collect_filesystem(struct metrics *m) {
    char *p = (char *)read_proc(m->rootfs, "proc/mounts");
    if (!p || !*p) return;
    /* One row per mount, six values each (this was six parallel arrays holding
       an identical copy of the label string). Sized from the line count of
       /proc/mounts, before the parse loop overwrites the newlines: a fixed
       bound dropped mounts past the 16th in silence on a bigger host, and cost
       its full size in .bss on this one. */
    enum { FS_AVAIL = 0, FS_SIZE, FS_FREE, FS_FILES, FS_FILESFREE, FS_RO,
           FS_NVAL };
    struct fsrow { char l[256]; char v[FS_NVAL][40]; };
    struct seenm { char mp[128]; };
    size_t fsmax = count_lines(p);
    struct fsrow *fsr = m_alloc(m, fsmax * sizeof *fsr);
    struct seenm *seen = m_alloc(m, fsmax * sizeof *seen);
    if (!fsr || !seen) return;
    int nfs = 0;
    int nseen = 0;
    char *toks[16];
    static const char *devbad[] = { "loop", "ram" };
    static const char *mntbad[] = { "containers", "docker", "kubelet",
                                    "podman" };
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        int n = split_ws(p, toks, 16);
        if (n >= 3) {
            const char *dev = toks[0], *mp = toks[1], *fst = toks[2];
            if (!(has_prefix(dev, "/dev/") || strcmp(dev, "overlay") == 0)) {
                goto next;
            }
            for (size_t i = 0; i < sizeof devbad / sizeof *devbad; i++)
                if (contains(dev, devbad[i])) goto next;
            for (size_t i = 0; i < sizeof mntbad / sizeof *mntbad; i++)
                if (contains(mp, mntbad[i])) goto next;
            int dup = 0;
            for (int i = 0; i < nseen; i++)
                if (strcmp(seen[i].mp, mp) == 0) { dup = 1; break; }
            if (dup) goto next;
            if ((size_t)nseen < fsmax)
                snprintf(seen[nseen++].mp, sizeof seen[0].mp, "%s", mp);

            char full[PATH_CAP];
            if (m->rootfs[0]) {
                if (PATH_FMT(full, "%s%s", m->rootfs, mp)) goto next;
                /* collapse // */
                char *out = full;
                for (char *in = full; *in; in++) {
                    if (*in == '/' && in > full && in[-1] == '/') continue;
                    *out++ = *in;
                }
                *out = 0;
            } else {
                if (PATH_FMT(full, "%s", mp)) goto next;
            }
            struct statvfs fs;
            if (statvfs(full, &fs) != 0) goto next;
            uint64_t bsize = fs.f_bsize;
            uint64_t total = fs.f_blocks * bsize;
            if (total == 0) goto next;

            if ((size_t)nfs < fsmax) {
                struct fsrow *r = &fsr[nfs++];
                size_t vz = sizeof r->v[0];
                snprintf(r->l, sizeof r->l,
                         "device=\"%s\",mountpoint=\"%s\",fstype=\"%s\"",
                         dev, mp, fst);
                snprintf(r->v[FS_AVAIL], vz, "%llu",
                         (unsigned long long)(fs.f_bavail * bsize));
                snprintf(r->v[FS_SIZE], vz, "%llu", (unsigned long long)total);
                snprintf(r->v[FS_FREE], vz, "%llu",
                         (unsigned long long)(fs.f_bfree * bsize));
                snprintf(r->v[FS_FILES], vz, "%llu",
                         (unsigned long long)fs.f_files);
                snprintf(r->v[FS_FILESFREE], vz, "%llu",
                         (unsigned long long)fs.f_ffree);
                snprintf(r->v[FS_RO], vz, "%s", (fs.f_flag & 1) ? "1" : "0");
            }
        }
    next:
        if (!nl) break;
        p = nl + 1;
    }
    /* Order matters for the text output: all of one metric, then the next,
       mounts in /proc/mounts order. */
    static const char *const fsnames[FS_NVAL] = {
        "node_filesystem_avail_bytes", "node_filesystem_size_bytes",
        "node_filesystem_free_bytes",  "node_filesystem_files",
        "node_filesystem_files_free",  "node_filesystem_readonly",
    };
    for (int k = 0; k < FS_NVAL; k++)
        for (int i = 0; i < nfs; i++)
            metrics_line(m, fsnames[k], fsr[i].l, fsr[i].v[k]);
}

struct nstat { const char *file, *suffix; const char *mtype; };

static void collect_network(struct metrics *m) {
    enum { NET_NSTATS = 8 };
    static const struct nstat nstats[NET_NSTATS] = {
        { "rx_bytes", "receive_bytes_total", "counter" },
        { "tx_bytes", "transmit_bytes_total", "counter" },
        { "rx_packets", "receive_packets_total", "counter" },
        { "tx_packets", "transmit_packets_total", "counter" },
        { "rx_dropped", "receive_drop_total", "counter" },
        { "tx_dropped", "transmit_drop_total", "counter" },
        { "rx_errors", "receive_errs_total", "counter" },
        { "tx_errors", "transmit_errs_total", "counter" },
    };
    size_t NN = sizeof nstats / sizeof nstats[0];
    /* One row per interface, one value per statistic (this was bufs[8][64],
       36,864 B whose 4,608 B row stride dirtied ~8 pages for ~1.7 kB of data,
       with the device name repeated once per statistic). Sized from a counting
       pass over the directory, so a host with more interfaces than the old
       fixed bound no longer loses them. */
    struct nif { char dev[32]; char val[NET_NSTATS][40]; };
    char base[PATH_CAP];
    if (m->rootfs[0])
        make_path(base, sizeof base, m->rootfs, "sys/class/net");
    else
        strcpy(base, "/sys/class/net");
    struct pdir d;
    if (pdir_open(&d, base) != 0) return;
    const char *e;
    size_t nmax = 0;
    while ((e = pdir_next(&d)) != NULL) nmax++;
    pdir_close(&d);
    struct nif *ifs = m_alloc(m, nmax * sizeof *ifs);
    if (!ifs) return;
    int nifs = 0;
    if (pdir_open(&d, base) != 0) return;
    while ((e = pdir_next(&d)) != NULL) {
        if (strcmp(e, ".") == 0 || strcmp(e, "..") == 0 ||
            strcmp(e, "lo") == 0)
            continue;
        if ((size_t)nifs >= nmax) break;
        struct nif *n = &ifs[nifs];
        /* Static storage reused across cycles: clear before filling so a
           statistic that disappears cannot leave the previous value behind. */
        memset(n, 0, sizeof *n);
        int got = 0;
        for (size_t i = 0; i < NN; i++) {
            char path[PATH_CAP];
            if (PATH_FMT(path, "%s/%s/statistics/%s", base, e,
                         nstats[i].file))
                continue;
            char vb[40];
            if (read_abs(path, vb, sizeof vb) > 0) {
                snprintf(n->val[i], sizeof n->val[i], "%s", vb);
                got = 1;
            }
        }
        if (!got) continue;
        if (NAME_CPY(n->dev, e)) continue;
        nifs++;
    }
    pdir_close(&d);
    for (size_t i = 0; i < NN; i++) {
        char mname[96];
        snprintf(mname, sizeof mname, "node_network_%s", nstats[i].suffix);
        for (int j = 0; j < nifs; j++) {
            if (!ifs[j].val[i][0]) continue;
            char l[300];
            snprintf(l, sizeof l, "device=\"%.255s\"", ifs[j].dev);
            metrics_line(m, mname, l, ifs[j].val[i]);
        }
    }
}

static char *trim_colon_ws(char *s) {
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ':' || e[-1] == ' ' || e[-1] == '\t')) *--e = 0;
    return s;
}

static void collect_meminfo_extras(struct metrics *m) {
    char *toks[8];
    char *p = (char *)read_proc(m->rootfs, "proc/meminfo");
    if (!p) return;
    int i;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        int n = split_ws(p, toks, 8);
        if (n >= 2) {
            char key[64];
            size_t kl = strcspn(toks[0], ":");
            /* skip the 11 target keys (they come from the memory section) */
            int skip = 0;
            for (i = 0; i < (int)(sizeof mem_targets / sizeof *mem_targets); i++) {
                if (strlen(mem_targets[i]) == kl &&
                    strncmp(toks[0], mem_targets[i], kl) == 0) {
                    skip = 1;
                    break;
                }
            }
            if (!skip) {
                if (kl >= sizeof key) kl = sizeof key - 1;
                memcpy(key, toks[0], kl);
                key[kl] = 0;
                for (char *c = key, *w = key; ; c++) {
                    if (*c == '(') { *w++ = '_'; continue; }
                    if (*c == ')') continue;
                    *w++ = *c;
                    if (*c == 0) break;
                }
                long long kb = strtoll(toks[1], NULL, 10);
                char metric[128], val[40];
                snprintf(metric, sizeof metric, "node_memory_%s_bytes", key);
                snprintf(val, sizeof val, "%lld", kb * 1024);
                metrics_line(m, metric, "", val);
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
}

static void collect_vmstat(struct metrics *m) {
    char *toks[8];
    char *p = (char *)read_proc(m->rootfs, "proc/vmstat");
    if (!p) return;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        int n = split_ws(p, toks, 8);
        if (n >= 2) {
            char metric[128];
            snprintf(metric, sizeof metric, "node_vmstat_%s", toks[0]);
            metrics_line(m, metric, "", toks[1]);
        }
        if (!nl) break;
        p = nl + 1;
    }
}

static void collect_cpufreq(struct metrics *m) {
    char base[PATH_CAP];
    if (m->rootfs[0])
        make_path(base, sizeof base, m->rootfs, "sys/devices/system/cpu");
    else
        strcpy(base, "/sys/devices/system/cpu");
    struct pdir d;
    if (pdir_open(&d, base) != 0) return;
    const char *e;
    while ((e = pdir_next(&d)) != NULL) {
        if (strncmp(e, "cpu", 3) != 0) continue;
        if (strlen(e) <= 3 || !is_all_digits(e + 3)) continue;
        char cdir[PATH_CAP];
        if (PATH_FMT(cdir, "%s/%s/cpufreq", base, e)) continue;
        int cfd = open(cdir, O_RDONLY);
        if (cfd < 0) continue;
        close(cfd);
        char chip[128];
        snprintf(chip, sizeof chip, "chip=\"%s\"", e);
        char cur[128] = "", maxf[128] = "", minf[128] = "", gov[128] = "";
        char path[PATH_CAP];
        if (!PATH_FMT(path, "%s/%s/cpufreq/scaling_cur_freq", base, e))
            read_abs(path, cur, sizeof cur);
        if (!PATH_FMT(path, "%s/%s/cpufreq/cpuinfo_max_freq", base, e))
            read_abs(path, maxf, sizeof maxf);
        if (!PATH_FMT(path, "%s/%s/cpufreq/cpuinfo_min_freq", base, e))
            read_abs(path, minf, sizeof minf);
        if (!PATH_FMT(path, "%s/%s/cpufreq/scaling_governor", base, e))
            read_abs(path, gov, sizeof gov);

        char v[40];
        if (cur[0]) {
            fmt_float(v, strtod(cur, NULL) * 1000.0);
            metrics_line(m, "node_cpu_scaling_frequency_hertz", chip, v);
            metrics_line(m, "node_cpufreq_frequency_hertz", chip, v);
        }
        if (maxf[0]) {
            fmt_float(v, strtod(maxf, NULL) * 1000.0);
            metrics_line(m, "node_cpu_scaling_frequency_max_hertz", chip, v);
            metrics_line(m, "node_cpufreq_frequency_max_hertz", chip, v);
        }
        if (minf[0]) {
            fmt_float(v, strtod(minf, NULL) * 1000.0);
            metrics_line(m, "node_cpu_scaling_frequency_min_hertz", chip, v);
            metrics_line(m, "node_cpufreq_frequency_min_hertz", chip, v);
        }
        if (gov[0]) {
            char l[400];
            snprintf(l, sizeof l, "%s,governor=\"%s\"", chip, gov);
            metrics_line(m, "node_cpufreq_scaling_governor", l, "1");
        }
    }
    pdir_close(&d);
}

/* Entries of /sys/block that carry no partitions and no stats worth walking. */
static bool skip_blockdev(const char *n) {
    return strcmp(n, ".") == 0 || strcmp(n, "..") == 0 ||
           has_prefix(n, "loop") || has_prefix(n, "ram");
}

/* A partition directory is always named after its disk -- the kernel builds
   "<disk><n>", inserting a 'p' when the disk name ends in a digit -- so the
   prefix is a sound pre-filter for the authoritative `partition` attribute.
   Without it the walk stats every one of the ~30 other entries a sysfs block
   directory carries (queue, power, holders, ...), which on the Pi was 32
   file opens to find 2 partitions. */
static bool is_part_of(const char *entry, const char *disk) {
    size_t dl = strlen(disk);
    return strncmp(entry, disk, dl) == 0 && entry[dl] != 0;
}

static void collect_diskstats(struct metrics *m) {
    /* parent device for partitions (from sys/block/<dev>/<part>/partition) */
    char sbase[PATH_CAP];
    if (m->rootfs[0])
        make_path(sbase, sizeof sbase, m->rootfs, "sys/block");
    else
        strcpy(sbase, "/sys/block");
    /* Device names, not paths: the kernel caps them at BDEVNAME_SIZE (32).
       This was part[256]/parent[256], 8,192 B of the frame. The slot count
       comes from a first walk of sys/block, since a fixed 16 silently lost the
       partition-to-parent mapping on a host with more disks than this one. */
    struct paren { char part[32], parent[32]; };
    size_t pmax = 0;
    {
        struct pdir cd;
        if (pdir_open(&cd, sbase) == 0) {
            const char *ce;
            while ((ce = pdir_next(&cd)) != NULL) {
                /* Same filter as the walk below. Without it this counted the
                   contents of every loop/ram device -- and of "." and "..",
                   so it opened and walked all of /sys as well: 27 directory
                   opens and ~800 entries read per cycle on the Pi to size an
                   array of 2. */
                if (skip_blockdev(ce)) continue;
                char cd2[PATH_CAP];
                if (PATH_FMT(cd2, "%s/%s", sbase, ce)) continue;
                struct pdir sd;
                if (pdir_open(&sd, cd2) != 0) continue;
                const char *se;
                while ((se = pdir_next(&sd)) != NULL)
                    if (is_part_of(se, ce)) pmax++;
                pdir_close(&sd);
            }
            pdir_close(&cd);
        }
    }
    struct paren *par = pmax ? m_alloc(m, pmax * sizeof *par) : NULL;
    int np = 0;
    struct pdir bd;
    if (pdir_open(&bd, sbase) == 0) {
        const char *be;
        while ((be = pdir_next(&bd)) != NULL) {
            if (skip_blockdev(be)) continue;
            char devdir[PATH_CAP];
            if (PATH_FMT(devdir, "%s/%s", sbase, be)) continue;
            struct pdir pd;
            if (pdir_open(&pd, devdir) != 0) continue;
            const char *pe;
            while ((pe = pdir_next(&pd)) != NULL) {
                if (!is_part_of(pe, be)) continue;
                char pf[PATH_CAP];
                if (PATH_FMT(pf, "%s/%s/partition", devdir, pe)) continue;
                int pfd = open(pf, O_RDONLY);
                if (pfd >= 0) {
                    close(pfd);
                    if (par && (size_t)np < pmax &&
                        !NAME_CPY(par[np].part, pe) &&
                        !NAME_CPY(par[np].parent, be))
                        np++;
                }
            }
            pdir_close(&pd);
        }
        pdir_close(&bd);
    }

    char *toks[24];
    char *p = (char *)read_proc(m->rootfs, "proc/diskstats");
    if (!p) return;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = 0;
        int n = split_ws(p, toks, 24);
        if (n >= 14) {
            const char *dev = toks[2];
            if (has_prefix(dev, "loop") || has_prefix(dev, "ram")) goto nextl;
            const char *disk = dev;
            for (int i = 0; i < np; i++)
                if (strcmp(par[i].part, dev) == 0) {
                    disk = par[i].parent;
                    break;
                }
            char dl[160];
            snprintf(dl, sizeof dl, "device=\"%s\",disk=\"%s\"", dev, disk);
            char v[40];
            snprintf(v, sizeof v, "%lld", strtoll(toks[3], NULL, 10));
            metrics_line(m, "node_disk_reads_completed_total", dl, v);
            snprintf(v, sizeof v, "%lld", strtoll(toks[7], NULL, 10));
            metrics_line(m, "node_disk_writes_completed_total", dl, v);
            fmt_float(v, strtod(toks[6], NULL) / 1000.0);
            metrics_line(m, "node_disk_read_time_seconds_total", dl, v);
            fmt_float(v, strtod(toks[10], NULL) / 1000.0);
            metrics_line(m, "node_disk_write_time_seconds_total", dl, v);
            snprintf(v, sizeof v, "%lld", strtoll(toks[11], NULL, 10));
            metrics_line(m, "node_disk_io_now", dl, v);
            fmt_float(v, strtod(toks[12], NULL) / 1000.0);
            metrics_line(m, "node_disk_io_time_seconds_total", dl, v);
            fmt_float(v, strtod(toks[13], NULL) / 1000.0);
            metrics_line(m, "node_disk_io_time_weighted_seconds_total", dl, v);
            if (n >= 18) {
                snprintf(v, sizeof v, "%lld", strtoll(toks[14], NULL, 10));
                metrics_line(m, "node_disk_discards_completed_total", dl, v);
            }
        }
    nextl:
        if (!nl) break;
        p = nl + 1;
    }
}

static void collect_pressure(struct metrics *m) {
    const char *body = read_proc(m->rootfs, "proc/pressure/cpu");
    if (body && *body) {
        char *line = (char *)body;
        while (*line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            if (has_prefix(line, "some ")) {
                char *toks[8];
                int n = split_ws(line, toks, 8);
                for (int i = 0; i < n; i++) {
                    if (has_prefix(toks[i], "total=")) {
                        metrics_line(m, "node_pressure_cpu_waiting_seconds_total",
                                     "", toks[i] + 6);
                        break;
                    }
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
    }
    static const char *ress[] = { "memory", "io" };
    for (size_t r = 0; r < sizeof ress / sizeof *ress; r++) {
        char rel[64], mname[80];
        snprintf(rel, sizeof rel, "proc/pressure/%s", ress[r]);
        body = read_proc(m->rootfs, rel);
        if (!body || !*body) continue;
        char *line = (char *)body;
        while (*line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            const char *kind = NULL;
            if (has_prefix(line, "some "))
                kind = "some";
            else if (has_prefix(line, "missing "))
                kind = "missing";
            if (kind) {
                char *toks[8];
                int n = split_ws(line, toks, 8);
                for (int i = 0; i < n; i++) {
                    if (has_prefix(toks[i], "total=")) {
                        snprintf(mname, sizeof mname,
                                 "node_pressure_%s_%s_seconds_total", ress[r],
                                 kind);
                        metrics_line(m, mname, "", toks[i] + 6);
                        break;
                    }
                }
            }
            if (!nl) break;
            line = nl + 1;
        }
    }
}

static void collect_netstat(struct metrics *m) {
    char *body = (char *)read_proc(m->rootfs, "proc/net/snmp");
    if (!body || !*body) return;
    char *arr[64];
    int n = 0;
    char *line = body;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        arr[n++] = line;
        if (!nl) break;
        line = nl + 1;
    }
    for (int i = 0; i + 1 < n; i += 2) {
        char *hdr = arr[i], *vals = arr[i + 1];
        char *hc = strchr(hdr, ':');
        char *vc = strchr(vals, ':');
        if (!hc || !vc) continue;
        *hc = 0; *vc = 0;
        const char *proto = trim_colon_ws(hdr);
        if (!*proto) continue;
        char *fields[64], *nums[64];
        int nf = split_ws(hc + 1, fields, 64);
        int nn = split_ws(vc + 1, nums, 64);
        int k = nf < nn ? nf : nn;
        for (int j = 0; j < k; j++) {
            char metric[128];
            snprintf(metric, sizeof metric, "node_netstat_%s_%s", proto,
                     fields[j]);
            metrics_line(m, metric, "", nums[j]);
        }
    }
}

static void collect_sockstat(struct metrics *m) {
    char *body = (char *)read_proc(m->rootfs, "proc/net/sockstat");
    if (!body || !*body) return;
    char *line = body;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *toks[32];
        int n = split_ws(line, toks, 32);
        if (n >= 2) {
            if (strcmp(toks[0], "sockets:") == 0) {
                if (n >= 3)
                    metrics_line(m, "node_sockstat_sockets_used", "", toks[2]);
            } else {
                char proto[64], metric[128];
                size_t pl = strlen(toks[0]);
                while (pl > 0 && toks[0][pl - 1] == ':') pl--;
                if (pl >= sizeof proto) pl = sizeof proto - 1;
                memcpy(proto, toks[0], pl);
                proto[pl] = 0;
                if (!*proto) goto nexts;
                for (int i = 1; i + 1 < n; i += 2) {
                    snprintf(metric, sizeof metric, "node_sockstat_%s_%s",
                             proto, toks[i]);
                    metrics_line(m, metric, "", toks[i + 1]);
                }
            }
        }
    nexts:
        if (!nl) break;
        line = nl + 1;
    }
}

static void collect_udp_queues(struct metrics *m) {
    static const char *paths[] = { "proc/net/udp", "proc/net/udp6" };
    for (size_t pi = 0; pi < sizeof paths / sizeof *paths; pi++) {
        char *body = (char *)read_proc(m->rootfs, paths[pi]);
        if (!body || !*body) continue;
        /* One slot per line, counted from the table itself: char *arr[64] both
           dropped sockets past the 64th and, before the bound was added, ran
           off the end of the array. */
        size_t amax = count_lines(body);
        char **arr = m_alloc(m, amax * sizeof *arr);
        if (!arr) continue;
        int n = 0;
        char *line = body;
        while (*line && (size_t)n < amax) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            arr[n++] = line;
            if (!nl) break;
            line = nl + 1;
        }
        double tx = 0, rx = 0;
        for (int i = 1; i < n; i++) {
            char *toks[24];
            int m2 = split_ws(arr[i], toks, 24);
            if (m2 <= 5) continue;
            char *c = strchr(toks[4], ':');
            if (!c) continue;
            tx += (double)strtoull(toks[4], NULL, 16);
            rx += (double)strtoull(c + 1, NULL, 16);
        }
        char v[40];
        fmt_float(v, tx);
        metrics_line(m, "node_udp_queues", "queue=\"tx\"", v);
        fmt_float(v, rx);
        metrics_line(m, "node_udp_queues", "queue=\"rx\"", v);
    }
}

static void collect_hwmon(struct metrics *m) {
    char hbase[PATH_CAP];
    if (m->rootfs[0])
        make_path(hbase, sizeof hbase, m->rootfs, "sys/class/hwmon");
    else
        strcpy(hbase, "/sys/class/hwmon");
    struct pdir hw;
    if (pdir_open(&hw, hbase) == 0) {
        const char *e;
        while ((e = pdir_next(&hw)) != NULL) {
            if (strcmp(e, ".") == 0 || strcmp(e, "..") == 0)
                continue;
            char cdir[PATH_CAP];
            if (PATH_FMT(cdir, "%s/%s", hbase, e)) continue;
            /* chip name */
            char fname[PATH_CAP], chip[128];
            if (PATH_FMT(fname, "%s/name", cdir)) continue;
            if (read_abs(fname, chip, sizeof chip) <= 0) continue;
            /* One slot per sensor, counted from the chip directory: a fixed
               16 dropped sensors on a chip that exposes more. */
            struct tval { char num[16]; double c; };
            struct pdir cd;
            if (pdir_open(&cd, cdir) != 0) continue;
            const char *fe;
            size_t tmax = 0;
            while ((fe = pdir_next(&cd)) != NULL) tmax++;
            pdir_close(&cd);
            struct tval *temps = m_alloc(m, tmax * sizeof *temps);
            if (!temps) continue;
            int nt = 0;
            if (pdir_open(&cd, cdir) != 0) continue;
            while ((fe = pdir_next(&cd)) != NULL) {
                const char *fn = fe;
                if (!has_prefix(fn, "temp")) continue;
                size_t nl = strlen(fn);
                size_t sl = 6;   /* strlen("_input") */
                if (nl <= sl || strcmp(fn + nl - sl, "_input") != 0) continue;
                char num[16], vb[128];
                size_t nn = nl - sl - 4;
                memcpy(num, fn + 4, nn);
                num[nn] = 0;
                if (nn == 0 || !is_all_digits(num)) continue;
                if (PATH_FMT(fname, "%s/temp%s_input", cdir, num)) continue;
                if (read_abs(fname, vb, sizeof vb) <= 0) continue;
                if ((size_t)nt < tmax) {
                    temps[nt].c = strtod(vb, NULL) / 1000.0;
                    snprintf(temps[nt].num, sizeof temps[0].num, "%s", num);
                    nt++;
                }
            }
            pdir_close(&cd);
            if (nt > 0) {
                char l[400], l2[400];
                snprintf(l, sizeof l, "chip=\"%s\",chip_name=\"%s\"", chip,
                         chip);
                metrics_line(m, "node_hwmon_chip_names", l, "1");
                for (int i = 0; i < nt; i++) {
                    char label[256];
                    if (PATH_FMT(fname, "%s/temp%s_label", cdir,
                                 temps[i].num))
                        continue;
                    if (read_abs(fname, label, sizeof label) <= 0)
                        snprintf(label, sizeof label, "%s", chip);
                    char v[40];
                    fmt_float(v, temps[i].c);
                    snprintf(l2, sizeof l2, "chip=\"%s\",label=\"%s\"", chip,
                             label);
                    metrics_line(m, "node_hwmon_temp_celsius", l2, v);
                }
            }
        }
        pdir_close(&hw);
    }

    char tbase[PATH_CAP];
    if (m->rootfs[0])
        make_path(tbase, sizeof tbase, m->rootfs, "sys/class/thermal");
    else
        strcpy(tbase, "/sys/class/thermal");
    struct pdir td;
    if (pdir_open(&td, tbase) == 0) {
        const char *e;
        while ((e = pdir_next(&td)) != NULL) {
            if (!has_prefix(e, "thermal_zone")) continue;
            char tf[PATH_CAP];
            if (PATH_FMT(tf, "%s/%s/temp", tbase, e)) continue;
            char vb[128];
            if (read_abs(tf, vb, sizeof vb) <= 0) continue;
            char v[40], l[270];
            fmt_float(v, strtod(vb, NULL) / 1000.0);
            snprintf(l, sizeof l, "zone=\"%s\"", e);
            metrics_line(m, "node_thermal_zone_temp", l, v);
        }
        pdir_close(&td);
    }
}

#ifdef ENABLE_SYSTEMD
static void collect_systemd(struct metrics *m) {
    FILE *p = popen("systemctl list-units --all --type=service -o json-pretty",
                    "r");
    if (!p) return;
    /* systemd's ActiveState is a closed set of short words (active, reloading,
       inactive, failed, activating, deactivating, maintenance), so 32 B is
       ample; this was state[256], 4 kB of the frame. */
    enum { SYSTEMD_STATE_CAP = 32 };
    struct st { char state[SYSTEMD_STATE_CAP]; long n; } sts[16];
    int nst = 0;
    char line[512];
    while (fgets(line, sizeof line, p)) {
        const char *q = strstr(line, "\"active\"");
        if (!q) continue;
        const char *colon = strchr(q + 8, ':');
        if (!colon) continue;
        const char *op = strchr(colon + 1, '"');   /* opening quote of value */
        if (!op) continue;
        const char *cl = strchr(op + 1, '"');      /* closing quote of value */
        if (!cl || cl - op - 1 >= (int)sizeof sts[0].state) continue;
        char st_[SYSTEMD_STATE_CAP];
        memcpy(st_, op + 1, (size_t)(cl - op - 1));
        st_[cl - op - 1] = 0;
        int found = -1;
        for (int i = 0; i < nst; i++)
            if (strcmp(sts[i].state, st_) == 0) { found = i; break; }
        if (found < 0 && nst < 16) {
            snprintf(sts[nst].state, sizeof sts[0].state, "%s", st_);
            sts[nst].n = 0;
            found = nst++;
        }
        if (found >= 0) sts[found].n++;
    }
    pclose(p);
    for (int i = 0; i < nst; i++) {
        char l[300], v[40];
        snprintf(l, sizeof l, "state=\"%.255s\",type=\"service\"", sts[i].state);
        snprintf(v, sizeof v, "%ld", sts[i].n);
        metrics_line(m, "node_systemd_units", l, v);
    }
}
#endif /* ENABLE_SYSTEMD */

/* ---------- textfile ---------- */

static const char *g_textfile_dir = NULL;

void collectors_set_textfile_dir(const char *dir) {
    g_textfile_dir = (dir && dir[0]) ? dir : NULL;
}

/* Splits one exposition line in place and hands the pieces to metrics_line,
   which already parses `k="v"` pairs, stores the strings and covers both
   output modes -- reimplementing any of that here would be a second copy of
   the same parser. Returns false for lines carrying no sample. */
static bool textfile_line(struct metrics *m, char *line) {
    while (*line == ' ' || *line == '\t') line++;
    if (!*line || *line == '#') return false;

    char *labels = (char *)"";
    char *p = line;
    while (*p && *p != '{' && *p != ' ' && *p != '\t') p++;
    if (!*p) return false;

    if (*p == '{') {
        *p = 0;
        labels = ++p;
        /* A label value may legally contain '}', so the closing brace is the
           first one seen outside quotes, not the first one seen. */
        bool quoted = false;
        for (; *p; p++) {
            if (*p == '\\' && p[1]) { p++; continue; }
            if (*p == '"') quoted = !quoted;
            else if (*p == '}' && !quoted) break;
        }
        if (*p != '}') return false;
        *p++ = 0;
    } else {
        *p++ = 0;
    }

    while (*p == ' ' || *p == '\t') p++;
    if (!*p) return false;
    char *value = p;
    /* Exposition format allows a trailing timestamp, and samples mode drops
       any value with leftover characters, so cut the line at the value. */
    while (*p && *p != ' ' && *p != '\t' && *p != '\r') p++;
    *p = 0;

    metrics_line(m, line, labels, value);
    return true;
}

static void collect_textfile(struct metrics *m) {
    if (!g_textfile_dir) return;

    struct pdir d;
    if (pdir_open(&d, g_textfile_dir) != 0) {
        metrics_line(m, "node_textfile_scrape_error", "", "1");
        return;
    }

    int failed = 0;
    const char *e;
    while ((e = pdir_next(&d)) != NULL) {
        size_t n = strlen(e);
        if (n < 6 || strcmp(e + n - 5, ".prom") != 0) continue;

        char path[PATH_CAP];
        if (PATH_FMT(path, "%s/%s", g_textfile_dir, e)) { failed++; continue; }

        struct stat st;
        if (stat(path, &st) != 0) { failed++; continue; }

        char label[PATH_CAP], mtime[40];
        if (snprintf(label, sizeof label, "file=\"%s\"", e) < (int)sizeof label) {
            fmt_float(mtime, (double)st.st_mtime);
            metrics_line(m, "node_textfile_mtime_seconds", label, mtime);
        }

        /* read_proc hands back the one shared buffer, so a file has to be
           parsed to the end before the next one is read. */
        char *buf = (char *)read_proc(g_textfile_dir, e);
        if (!buf) { failed++; continue; }

        for (char *line = buf; *line; ) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            textfile_line(m, line);
            if (!nl) break;
            line = nl + 1;
        }
    }
    pdir_close(&d);

    metrics_line(m, "node_textfile_scrape_error", "", failed ? "1" : "0");
}

void collect_all(struct metrics *m) {
    collect_build(m);
    collect_rss(m);
    collect_uname(m);
    collect_uptime(m);
    collect_load(m);
    collect_entropy(m);
    collect_memory(m);
    collect_stat(m);
    collect_disk_bytes(m);
    collect_filefd(m);
    collect_filesystem(m);
    collect_network(m);

    SCRAPE("meminfo") collect_meminfo_extras(m);
    SCRAPE("vmstat") collect_vmstat(m);
    SCRAPE("cpufreq") collect_cpufreq(m);
    SCRAPE("diskstats") collect_diskstats(m);
    SCRAPE("pressure") collect_pressure(m);
    SCRAPE("netstat") collect_netstat(m);
    SCRAPE("sockstat") collect_sockstat(m);
    SCRAPE("udp_queue") collect_udp_queues(m);
    SCRAPE("hwmon") collect_hwmon(m);
    SCRAPE("textfile") collect_textfile(m);
#ifdef ENABLE_SYSTEMD
    SCRAPE("systemd") collect_systemd(m);
#endif

    /* Self-report, and only when non-zero: a permanently-zero series would
       cost a sample slot plus arena on every cycle. metrics_add is used rather
       than the collector path, so the reserved slots guarantee room for it
       even in the cycle that exhausted the cap. */
    if (m->ndropped)
        metrics_add(m, "node_exporter_dropped_samples_total",
                    (double)m->ndropped);
}

void metrics_init(struct metrics *m, bool text_mode, const char *rootfs) {
    memset(m, 0, sizeof *m);
    m->text_mode = text_mode;
    if (!rootfs || rootfs[0] == 0 || strcmp(rootfs, "/") == 0)
        m->rootfs = "";
    else
        m->rootfs = rootfs;
    clk_tick = (double)sysconf(_SC_CLK_TCK);
    if (clk_tick <= 0) clk_tick = 100.0;
}

void metrics_free(struct metrics *m) {
    if (m->n) g_scap_hint = m->n;
    /* Heap-owned memory first: in arena mode these are the arena-exhaustion
       fallbacks, which arena_reset does not cover. Skipping them leaked a
       cycle's worth of strings on every overflowing cycle of the push loop. */
    for (size_t i = 0; i < m->nsfree; i++) free(m->sfree[i]);
    free(m->sfree);
    m->sfree = NULL;
    m->nsfree = 0;
    m->capsf = 0;
    if (m->heap_samples) free(m->samples);
    m->heap_samples = false;
    m->samples = NULL;
    m->scap = 0;

    if (m->ar) {
        /* Rewind + MADV_DONTNEED: evict the cycle's pages during the sleep so
           only the resting baseline stays resident (see AGENTS.md), not the
           sample and label memory the collection just touched. */
        arena_reset(m->ar);
        rbuf_cycle_end();
        return;
    }
    free(m->txt);
    m->txt = NULL;
    m->tlen = 0;
    m->tcap = 0;
}

/* --dump: print `DUMP name{k=v,k2=v2}=<value>` for every sample whose name
   contains substr. */
void metrics_dump(struct metrics *m, const char *substr) {
    struct msample *s = m->samples;
    for (size_t i = 0; i < m->n; i++) {
        if (strstr(s[i].name, substr) == NULL) continue;
        size_t need = strlen(s[i].name) + 1; /* { */
        for (int j = 0; j < s[i].nlabels; j++)
            need += strlen(s[i].labels[j].k) + 1 + strlen(s[i].labels[j].v) + 1;
        size_t cap = need + 192;
        char *buf = malloc(cap);
        size_t o = 0;
        buf[o++] = 'D'; buf[o++] = 'U'; buf[o++] = 'M'; buf[o++] = 'P';
        buf[o++] = ' ';
        o += (size_t)snprintf(buf + o, cap - o, "%s", s[i].name);
        buf[o++] = '{';
        for (int j = 0; j < s[i].nlabels; j++) {
            o += (size_t)snprintf(buf + o, cap - o, "%s=%s,",
                                  s[i].labels[j].k, s[i].labels[j].v);
        }
        if (s[i].nlabels > 0) buf[o - 1] = '}';
        else buf[o++] = '}';
        char v[40];
        fmt_float(v, s[i].value);
        o += (size_t)snprintf(buf + o, cap - o, "=%s\n", v);
        fwrite(buf, 1, o, stdout);
        free(buf);
    }
}