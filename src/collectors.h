#ifndef COLLECTORS_H
#define COLLECTORS_H

#include <stdbool.h>
#include <stddef.h>

#include "arena.h"

/* Reads /proc and /sys under a rootfs and produces either Prometheus text
   exposition lines (--metrics-once) or an array of samples (push mode). */

/* Upper bound on the labels one series may carry. The widest series in the
   whole exporter is node_uname_info with 5 labels (machine, nodename,
   release, sysname, version), so 8 leaves three spare. Overflow is not
   silent -- it bumps nlabels_capped. Unlike earlier revisions this no longer
   drives sizeof(struct msample): labels hang off a pointer. */
#define COLLECT_MAX_LABELS 8
#ifndef COLLECT_MAX_SAMPLES
#define COLLECT_MAX_SAMPLES 8192
#endif

/* Slots held back from the collectors so the self-report and `up` can always
   be emitted -- including in the very cycle where the sample cap was hit. */
#define COLLECT_RESERVED_SAMPLES 2

struct mkv {
    const char *k;
    const char *v;
};

/* `labels` points at exactly nlabels pairs carved from the same per-cycle
   storage as the strings (arena in push mode, tracked malloc otherwise), and
   is NULL when nlabels == 0. Holding the array out of line is what keeps the
   struct at 32 bytes: an inline mkv[8] cost 128 of 152 bytes for a population
   where 59% of samples carry no labels at all and 98% carry at most two. */
struct msample {
    const char *name;
    const struct mkv *labels;
    int  nlabels;
    double value;
};

struct metrics {
    bool       text_mode;
    const char *rootfs;          /* "" or a trailing-slash path */

    /* per-cycle arena (samples mode only); NULL means plain malloc */
    struct arena *ar;

    /* owned label/name strings. Normally only the non-arena samples mode
       (one-shot --dump) uses these, but arena mode also lands here for the
       malloc fallbacks it takes when the arena is exhausted, so sfree[] must
       be released on every path. */
    char     **sfree;
    size_t     nsfree, capsf;

    /* text sink */
    char      *txt;
    size_t     tlen, tcap;

    /* samples sink. heap_samples marks `samples` as malloc/realloc-owned:
       always true in non-arena mode, and in arena mode after an
       arena-exhaustion fallback (arena_reset does not cover it). */
    struct msample *samples;
    size_t     n, scap;
    bool       heap_samples;

    /* Per-cycle self-report: samples the cap refused, and samples whose label
       list was truncated. Counted, then reported once per cycle -- a message
       per occurrence would be thousands of identical lines on a host big
       enough to trigger it. */
    size_t     ndropped;
    size_t     nlabels_capped;
};

/* Points the shared /proc read buffer at the cycle arena (push mode). Unset
   -- the one-shot modes -- keeps it on a one-off malloc. */
void collectors_set_arena(struct arena *ar);

/* Directory scanned for `*.prom` files (TEXTFILE_DIR). NULL or empty
   disables the collector entirely. */
void collectors_set_textfile_dir(const char *dir);

void metrics_init(struct metrics *m, bool text_mode, const char *rootfs);
void metrics_free(struct metrics *m);

/* Emit one series. labels is "" or a pre-formatted `k="v",k2="v2"` string. */
void metrics_line(struct metrics *m, const char *name, const char *labels,
                  const char *value);

/* Append a raw sample with no labels (samples mode only; e.g. the `up` series). */
void metrics_add(struct metrics *m, const char *name, double value);

/* Collect everything in the same order as getMetrics. */
void collect_all(struct metrics *m);

/* Print `DUMP name{k=v,...}=<value>` for matching samples (--dump). */
void metrics_dump(struct metrics *m, const char *substr);

#endif