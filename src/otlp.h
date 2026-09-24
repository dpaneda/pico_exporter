#ifndef OTLP_H
#define OTLP_H

#include <stddef.h>
#include <stdint.h>

#include "collectors.h"

/* Resource attribute pair (service.name / service.instance.id). */
struct otlp_kv {
    const char *k;
    const char *v;
};

/* Encoder buffer. When `ar` is set the data lives on the cycle arena (fresh
   region per otlp_encode call, reclaimed by arena_reset at cycle end);
   otherwise a caller-owned heap buffer grown with realloc. */
struct arena;
struct otlp_buf {
    char *data;
    size_t len;
    size_t cap;
    int   dry;   /* internal: counting pass, no writes */
    int   owned; /* internal: `data` is malloc/realloc-owned, must be freed */
    struct arena *ar;
};

int  otlp_buf_reserve(struct otlp_buf *b, size_t extra);   /* 0 ok */
void otlp_buf_reset(struct otlp_buf *b);

/* Encodes samples[first..first+count) at ts_ns (real ns) with one resource
   carrying res_attrs (service.name/service.instance.id). *_total -> Sum
   monotonic cumulative; everything else -> Gauge. `samples` are the same
   structs produced by the collectors (msample), encoded directly. Returns
   bytes written. */
size_t otlp_encode(struct otlp_buf *out, const struct msample *samples,
                   size_t n, const struct otlp_kv *res_attrs, size_t res_n,
                   int64_t ts_ns, size_t first, size_t count);

#endif