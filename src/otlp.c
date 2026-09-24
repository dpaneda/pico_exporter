/* otlp.c - OpenTelemetry Metrics Protocol (OTLP/HTTP) protobuf encoder.
 *
 * Fixed nesting and field order: resource, scope, then one Metric message per
 * metric name holding its datapoints, including the empty-message artifacts
 * (an empty resource -> 0A 00, empty scope -> 12 00).
 *
 * Framing trick: every length-delimited submessage is written as a frame
 * that opens with its tag + 10 raw bytes of room, then closes by backpatching
 * the real length varint and trimming the surplus. A dry (counting) first pass
 * sizes the output, so the real pass never reallocates.
 *
 * Structure emitted (all length-delimited unless noted):
 *   ExportMetricsServiceRequest field1 = ResourceMetrics
 *     ResourceMetrics.resource       field1 = Resource { KeyValue* }
 *     ResourceMetrics.scope_metrics  field2 = ScopeMetrics { Metric* }
 *       Metric.name  field1, and either Metric.gauge field5 or Metric.sum
 *       field7, each = NumberDataPoint* (field1) + (Sum only) temporality
 *       field2 varint=2, is_monotonic field3 varint=1
 *     NumberDataPoint = { attributes field7 (KeyValue*),
 *                         time_unix_nano field3 fixed64,
 *                         as_double field4 fixed64 }
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arena.h"
#include "otlp.h"

#define WIRE_VARINT 0
#define WIRE_FIXED64 1
#define WIRE_LEN 2

static int  buf_ensure(struct otlp_buf *b, size_t need);   /* 0 ok */

static void put(struct otlp_buf *b, unsigned char c) {
    if (!b->dry) b->data[b->len] = (char)c;
    b->len++;
}

static void emit_raw(struct otlp_buf *b, const char *p, size_t n) {
    if (!b->dry && n > 0) memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void emit_varint(struct otlp_buf *b, uint64_t v) {
    while (v >= 0x80) {
        put(b, (unsigned char)((v & 0x7F) | 0x80));
        v >>= 7;
    }
    put(b, (unsigned char)v);
}

static void emit_tag(struct otlp_buf *b, int field, int wire) {
    emit_varint(b, ((uint64_t)field << 3) | (uint64_t)wire);
}

static void emit_fixed64(struct otlp_buf *b, uint64_t bits) {
    for (int i = 0; i < 8; i++) put(b, (unsigned char)(bits >> (8 * i)));
}

static size_t frame_open(struct otlp_buf *b, int field) {
    emit_tag(b, field, WIRE_LEN);
    size_t lenpos = b->len;            /* position of the length varint */
    for (int i = 0; i < 10; i++) put(b, 0);   /* room for the length varint */
    return lenpos;
}

static void frame_close(struct otlp_buf *b, size_t lenpos) {
    if (b->dry) return;              /* dry pass: sizes already counted */
    uint64_t n = (uint64_t)(b->len - lenpos - 10);   /* message content bytes */
    char tmp[10];
    size_t k = 0;
    while (n >= 0x80) {
        tmp[k++] = (char)((n & 0x7F) | 0x80);
        n >>= 7;
    }
    tmp[k++] = (char)n;
    memcpy(b->data + lenpos, tmp, k);              /* backpatch length */
    if (b->len - (lenpos + 10) > 0)                /* slide content over room */
        memmove(b->data + lenpos + k, b->data + lenpos + 10,
                b->len - (lenpos + 10));
    n = k;
    b->len = lenpos + n + (b->len - (lenpos + 10));
}

static int is_counter_name(const char *name) {
    size_t n = strlen(name);
    return n > 6 && strncmp(name + n - 6, "_total", 6) == 0;
}

/* KeyValue { key=1, value=2=AnyValue{ string_value=1 } } at field `field`.
   Matches writeKv: key bytes first, then the AnyValue message. */
static void emit_kv(struct otlp_buf *b, int field, const char *k, const char *v) {
    size_t f = frame_open(b, field);
    size_t kf = frame_open(b, 1);
    emit_raw(b, k, strlen(k));
    frame_close(b, kf);
    size_t vf = frame_open(b, 2);          /* KeyValue.value = AnyValue */
    size_t svf = frame_open(b, 1);         /* AnyValue.string_value */
    emit_raw(b, v, strlen(v));
    frame_close(b, svf);
    frame_close(b, vf);
    frame_close(b, f);
}

static void emit_point(struct otlp_buf *b, const struct msample *s,
                       int64_t ts_ns) {
    size_t pf = frame_open(b, 1);          /* NumberDataPoint */
    for (size_t i = 0; i < (size_t)s->nlabels; i++)
        emit_kv(b, 7, s->labels[i].k, s->labels[i].v);
    emit_tag(b, 3, WIRE_FIXED64);          /* time_unix_nano */
    emit_fixed64(b, (uint64_t)ts_ns);
    emit_tag(b, 4, WIRE_FIXED64);          /* as_double */
    uint64_t bits;
    memcpy(&bits, &s->value, 8);
    emit_fixed64(b, bits);
    frame_close(b, pf);
}

static void emit_all(struct otlp_buf *b, const struct msample *samples,
                     size_t n, const struct otlp_kv *res, size_t res_n,
                     int64_t ts_ns, size_t first, size_t count) {
    size_t last = first + count;
    if (last > n) last = n;

    size_t rml = frame_open(b, 1);         /* ResourceMetrics */
    size_t rs = frame_open(b, 1);          /* Resource */
    for (size_t i = 0; i < res_n; i++)
        emit_kv(b, 1, res[i].k, res[i].v);
    frame_close(b, rs);
    size_t sm = frame_open(b, 2);          /* ScopeMetrics */
    size_t i = first;
    while (i < last) {
        const char *name = samples[i].name;
        int counter = is_counter_name(name);
        size_t mf = frame_open(b, 2);      /* Metric */
        size_t nf = frame_open(b, 1);      /* Metric.name */
        emit_raw(b, name, strlen(name));
        frame_close(b, nf);
        size_t df = frame_open(b, counter ? 7 : 5);   /* Sum or Gauge */
        while (i < last && strcmp(samples[i].name, name) == 0) {
            emit_point(b, &samples[i], ts_ns);
            i++;
        }
        if (counter) {
            emit_tag(b, 2, WIRE_VARINT);   /* aggregation_temporality = CUMULATIVE */
            emit_varint(b, 2);
            emit_tag(b, 3, WIRE_VARINT);   /* is_monotonic = true */
            emit_varint(b, 1);
        }
        frame_close(b, df);
        frame_close(b, mf);
    }
    frame_close(b, sm);
    frame_close(b, rml);
}

int otlp_buf_reserve(struct otlp_buf *b, size_t extra) {
    if (b->len + extra <= b->cap) return 0;
    size_t need = b->len + extra;
    if (b->cap == 0 && need < 4096) need = 4096;
    return buf_ensure(b, need);
}

static int buf_ensure(struct otlp_buf *b, size_t need) {
    if (need <= b->cap) return 0;
    if (b->ar) {
        /* Hot path: the region comes from the cycle arena. Encoding runs after
           collection, so the buffer is normally still the arena's last block
           and the next batch just extends it in place; otherwise a fresh
           region supersedes it (no free; reclaimed at cycle end). No copy
           either way -- otlp_encode sizes with a dry pass, then rewrites from
           zero. Falls back to malloc only if the arena is exhausted (never in
           production). */
        int heap = 0;
        char *na = (b->data && !b->owned)
                     ? arena_extend(b->ar, b->data, b->cap, need) : NULL;
        if (!na) na = arena_alloc(b->ar, need);
        if (!na) {
            na = malloc(need);
            if (!na) return 1;
            heap = 1;
            fprintf(stderr, "WARN otlp: arena exhausted, malloc %zu\n", need);
        }
        /* A heap region from an earlier exhausted cycle is not reclaimed by
           arena_reset, so this is the only chance to release it. */
        if (b->owned) free(b->data);
        b->data = na;
        b->owned = heap;
        b->cap = need;
        return 0;
    }
    char *nd = realloc(b->data, need);
    if (!nd) return 1;
    b->data = nd;
    b->owned = 1;
    b->cap = need;
    return 0;
}

size_t otlp_encode(struct otlp_buf *out, const struct msample *samples,
                   size_t n, const struct otlp_kv *res, size_t res_n,
                   int64_t ts_ns, size_t first, size_t count) {
    /* Pass 0: dry run to size the output exactly. */
    int saved_dry = out->dry;
    out->dry = 1;
    out->len = 0;
    emit_all(out, samples, n, res, res_n, ts_ns, first, count);
    size_t need = out->len;
    out->dry = saved_dry;

    if (buf_ensure(out, need) != 0) { out->len = 0; return 0; }
    out->len = 0;
    emit_all(out, samples, n, res, res_n, ts_ns, first, count);
    return out->len;
}

/* Drops the buffer as well as its contents. Mandatory once per cycle in arena
   mode: arena_reset hands the region back, so keeping `data`/`cap` across the
   boundary leaves a stale pointer that buf_ensure will happily write through
   -- straight over the next cycle's live samples as soon as a collection
   reaches that far up the arena. */
void otlp_buf_reset(struct otlp_buf *b) {
    b->len = 0;
    if (!b->ar) return;
    if (b->owned) free(b->data);
    b->data = NULL;
    b->cap = 0;
    b->owned = 0;
}
