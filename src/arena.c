/* arena.c - mmap + madvise(MADV_DONTNEED) cycle arena, and the only allocator
 * in the binary. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "arena.h"
#include "fmt.h"

/* Linux-only; MADV_NOHUGEPAGE lacks a POSIX declaration, so guard it. */
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif

static size_t align16(size_t n) { return (n + 15) & ~(size_t)15; }

int arena_init(struct arena *a, size_t cap) {
    memset(a, 0, sizeof *a);
    if (cap == 0) return 1;
    a->base = mmap(NULL, cap, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a->base == MAP_FAILED) {
        a->base = NULL;
        return 1;
    }
    /* With transparent hugepages in `always` mode the first byte touched here
       faults a whole 2 MiB page, so a cycle that really uses ~150 kB shows up
       as a 2 MiB RSS spike. This is what keeps a cap above 2 MiB from turning
       a 150 kB cycle into one; it is a no-op where THP is absent (the deployed
       Pi kernel) or already in `madvise` mode. */
    madvise(a->base, cap, MADV_NOHUGEPAGE);
    a->cap = cap;
    a->off = 0;
    return 0;
}

void arena_reset(struct arena *a) {
    if (!a->base) return;
    a->off = 0;
    madvise(a->base, a->cap, MADV_DONTNEED);
}

/* The refusal. There is no heap behind the arena, so a collection that does
 * not fit is not a degraded cycle, it is a collection this binary cannot make:
 * the alternatives were a silently truncated push or a fallback allocator, and
 * both hide the number an operator needs. Three numbers and the knob that
 * changes them, then out -- the unit's Restart=policy decides what happens
 * next, and a loud death beats a silently incomplete push. */
static _Noreturn void arena_die(size_t need, const struct arena *a) {
    char buf[192];
    char *o = buf;
    fmt_str_append(&o, "pico_exporter: arena exhausted: need ");
    fmt_u64_append(&o, need);
    fmt_str_append(&o, " B, ");
    fmt_u64_append(&o, a->off);
    fmt_str_append(&o, " of ");
    fmt_u64_append(&o, a->cap);
    fmt_str_append(&o, " B in use (raise ARENA_CAP)\n");
    size_t len = (size_t)(o - buf), off = 0;
    while (off < len) {
        ssize_t w = write(2, buf + off, len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    exit(1);
}

void *arena_alloc(struct arena *a, size_t n) {
    if (!a->base) arena_die(n, a);
    size_t aligned = align16(n);
    if (a->off + aligned > a->cap) arena_die(n, a);
    void *p = a->base + a->off;
    a->off += aligned;
    return p;
}

void *arena_extend(struct arena *a, void *p, size_t oldn, size_t newn) {
    if (!a->base || !p) return NULL;
    if (newn <= oldn) return p;
    size_t aold = align16(oldn), anew = align16(newn);
    size_t start = (size_t)((unsigned char *)p - a->base);
    if (start + aold != a->off) return NULL;       /* not the last block */
    /* Out of room is arena_alloc's refusal, not a soft NULL: the caller that
       could not grow in place calls arena_alloc next, and dies there if the
       arena really is full. */
    if (start + anew > a->cap) return NULL;
    a->off = start + anew;
    return p;
}

void *arena_realloc(struct arena *a, void *p, size_t oldn, size_t newn) {
    if (!p) return arena_alloc(a, newn);
    void *q = arena_extend(a, p, oldn, newn);
    if (q) return q;
    q = arena_alloc(a, newn);
    if (oldn) memcpy(q, p, oldn < newn ? oldn : newn);
    return q;
}
