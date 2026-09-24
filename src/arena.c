/* arena.c - mmap + madvise(MADV_DONTNEED) cycle arena. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "arena.h"

/* Linux-only; picolibc's headers do not carry it. */
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
       as a 2 MiB RSS spike. The cap is under 2 MiB for the same reason; this
       is the belt to that suspenders, and is a no-op where THP is absent (the
       deployed Pi kernel) or already in `madvise` mode. */
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

void *arena_alloc(struct arena *a, size_t n) {
    if (!a->base) return NULL;
    size_t aligned = align16(n);
    if (a->off + aligned > a->cap) return NULL;
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
    if (start + anew > a->cap) return NULL;
    a->off = start + anew;
    return p;
}

void *arena_realloc(struct arena *a, void *p, size_t oldn, size_t newn) {
    if (!p) return arena_alloc(a, newn);
    void *q = arena_extend(a, p, oldn, newn);
    if (q) return q;
    q = arena_alloc(a, newn);
    if (q && oldn) memcpy(q, p, oldn < newn ? oldn : newn);
    return q;
}
