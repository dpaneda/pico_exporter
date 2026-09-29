#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>

/* Per-cycle scratch for the exporter, following the Zig POC's RSS technique:
   mmap once, reset each cycle, madvise(MADV_DONTNEED) so pages are evicted
   during the 15 s sleep and RSS stays flat. It is also the only allocator in
   the binary: there is no heap behind it, so a request it cannot serve ends
   the process (see arena_die) rather than falling back. */

struct arena {
    unsigned char *base;   /* NULL until first init */
    size_t         cap;
    size_t         off;
};

int  arena_init(struct arena *a, size_t cap);   /* 0 ok, 1 ENOMEM-ish */
void arena_reset(struct arena *a);              /* rewind + MADV_DONTNEED */
void *arena_alloc(struct arena *a, size_t n) __attribute__((returns_nonnull));

/* Grows the block at `p` (allocated with size `oldn`) to `newn` without moving
   it, which only works while `p` is still the arena's last block. Returns `p`,
   or NULL when something was allocated behind it or the arena is full -- the
   caller then allocates afresh (arena_realloc) or dies there. */
void *arena_extend(struct arena *a, void *p, size_t oldn, size_t newn);

/* arena_extend, falling back to a fresh region plus a copy of the first `oldn`
   bytes. Never returns NULL. */
void *arena_realloc(struct arena *a, void *p, size_t oldn, size_t newn)
    __attribute__((returns_nonnull));

#endif
