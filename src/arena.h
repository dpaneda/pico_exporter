#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>

/* Per-cycle scratch for the exporter, following the Zig POC's RSS technique:
   mmap once, reset each cycle, madvise(MADV_DONTNEED) so pages are evicted
   during the 15 s sleep and RSS stays flat. */

struct arena {
    unsigned char *base;   /* NULL until first init */
    size_t         cap;
    size_t         off;
};

int  arena_init(struct arena *a, size_t cap);   /* 0 ok, 1 ENOMEM-ish */
void arena_reset(struct arena *a);              /* rewind + MADV_DONTNEED */
void *arena_alloc(struct arena *a, size_t n);   /* NULL when exhausted */

/* Grows the block at `p` (allocated with size `oldn`) to `newn` without moving
   it, which only works while `p` is still the arena's last block. Returns `p`,
   or NULL when something was allocated behind it -- the caller then decides
   whether the old contents are worth copying. */
void *arena_extend(struct arena *a, void *p, size_t oldn, size_t newn);

/* arena_extend, falling back to a fresh region plus a copy of the first `oldn`
   bytes. NULL leaves the original block untouched. */
void *arena_realloc(struct arena *a, void *p, size_t oldn, size_t newn);

#endif
