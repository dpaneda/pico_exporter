/* alloc.c - the malloc free-standing binaries get instead of libc's.
 *
 * Call volume: the one-shot modes (--metrics-once/--dump, which have no cycle
 * arena), the arena-exhaustion fallbacks collectors.c and otlp.c keep for a
 * pathologically large collection, and the systemd flavor's popen_sh stream.
 * A first-fit free list with coalescing over anonymous mmap chunks covers all
 * of that in ~250 bytes of text, and never creates a [heap] mapping (the
 * resting-footprint gate greps /proc maps for one) or any libc state.
 */

#ifdef __PICO_FREESTAND__

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *d, int c, size_t n);

/* Every live block keeps this header at its payload-16 base; free blocks are
   held in an address-sorted singly-linked list for O(1) adjacency merges. */
struct fs_span {
    size_t           size;   /* whole span, header included */
    struct fs_span  *next;   /* free-list link, only while free */
};
enum { FS_HDR = sizeof(struct fs_span) < 16 ? 16 : sizeof(struct fs_span) };

static struct fs_span *g_free;

/* One fresh 64 KiB-or-bigger mapping, offered to malloc as a single span. */
static void *fs_grow(size_t need) {
    size_t len = need > 65536 ? (need + 4095) & ~(size_t)4095 : 65536;
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return NULL;
    struct fs_span *b = p;
    b->size = len;
    b->next = NULL;
    return b;
}

/* Address-ordered insert + immediate merges, so live/free blocks of adjacent
   churn collapse instead of splitting the pool into unusable crumbs. */
static void fs_release(struct fs_span *b) {
    struct fs_span **pp = &g_free, *prev = NULL;
    while (*pp && *pp < b) {
        prev = *pp;
        pp = &(*pp)->next;
    }
    if (*pp && (char *)b + b->size == (char *)*pp) {
        /* forward */
        b->size += (*pp)->size;
        b->next = (*pp)->next;
        if (prev && (char *)prev + prev->size == (char *)b) {
            prev->size += b->size;
            prev->next = b->next;
        } else {
            *pp = b;
        }
        return;
    }
    if (prev && (char *)prev + prev->size == (char *)b) {
        /* backward */
        prev->size += b->size;
        prev->next = *pp;
        return;
    }
    b->next = *pp;
    *pp = b;
}

void *malloc(size_t n) {
    if (n == 0) n = 1;
    size_t need = (n + FS_HDR + 15) & ~(size_t)15;
    struct fs_span **pp = &g_free;
    while (*pp) {
        struct fs_span *b = *pp;
        if (b->size >= need) {
            if (b->size - need >= FS_HDR + 16) {
                /* split off the tail keeps the list address-ordered as-is */
                struct fs_span *tail = (struct fs_span *)((char *)b + need);
                tail->size = b->size - need;
                tail->next = b->next;
                *pp = tail;
                b->size = need;
            } else {
                *pp = b->next;   /* whole span taken */
            }
            return (char *)b + FS_HDR;
        }
        pp = &b->next;
    }
    struct fs_span *fresh = fs_grow(need);
    if (!fresh) return NULL;
    fs_release(fresh);
    return malloc(n);      /* retry; the path cannot loop back */
}

void free(void *p) {
    if (!p) return;
    fs_release((struct fs_span *)((char *)p - FS_HDR));
}

void *realloc(void *p, size_t n) {
    if (!p) return malloc(n);
    struct fs_span *b = (struct fs_span *)((char *)p - FS_HDR);
    size_t cur = b->size;
    size_t need = (n + FS_HDR + 15) & ~(size_t)15;
    if (need <= cur) return p;   /* shrink in place; the slack stays hidden */
    void *np = malloc(n);
    if (!np) return NULL;
    memcpy(np, p, cur - FS_HDR);
    free(p);
    return np;
}

void *calloc(size_t nm, size_t sz) {
    size_t n = nm * sz;
    if (nm && n / nm != sz) return NULL;
    void *p = malloc(n);
    if (p) memset(p, 0, n);
    return p;
}

#endif /* __PICO_FREESTAND__ */
