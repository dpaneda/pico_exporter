/* pdir.c - getdents64 directory iterator (aarch64 + x86_64). */

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "pdir.h"

long syscall(long num, ...);

#if defined(__aarch64__)
#define PDIR_SYS_getdents64 61
#elif defined(__x86_64__)
#define PDIR_SYS_getdents64 217
#else
#error "pdir.c: aarch64 and x86_64 only"
#endif

struct linux_dirent64 {
    uint64_t       d_ino;
    int64_t        d_off;
    unsigned short d_reclen;
    unsigned char  d_type;
    char           d_name[];
};

int pdir_open(struct pdir *d, const char *path) {
    d->off = d->len = 0;
    d->fd = open(path, O_RDONLY);
    return d->fd < 0 ? -1 : 0;
}

const char *pdir_next(struct pdir *d) {
    if (d->fd < 0) return NULL;
    if (d->off >= d->len) {
        long n = syscall(PDIR_SYS_getdents64, (long)d->fd, (long)d->buf,
                         (long)sizeof d->buf);
        if (n <= 0) return NULL;   /* end, or ENOTDIR on a plain file */
        d->off = 0;
        d->len = (int)n;
    }
    struct linux_dirent64 *e = (struct linux_dirent64 *)(d->buf + d->off);
    d->off += e->d_reclen;
    return e->d_name;
}

void pdir_close(struct pdir *d) {
    if (d->fd >= 0) close(d->fd);
    d->fd = -1;
}
