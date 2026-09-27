#ifndef PDIR_H
#define PDIR_H

/* Directory iteration without opendir(), whose calloc of the DIR is what
   put the one heap page into the resting footprint (and there is no opendir
   to call at all on the freestanding link). Names only: no collector reads
   anything else out of a dirent. */

#include <stddef.h>

struct pdir {
    int  fd;             /* -1 when closed */
    int  off, len;       /* cursor into buf */
    _Alignas(8) char buf[1024];
};

int         pdir_open(struct pdir *d, const char *path);   /* 0 ok, -1 error */
const char *pdir_next(struct pdir *d);   /* name (valid until the next call), NULL at end */
void        pdir_close(struct pdir *d);

#endif
