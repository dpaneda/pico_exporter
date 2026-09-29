/* freestand.c - the libc surface the freestanding binaries run on.
 *
 * Each entry point is a thin wrapper over one raw syscall (open is openat
 * because aarch64 has no plain-open syscall), and wrappers set errno the way
 * a libc would, since push.c and dns.c message off errno. The mem and str
 * helpers replace picolibc's, and `statvfs` maps the raw statfs syscall into
 * the glibc-shaped struct statvfs the filesystem collector reads.
 *
 * Compiles to nothing under the glibc test-harness link: the whole file is
 * guarded on -D__PICO_FREESTAND__, a define only the service builds carry.
 */

#ifdef __PICO_FREESTAND__

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>

/* glibc, with _GNU_SOURCE (ISOC23 on), defines strchr/strstr as _Generic
   macros and sys/stat.h st_atime/st_mtime/st_ctime as st_*tim.tv_sec macros.
   This TU defines the functions and fills struct stat by hand, so take
   everything those macros would rewrite back to identifiers. */
#undef strchr
#undef strstr
#undef st_atime
#undef st_atime_nsec
#undef st_mtime
#undef st_mtime_nsec
#undef st_ctime
#undef st_ctime_nsec

#include "freestand.h"

extern char **environ;   /* defined in src/start.c */

/* arch_prctl / the FS base: only x86_64 needs it (see fs_set_tls_block), but
   the number has to exist for the aarch64 table too, so both declare it. */
#define FS_ARCH_SET_FS 0x1002

#if defined(__aarch64__)
#define FS_SYS_read          63
#define FS_SYS_write         64
#define FS_SYS_close         57
#define FS_SYS_openat        56
#define FS_SYS_mmap          222
#define FS_SYS_madvise       233
#define FS_SYS_clock_gettime 113
#define FS_SYS_gettimeofday  169
#define FS_SYS_newfstatat    79
#define FS_SYS_statfs        43
#define FS_SYS_rt_sigprocmask 135
#define FS_SYS_clone         220
#define FS_SYS_execve        221
#define FS_SYS_wait4         260
#define FS_SYS_pipe2         59
#define FS_SYS_dup3          24
#elif defined(__x86_64__)
#define FS_SYS_read          0
#define FS_SYS_write         1
#define FS_SYS_close         3
#define FS_SYS_openat        257
#define FS_SYS_mmap          9
#define FS_SYS_madvise       28
#define FS_SYS_clock_gettime 228
#define FS_SYS_gettimeofday  78
#define FS_SYS_newfstatat    262
#define FS_SYS_statfs        137
#define FS_SYS_rt_sigprocmask 14
#define FS_SYS_clone         56
#define FS_SYS_arch_prctl    158
#define FS_SYS_execve        59
#define FS_SYS_wait4         61
#define FS_SYS_pipe2         293
#define FS_SYS_dup3          292
#else
#error "freestand.c: aarch64 and x86_64 only"
#endif

/* --- syscall dispatch ---------------------------------------------------- */

#if defined(__x86_64__)
static long fs_sys(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    long r;
    register long r10 __asm__("r10") = a3;
    register long r8 __asm__("r8") = a4;
    register long r9 __asm__("r9") = a5;
    __asm__ volatile ("syscall"
                      : "=a"(r)
                      : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10),
                        "r"(r8), "r"(r9)
                      : "rcx", "r11", "memory");
    return r;
}
#elif defined(__aarch64__)
static long fs_sys(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile ("svc 0"
                      : "+r"(x0)
                      : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                      : "memory");
    return x0;
}
#endif

static inline long fs_sys1(long n, long a) { return fs_sys(n, a, 0, 0, 0, 0, 0); }
static inline long fs_sys2(long n, long a, long b) {
    return fs_sys(n, a, b, 0, 0, 0, 0);
}
static inline long fs_sys3(long n, long a, long b, long c) {
    return fs_sys(n, a, b, c, 0, 0, 0);
}
static inline long fs_sys4(long n, long a, long b, long c, long d) {
    return fs_sys(n, a, b, c, d, 0, 0);
}
static inline long fs_sys5(long n, long a, long b, long c, long d, long e) {
    return fs_sys(n, a, b, c, d, e, 0);
}

/* pdir.c and linux_sock.c declare `syscall()` extern and shell out to it. */
long syscall(long num, ...) {
    va_list ap;
    long a[6];
    va_start(ap, num);
    for (int i = 0; i < 6; i++) a[i] = va_arg(ap, long);
    va_end(ap);
    return fs_sys(num, a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* --- errno: plain .bss, a single-threaded exporter has no TLS to serve --- */

int *__errno_location(void) {
    static int fs_errno;
    return &fs_errno;
}

/* --- signals ------------------------------------------------------------- */

/* Blocking == the write on a server-closed keep-alive socket returns EPIPE
   instead of raising SIGPIPE; push.c reconnects. The signal(SIGPIPE, SIG_IGN)
   equivalent, without libc's signal(). */
int fs_ignore_sigpipe(void) {
    unsigned long set = 1UL << 13;   /* SIGPIPE is 13 on every Linux */
    long r = fs_sys4(FS_SYS_rt_sigprocmask, 0 /* SIG_BLOCK */, (long)&set, 0, 8);
    if (r < 0) { errno = (int)-r; return -1; }
    return 0;
}

/* --- thread base (TLS) ----------------------------------------------------- */

/* The x86_64 default stack-protector guard reads the canary from %fs:0x28. On
   a -nostdlib link the kernel starts the process with no FS base at all, so
   that load faults: every canary-protected function dies with SIGSEGV before
   it can compare anything. Our own TUs are compiled with
   -mstack-protector-guard=global and never touch %fs, but BearSSL is a
   separate build (tools/bearssl_env.sh) compiled at default flags, and it
   brings 101 of those loads with it. Rather than fight that -- the guard is a
   per-TU codegen decision carried in each function's LTO target options, so
   neither the link-time flag nor -fno-stack-protector can cover BearSSL's
   target-attribute files -- give the address the canary lives at: a 64-byte
   block in .bss (the dirty data page, so no extra RSS at rest) with the
   AT_RANDOM secret at +0x28, exactly where the guard looks.
   aarch64 needs none of this: its gcc defaults to the global guard, which is
   measured to emit zero TLS-base reads. */
int fs_set_tls_block(void *base) {
#if defined(__x86_64__)
    long r = fs_sys2(FS_SYS_arch_prctl, FS_ARCH_SET_FS, (long)base);
    if (r < 0) { errno = (int)-r; return -1; }
    return 0;
#else
    (void)base;
    return 0;
#endif
}

/* --- I/O ----------------------------------------------------------------- */

ssize_t read(int fd, void *buf, size_t n) {
    long r = fs_sys3(FS_SYS_read, fd, (long)buf, (long)n);
    if (r < 0) { errno = (int)-r; return (ssize_t)-1; }
    return (ssize_t)r;
}

ssize_t write(int fd, const void *buf, size_t n) {
    long r = fs_sys3(FS_SYS_write, fd, (long)buf, (long)n);
    if (r < 0) { errno = (int)-r; return (ssize_t)-1; }
    return (ssize_t)r;
}

int open(const char *path, int flags, ...) {
    int mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    long r = fs_sys4(FS_SYS_openat, -100 /* AT_FDCWD */, (long)path, flags, mode);
    if (r < 0) { errno = (int)-r; return -1; }
    return (int)r;
}

int close(int fd) {
    long r = fs_sys1(FS_SYS_close, fd);
    if (r < 0) { errno = (int)-r; return -1; }
    return 0;
}

/* --- mapping ------------------------------------------------------------- */

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off) {
    long r = fs_sys(FS_SYS_mmap, (long)addr, (long)len, prot, flags, fd, off);
    if (r < 0) { errno = (int)-r; return MAP_FAILED; }
    return (void *)(uintptr_t)r;
}

int madvise(void *addr, size_t len, int advice) {
    long r = fs_sys3(FS_SYS_madvise, (long)addr, (long)len, advice);
    if (r < 0) { errno = (int)-r; return -1; }
    return 0;
}

/* --- clocks -------------------------------------------------------------- */

int clock_gettime(clockid_t clk, struct timespec *ts) {
    long r = fs_sys2(FS_SYS_clock_gettime, clk, (long)ts);
    if (r < 0) { errno = (int)-r; return -1; }
    return 0;
}

int gettimeofday(struct timeval *tv, void *tz) {
    long r = fs_sys2(FS_SYS_gettimeofday, (long)tv, (long)tz);
    if (r < 0) { errno = (int)-r; return -1; }
    return 0;
}

time_t time(time_t *t) {
    struct timespec ts;
    if (fs_sys2(FS_SYS_clock_gettime, 0 /* CLOCK_REALTIME */, (long)&ts) < 0)
        return (time_t)-1;
    if (t) *t = ts.tv_sec;
    return ts.tv_sec;
}

/* --- file metadata: raw syscalls translated into the glibc shapes -------- */

/* The kernel `struct stat` that the newfstatat syscall fills: x86_64 and
   aarch64 (asm-generic) layouts. Only the fields translated below are read
   anywhere (textfile mtime); the static asserts pin the sizes and the mtime
   offsets, and the --metrics-once assertions on the fake rootfs (exact
   node_textfile_mtime_seconds values, uati) check them in practice. */
#if defined(__x86_64__)
struct fs_kstat {
    uint64_t st_dev, st_ino, st_nlink;
    uint32_t st_mode, st_uid, st_gid, pad0;
    uint64_t st_rdev, st_size, st_blksize, st_blocks;
    int64_t  fs_atime; uint64_t fs_atime_nsec;
    int64_t  fs_mtime; uint64_t fs_mtime_nsec;
    int64_t  fs_ctime; uint64_t fs_ctime_nsec;
    uint64_t unused[3];
};
_Static_assert(sizeof(struct fs_kstat) == 144, "x86_64 struct stat size");
_Static_assert(offsetof(struct fs_kstat, fs_mtime) == 88, "x86_64 mtime offset");
#elif defined(__aarch64__)
struct fs_kstat {
    uint64_t st_dev, st_ino;
    uint32_t st_mode, st_nlink, st_uid, st_gid;
    uint64_t st_rdev, pad1, st_size;
    uint32_t st_blksize, pad2;
    uint64_t st_blocks;
    int64_t  fs_atime; uint64_t fs_atime_nsec;
    int64_t  fs_mtime; uint64_t fs_mtime_nsec;
    int64_t  fs_ctime; uint64_t fs_ctime_nsec;
    uint32_t unused4, unused5;
};
_Static_assert(sizeof(struct fs_kstat) == 128, "aarch64 struct stat size");
_Static_assert(offsetof(struct fs_kstat, fs_mtime) == 88, "aarch64 mtime offset");
#endif

int stat(const char *path, struct stat *out) {
    struct fs_kstat k;
    long r = fs_sys3(FS_SYS_newfstatat, -100 /* AT_FDCWD */, (long)path, (long)&k);
    if (r < 0) { errno = (int)-r; return -1; }
    out->st_dev = k.st_dev;
    out->st_ino = k.st_ino;
    out->st_mode = k.st_mode;
    out->st_nlink = k.st_nlink;
    out->st_uid = k.st_uid;
    out->st_gid = k.st_gid;
    out->st_rdev = k.st_rdev;
    out->st_size = (off_t)k.st_size;
    out->st_blksize = k.st_blksize;
    out->st_blocks = (long)k.st_blocks;
    out->st_atim.tv_sec = k.fs_atime;
    out->st_atim.tv_nsec = (long)k.fs_atime_nsec;
    out->st_mtim.tv_sec = k.fs_mtime;
    out->st_mtim.tv_nsec = (long)k.fs_mtime_nsec;
    out->st_ctim.tv_sec = k.fs_ctime;
    out->st_ctim.tv_nsec = (long)k.fs_ctime_nsec;
    return 0;
}

/* statvfs over the raw statfs syscall: on 64-bit targets the kernel layout
   is the asm-generic one (all __statfs_word fields, f_spare[4] tail), which
   is what glibc's `struct statfs` on the cross gcc holds, so the syscall and
   the library struct are the same shape. Fields the filesystem collector
   reads are copied; the few statvfs carries that statfs does not (none
   material) stay zero. */
int statvfs(const char *path, struct statvfs *out) {
    struct statfs fs;
    memset(out, 0, sizeof *out);
    long r = fs_sys2(FS_SYS_statfs, (long)path, (long)&fs);
    if (r < 0) { errno = (int)-r; return -1; }
    out->f_bsize = fs.f_bsize;
    out->f_frsize = fs.f_frsize;
    out->f_blocks = fs.f_blocks;
    out->f_bfree = fs.f_bfree;
    out->f_bavail = fs.f_bavail;
    out->f_files = fs.f_files;
    out->f_ffree = fs.f_ffree;
    out->f_flag = fs.f_flags;
    out->f_namemax = fs.f_namelen;
    if (fs.f_fsid.__val[0] | fs.f_fsid.__val[1])
        out->f_fsid = (unsigned long)fs.f_fsid.__val[0] |
                      ((unsigned long)fs.f_fsid.__val[1] << 32);
    return 0;
}

/* --- popen-shaped sh -c (the systemd collector is its only user) --------- */

int popen_sh(const char *cmd) {
    int pfd[2];
    if (fs_sys2(FS_SYS_pipe2, (long)pfd, 0) < 0) return -1;
    long pid = fs_sys5(FS_SYS_clone, 17 /* SIGCHLD */, 0, 0, 0, 0);
    if (pid < 0) {
        int e = errno;
        close(pfd[0]);
        close(pfd[1]);
        errno = e;
        return -1;
    }
    if (pid == 0) {
        /* Caught signals reset across execve, but the blocked mask does NOT:
           the parent's SIGPIPE block would make the child's systemctl inherit
           a blocked SIGPIPE (writes failing with EPIPE quietly, a half-state a
           plain popen never produced). Reset the mask to what a fresh exec
           gets, then hand over the pipe. */
        unsigned long clear = 0;
        fs_sys4(FS_SYS_rt_sigprocmask, 2 /* SIG_SETMASK */, (long)&clear, 0, 8);
        fs_sys3(FS_SYS_dup3, pfd[1], 1, 0);
        fs_sys3(FS_SYS_dup3, pfd[1], 2, 0);
        close(pfd[0]);
        close(pfd[1]);
        char *sh_arg[4] = { (char *)"/bin/sh", (char *)"-c", (char *)cmd, NULL };
        fs_sys3(FS_SYS_execve, (long)sh_arg[0], (long)sh_arg, (long)environ);
        _exit(127);        /* exec failed: popen's reads will see EOF */
    }
    close(pfd[1]);
    return pfd[0];
}

int pclose_sh(int fd) {
    if (fd >= 0) close(fd);
    int st = -1;
    /* Exactly one child can ever have been spawned; wait it out. */
    if (fs_sys3(FS_SYS_wait4, -1, (long)&st, 0) < 0) return -1;
    return st;
}

/* --- mem* / str* ---------------------------------------------------------
   Free-standing definitions for the -nostdlib links (nothing else defines
   them). The several-byte strings the collectors push through them ride in
   registers; the 8-byte-aligned fast path in memcpy stays for the /proc
   buffers' growth copies. If a future gcc teaches itself to rewrite one of
   these loops into a call to itself, that must be shut up with per-object
   -fno-builtin in the Makefile -- checked in the build verification. */
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if ((((uintptr_t)d ^ (uintptr_t)s) & 7) || n < 8) {
        for (size_t i = 0; i < n; i++) d[i] = s[i];
        return dst;
    }
    uint64_t *dw = (uint64_t *)d;
    const uint64_t *sw = (const uint64_t *)s;
    size_t nw = n >> 3;
    for (size_t i = 0; i < nw; i++) dw[i] = sw[i];
    unsigned char *d8 = (unsigned char *)(dw + nw);
    const unsigned char *s8 = (const unsigned char *)(sw + nw);
    for (size_t i = 0; i < (n & 7); i++) d8[i] = s8[i];
    return dst;
}

/* Word-at-a-time, never a byte loop: at -Os gcc leaves a byte memset
   unrolled-by-nothing (movb/inc/jmp, ~1 byte/cycle), which is ~20x picolibc's
   word loop and is the single hottest thing in the binary when a caller
   zeroes kilobytes. The head loop only runs for an unaligned dst. */
void *memset(void *d, int c, size_t n) {
    unsigned char *d_ = d;
    if (!n) return d;
    uint64_t pat = (uint64_t)(unsigned char)c * 0x0101010101010101ULL;
    while (n && ((uintptr_t)d_ & 7)) { *d_++ = (unsigned char)c; n--; }
    uint64_t *dw = (uint64_t *)d_;
    size_t nw = n >> 3;
    for (size_t i = 0; i < nw; i++) dw[i] = pat;
    d_ = (unsigned char *)(dw + nw);
    for (size_t i = 0; i < (n & 7); i++) *d_++ = (unsigned char)c;
    return d;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if ((uintptr_t)d < (uintptr_t)s || (uintptr_t)d == (uintptr_t)s || n == 0)
        return memcpy(dst, src, n);
    d += n; s += n;
    while (n--) *--d = *--s;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *ua = a, *ub = b;
    for (size_t i = 0; i < n; i++)
        if (ua[i] != ub[i]) return ua[i] < ub[i] ? -1 : 1;
    return 0;
}

size_t strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

char *strcpy(char *d, const char *s) {
    char *o = d;
    while ((*d++ = *s++)) ;
    return o;
}

size_t strnlen(const char *s, size_t n) {
    size_t i = 0;
    while (i < n && s[i]) i++;
    return i;
}

char *strchr(const char *s, int c) {
    for (const char *p = s; ; p++) {
        if (*p == (char)c) return (char *)p;
        if (*p == 0) return NULL;
    }
}

int strcmp(const char *a, const char *b) {
    unsigned char ua, ub;
    do {
        ua = (unsigned char)*a++;
        ub = (unsigned char)*b++;
    } while (ua && ua == ub);
    return ua - ub;
}

int strncmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char ua = (unsigned char)a[i], ub = (unsigned char)b[i];
        if (ua != ub) return ua - ub;
        if (ua == 0) return 0;
    }
    return 0;
}

/* ASCII fold only: the compared tokens are HTTP header names and metric
   names, exactly what push.c and the textfile parser hold. */
static int fs_tolower(int c) {
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

int strncasecmp(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int la = fs_tolower(a[i]), lb = fs_tolower(b[i]);
        if (la != lb) return la - lb;
        if (la == 0) return 0;
    }
    return 0;
}

size_t strcspn(const char *s, const char *reject) {
    size_t n = 0;
    for (; s[n]; n++)
        for (const char *r = reject; *r; r++)
            if (s[n] == *r) return n;
    return n;
}

char *strstr(const char *hay, const char *needle) {
    if (!needle[0]) return (char *)hay;
    for (const char *p = hay; *p; p++) {
        const char *h = p, *nn = needle;
        while (*h && *h == *nn) { h++; nn++; }
        if (*nn == 0) return (char *)p;
    }
    return NULL;
}

#endif /* __PICO_FREESTAND__ */
