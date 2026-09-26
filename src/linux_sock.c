/* linux_sock.c - Linux socket syscalls on the freestanding link (aarch64 +
   x86_64).
 *
 * The service is linked -nostdlib, so the few network syscalls the push path
 * and src/dns.c need go through raw syscall()s here. Compiles to an empty
 * object on the glibc test-harness build, which links libc's own socket
 * wrappers instead.
 */
#ifdef __PICO_FREESTAND__

#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/utsname.h>

long syscall(long num, ...);

#if defined(__aarch64__)
#define __LINUX_SYS_socket     198
#define __LINUX_SYS_connect    203
#define __LINUX_SYS_sendto     206
#define __LINUX_SYS_recvfrom   207
#define __LINUX_SYS_setsockopt 208
#define __LINUX_SYS_uname      160 /* aarch64 uname -> sys_newuname */
#elif defined(__x86_64__)
#define __LINUX_SYS_socket     41
#define __LINUX_SYS_connect    42
#define __LINUX_SYS_sendto     44
#define __LINUX_SYS_recvfrom   45
#define __LINUX_SYS_setsockopt 54
#define __LINUX_SYS_uname      63 /* x86_64 uname (sys_newuname, 390-byte struct) */
#else
#error "linux_sock.c: socket shims support aarch64 and x86_64 only"
#endif

int socket(int domain, int type, int protocol)
{
    return (int)syscall(__LINUX_SYS_socket, (long)domain, (long)type, (long)protocol);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
    return (int)syscall(__LINUX_SYS_connect, (long)fd, (long)addr, (long)len);
}

int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    return (int)syscall(__LINUX_SYS_setsockopt, (long)fd, (long)level, (long)optname,
                        (long)optval, (long)optlen);
}

long sendto(int fd, const void *buf, unsigned long len, int flags,
            const struct sockaddr *addr, socklen_t addrlen)
{
    return syscall(__LINUX_SYS_sendto, (long)fd, (long)buf, (long)len, (long)flags,
                   (long)addr, (long)addrlen);
}

long recvfrom(int fd, void *buf, unsigned long len, int flags,
              struct sockaddr *addr, socklen_t *addrlen)
{
    return syscall(__LINUX_SYS_recvfrom, (long)fd, (long)buf, (long)len, (long)flags,
                   (long)addr, (long)addrlen);
}

int uname(struct utsname *buf)
{
    return (int)syscall(__LINUX_SYS_uname, (long)buf);
}

/* Minimal sysconf for the handful of queries the exporter makes; anything
 * unknown returns -1/EINVAL like a real libc. */
long sysconf(int name)
{
    if (name == 2) /* _SC_CLK_TCK: Linux HZ, always 100 for user space */ return 100;
    errno = EINVAL;
    return -1;
}

#endif /* __PICO_FREESTAND__ */