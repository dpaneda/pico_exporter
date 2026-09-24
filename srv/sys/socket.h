/* Minimal POSIX socket types/syscalls for picolibc linux (aarch64). */
#ifndef _SYS_SOCKET_H_
#define _SYS_SOCKET_H_

#include <stdint.h>

typedef uint32_t socklen_t;
typedef unsigned short sa_family_t;

#define AF_UNSPEC 0
#define AF_INET   2

#define SOCK_STREAM 1
#define SOCK_DGRAM  2

#define SOL_SOCKET 1
#define SO_RCVTIMEO 20

struct sockaddr {
    sa_family_t sa_family;
    char        sa_data[14];
};

struct sockaddr_storage {
    sa_family_t ss_family;
    char        __ss_pad[126];
};

#ifdef __cplusplus
extern "C" {
#endif

int socket(int domain, int type, int protocol);
int connect(int fd, const struct sockaddr *addr, socklen_t len);
int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);
long sendto(int fd, const void *buf, unsigned long len, int flags,
            const struct sockaddr *addr, socklen_t addrlen);
long recvfrom(int fd, void *buf, unsigned long len, int flags,
              struct sockaddr *addr, socklen_t *addrlen);

#ifdef __cplusplus
}
#endif

#endif