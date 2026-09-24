/* Minimal IPv4 structs for picolibc linux. */
#ifndef _NETINET_IN_H_
#define _NETINET_IN_H_

#include <stdint.h>
#include <sys/socket.h>

typedef uint16_t in_port_t;

struct in_addr { uint32_t s_addr; };

struct sockaddr_in {
    sa_family_t    sin_family;
    in_port_t      sin_port;
    struct in_addr sin_addr;
    unsigned char  sin_zero[8];
};

#define IPPROTO_IP   0
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17
#define INADDR_ANY   ((uint32_t)0x00000000)

static inline uint16_t htons(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }
static inline uint32_t htonl(uint32_t v) {
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff);
}
static inline uint16_t ntohs(uint16_t v) { return htons(v); }
static inline uint32_t ntohl(uint32_t v) { return htonl(v); }

#endif