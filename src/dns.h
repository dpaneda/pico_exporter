/* dns.h - minimal RFC 1035 A-record resolver replacing getaddrinfo().
 * Shared by the musl/glibc dev build (libc sockets) and the picolibc
 * deployable (sockets are shimmed via srv/ headers + src/linux_sock.c). */
#ifndef DNS_H
#define DNS_H

#include <netinet/in.h>

/* Resolve `host` (IPv4 only) to *out. `timeout_s` bounds the number of
 * DNS attempts (min 1, capped at 8). Returns 0 on success, -1 on failure
 * with errno set (ENOENT, ETIMEDOUT, EINVAL, ...). */
int dns_resolve_a(const char *host, struct in_addr *out, int timeout_s);

#endif