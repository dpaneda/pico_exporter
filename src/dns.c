/* dns.c - minimal RFC 1035 DNS client (A records over UDP).
 *
 * One UDP query against the first nameserver parsed from /etc/resolv.conf,
 * then a fallback query against a configured secondary. No CNAME chasing:
 * the first A record in the answer section wins. Sized for the picolibc
 * deployable (~1.5 KB .text), so it avoids <stdio.h> and libc DNS.
 */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "dns.h"

#define DNS_PORT       53
#define DNS_MAX_PACKET 512

static int parse_ipv4(const char *s, struct in_addr *out)
{
    unsigned int a[4] = {0, 0, 0, 0};
    int i;
    for (i = 0; i < 4; i++) {
        if (*s < '0' || *s > '9') return -1;
        a[i] = 0;
        while (*s >= '0' && *s <= '9') {
            a[i] = a[i] * 10 + (unsigned int)(*s - '0');
            if (a[i] > 255) return -1;
            s++;
        }
        if (i < 3 && *s++ != '.') return -1;
    }
    if (*s != 0) return -1;
    /* Store as network-byte-order (big-endian) in s_addr. The bytes
       [a0, a1, a2, a3] are already in the correct wire order; copy
       them directly so the kernel reads the right IP on LE targets. */
    {
        uint8_t raw[4] = { (uint8_t)a[0], (uint8_t)a[1], (uint8_t)a[2], (uint8_t)a[3] };
        memcpy(&out->s_addr, raw, 4);
    }
    return 0;
}

/* First nameserver from /etc/resolv.conf. */
static int read_ns(struct in_addr *out)
{
    /* A fixed-size buffer truncates silently: systemd-resolved ships a stub
       resolv.conf whose comment header alone is ~500 B, pushing the
       nameserver line past the end of a 512 B slice and silently falling back
       to 127.0.0.1. Read to EOF into a roomy local instead; it only lives
       while a connection is being opened, on stack pages the idle path hands
       back. */
    char buf[2048];
    long n = 0;
    int fd = open("/etc/resolv.conf", O_RDONLY);
    if (fd < 0) return -1;
    for (;;) {
        long k = read(fd, buf + n, (size_t)(sizeof buf - 1 - (size_t)n));
        if (k <= 0) break;
        n += k;
        if (n >= (long)(sizeof buf - 1)) break;
    }
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    char *line = buf;
    while (line) {
        char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (len >= 11) {
            char tmp[256];
            const char *sp;
            if (len >= sizeof tmp) len = sizeof tmp - 1;
            memcpy(tmp, line, len);
            tmp[len] = 0;
            sp = strstr(tmp, "nameserver");
            if (sp) {
                sp += 10;
                while (*sp == ' ' || *sp == '\t') sp++;
                if (parse_ipv4(sp, out) == 0) return 0;
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return -1;
}

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }

/* Encode host as a DNS label sequence; returns bytes written or -1. */
static int enc_qname(uint8_t *buf, const char *host)
{
    int pos = 0;
    const char *s = host;
    while (*s) {
        const char *dot = strchr(s, '.');
        int l = dot ? (int)(dot - s) : (int)strlen(s);
        if (l <= 0 || l > 63) return -1;
        buf[pos++] = (uint8_t)l;
        memcpy(buf + pos, s, (size_t)l);
        pos += l;
        s += l;
        if (*s == '.') s++;
    }
    if (pos == 0) return -1;
    buf[pos++] = 0;
    return pos;
}

/* Skip a (possibly compressed) owner name inside the reply. */
static int skip_name(const uint8_t *pkt, int len, int *pos)
{
    for (;;) {
        if (*pos >= len) return -1;
        uint8_t b = pkt[(*pos)++];
        if (b == 0) return 0;
        if ((b & 0xc0) == 0xc0) {
            (*pos)++;
            return 0;
        }
        if ((b & 0xc0) != 0) return -1;
        if (*pos + (int)b > len) return -1;
        *pos += (int)b;
    }
}

static uint32_t stamp(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) return 0x12345678u;
    return (uint32_t)tv.tv_sec;
}

int dns_resolve_a(const char *host, struct in_addr *out, int timeout_s)
{
    /* A literal dotted quad needs no resolver. Without this, the documented
       local-sink mode (GW_URL=http://127.0.0.1:9001/rw) sent a real A query
       for "127.0.0.1", got NXDOMAIN and failed to connect. */
    if (parse_ipv4(host, out) == 0) return 0;

    static struct in_addr ns_primary, ns_secondary;
    static int have_ns = 0;
    if (!have_ns) {
        if (read_ns(&ns_primary) != 0)
            parse_ipv4("127.0.0.1", &ns_primary);
        parse_ipv4("8.8.8.8", &ns_secondary);
        have_ns = 1;
    }

    uint8_t q[280];
    int ql, si;
    uint16_t id = (uint16_t)(stamp() ^ 0xa5a5);
    memset(q, 0, sizeof q);
    put16(q, id);
    put16(q + 2, 0x0100);          /* RD */
    put16(q + 4, 1);               /* QDCOUNT */
    ql = enc_qname(q + 12, host);
    if (ql < 0) { errno = EINVAL; return -1; }
    put16(q + 12 + ql, 1);         /* qtype A */
    put16(q + 12 + ql + 2, 1);     /* qclass IN */
    ql += 16;

    int tries = timeout_s > 0 ? timeout_s : 1;
    if (tries > 8) tries = 8;
    struct in_addr servers[2];
    servers[0] = ns_primary;
    servers[1] = ns_secondary;

    struct { long tv_sec; long tv_usec; } tv = { 2, 0 };

    for (si = 0; si < 2 && tries > 0; si++, tries--) {
        int rfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (rfd < 0) break;
        setsockopt(rfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons(DNS_PORT);
        sa.sin_addr = servers[si];
        if (sendto(rfd, q, (unsigned long)ql, 0, (struct sockaddr *)&sa, sizeof sa) < 0) {
            close(rfd);
            continue;
        }

        uint8_t r[DNS_MAX_PACKET];
        long n = recvfrom(rfd, r, sizeof r, 0, NULL, NULL);
        close(rfd);
        if (n < 12) continue;
        if (get16(r) != id) continue;
        uint16_t flags = get16(r + 2);
        if (!(flags & 0x8000)) continue;    /* QR */
        int rc = flags & 0xf;
        if (rc == 3) { errno = ENOENT; return -1; }
        if (rc != 0) { errno = EAGAIN; return -1; }
        int ancount = get16(r + 6);
        if (ancount == 0) { errno = ENOENT; return -1; }

        int pos = 12;
        if (skip_name(r, (int)n, &pos) != 0) continue;
        pos += 4;
        if (pos > n) continue;

        struct in_addr found;
        int got = 0, i;
        for (i = 0; i < ancount; i++) {
            if (skip_name(r, (int)n, &pos) != 0) break;
            if (pos + 10 > n) break;
            uint16_t rr_type = get16(r + pos);
            uint16_t rdlen = get16(r + pos + 8);
            int rd = pos + 10;
            if (rd + (int)rdlen > n) break;
            if (rr_type == 1 && rdlen == 4) {
                /* RDATA is already network-order; hand it straight to the
                   caller (sockaddr_in.s_addr is network-order too). */
                memcpy(&found.s_addr, r + rd, 4);
                got = 1;
                break;
            }
            pos = rd + (int)rdlen;
        }
        if (got) { *out = found; return 0; }
        errno = ENOENT;
        return -1;
    }
    errno = ETIMEDOUT;
    return -1;
}