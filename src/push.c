/* push.c - minimal HTTP/1.1 client for the OTLP/HTTP push path.
 *
 * Plain-socket POST (P0) + BearSSL TLS via bearglue.c (P2). A connection is
 * held across the whole cycle (keep-alive); TLS handshake happens once at open.
 * read_response consumes the exact Content-Length so the socket (and the TLS
 * stream) are positioned for the next POST. */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1

#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "fmt.h"
#include "push.h"

/* strerror() would drag in picolibc's full 1,152 B errnames table for this one
   message. These are the failures the connect path actually produces; anything
   else still reports its number. */
static const char *errno_name(int e) {
    switch (e) {
    case ECONNREFUSED: return "connection refused";
    case ETIMEDOUT:    return "timed out";
    case EHOSTUNREACH: return "host unreachable";
    case ENETUNREACH:  return "network unreachable";
    case ECONNRESET:   return "connection reset";
    case EAGAIN:       return "temporarily unavailable";
    case EINVAL:       return "invalid argument";
    default:           return "error";
    }
}
#include "bearglue.h"
#include "dns.h"

#define UNIX_EPOCH_DAYS 719528u  /* days from 0 AD to 1970-01-01 */

/* --- URL parsing --- */
bool parse_rw_url(const char *raw, struct rw_url *u) {
    memset(u, 0, sizeof *u);
    const char *p = raw, *q;

    q = strstr(raw, "://");
    if (!q) return false;
    if ((size_t)(q - p) == 5 && (strncmp(p, "https", 5) == 0)) u->use_tls = true;
    else if ((size_t)(q - p) == 4 && (strncmp(p, "http", 4) == 0)) u->use_tls = false;
    else return false;
    p = q + 3;

    size_t hlen = 0;
    while (p[hlen] && p[hlen] != ':' && p[hlen] != '/') hlen++;
    if (hlen == 0 || hlen >= sizeof u->host) return false;
    memcpy(u->host, p, hlen);
    u->host[hlen] = 0;
    p += hlen;

    u->port = u->use_tls ? 443 : 80;
    if (*p == ':') {
        const char *end;
        long long pt = fmt_parse_ll(p + 1, &end);
        if (end == p + 1) return false;
        if (pt < 1 || pt > 65535) return false;
        u->port = (uint16_t)pt;
        p = end;
    }

    if (*p == 0) {
        strcpy(u->path, "/");
        return true;
    }
    size_t plen = strnlen(p, sizeof u->path - 1);
    memcpy(u->path, p, plen);
    u->path[plen] = 0;
    return true;
}

/* --- base64 (RFC 4648) --- */
static const char b64t[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const char *in, size_t n, char *out) {
    size_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)(unsigned char)in[i] << 16) |
                     ((uint32_t)(unsigned char)in[i + 1] << 8) |
                     (uint32_t)(unsigned char)in[i + 2];
        out[o++] = b64t[(v >> 18) & 63];
        out[o++] = b64t[(v >> 12) & 63];
        out[o++] = b64t[(v >> 6) & 63];
        out[o++] = b64t[v & 63];
    }
    size_t rem = n - i;
    if (rem == 1) {
        uint32_t v = (uint32_t)(unsigned char)in[i] << 16;
        out[o++] = b64t[(v >> 18) & 63];
        out[o++] = b64t[(v >> 12) & 63];
        out[o++] = '=';
        out[o++] = '=';
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)(unsigned char)in[i] << 16) |
                     ((uint32_t)(unsigned char)in[i + 1] << 8);
        out[o++] = b64t[(v >> 18) & 63];
        out[o++] = b64t[(v >> 12) & 63];
        out[o++] = b64t[(v >> 6) & 63];
        out[o++] = '=';
    }
    out[o] = 0;
}

int basic_auth(const char *user, const char *pass, char *out, size_t out_sz) {
    char up[256];
    size_t ul = user ? strlen(user) : 0, pl = pass ? strlen(pass) : 0;
    if (ul + pl + 2 > sizeof up) return 0;
    memcpy(up, user ? user : "", ul);
    up[ul] = ':';
    memcpy(up + ul + 1, pass ? pass : "", pl);
    up[ul + 1 + pl] = 0;
    if (4 * ((ul + pl + 2 + 2) / 3) + 1 > out_sz) return 0;
    base64_encode(up, ul + 1 + pl, out);
    return 1;
}

/* --- socket / stream helpers --- */
int tcp_connect_host(const char *host, uint16_t port, int timeout_s) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    if (dns_resolve_a(host, &sa.sin_addr, 3) != 0) return -1;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    if (timeout_s > 0) {
        struct { long tv_sec; long tv_usec; } tv = { timeout_s, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    return fd;
}

static int send_all(int fd, const void *data, size_t len) {
    const char *p = data;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* Stream-level I/O: routes between the raw fd and the BearSSL sslio context. */
static int conn_read(struct rw_conn *c, char *buf, size_t n) {
    if (c->tls) return bg_read_some((unsigned char *)buf, (int)n);
    return (int)read(c->fd, buf, n);
}

static int conn_write_all(struct rw_conn *c, const void *data, size_t len) {
    if (c->tls)
        return bg_write_all((const unsigned char *)data, (int)len) == 0 ? 0 : -1;
    return send_all(c->fd, data, len);
}

struct http_resp {
    int code;
    int content_len;    /* -1 when absent -> connection cannot be reused */
    int dead;           /* caller must reconnect (EOF/truncated) */
    char msg[96];
};

/* Reads one full response (headers + body as per Content-Length). Leaves the
   connection positioned for the next request when content_len >= 0. */
/* Largest header block we will consume before giving up on the peer. Nothing
   is stored, so this only bounds how long a broken server can keep us here. */
#define HDR_LIMIT 16384

/* Leading-digits reader (the atoi replacement). Skips the blanks the
   header parse points at ("Content-Length: 354"): atoi did too, and a
   zero read here would leave the body undrained and desync the stream. */
static int header_num(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    int v = 0;
    while (*s >= '0' && *s <= '9')
        v = v * 10 + (*s++ - '0');
    return v;
}

static void read_response(struct rw_conn *c, struct http_resp *r) {
    memset(r, 0, sizeof *r);
    r->content_len = -1;
    /* Only the status line and Content-Length are ever read out of the header
       block, so it is parsed a line at a time and never held whole. The 4 kB
       block this replaced was the largest stack frame in the binary, and it
       also imposed a header-size limit nobody had measured against the
       gateway: a response whose headers did not fit was reported dead and
       retried forever. A line longer than the buffer is now truncated for
       parsing but still consumed, so the stream cannot desynchronise. */
    char line[256];
    size_t ll = 0, total = 0;
    int first = 1, hl = -1;

    for (;;) {
        char ch;
        if (conn_read(c, &ch, 1) <= 0 || ++total > HDR_LIMIT) {
            r->dead = 1;
            return;
        }
        if (ch == '\r') continue;              /* CR only ever ends a line */
        if (ch != '\n') {
            if (ll < sizeof line - 1) line[ll++] = ch;
            continue;
        }
        line[ll] = 0;
        if (ll == 0) break;                    /* blank line: headers done */
        if (first) {
            first = 0;
            /* HTTP/1.1 NNN ... */
            if (ll >= 9 && strncmp(line, "HTTP/1.", 7) == 0)
                r->code = header_num(line + 9);
            else if (ll >= 6)
                r->code = header_num(line + 5);
        } else if (ll >= 15 && strncasecmp(line, "content-length:", 15) == 0) {
            hl = header_num(line + 15);
        }
        ll = 0;
    }
    if (first || hl < 0) { r->dead = 1; return; }   /* keep-alive needs a length */
    r->content_len = hl;

    /* Drain the (likely small) response body. */
    int remaining = hl;
    char junk[256];
    while (remaining > 0) {
        int n = conn_read(c, junk,
                          remaining < (int)sizeof junk ? remaining : (int)sizeof junk);
        if (n <= 0) { r->dead = 1; r->content_len = -1; return; }
        remaining -= n;
    }
}

/* --- connection lifecycle --- */
void conn_open(struct rw_conn *c, const struct rw_url *u, const char *auth_b64,
               int64_t now_sec, int timeout_s) {
    memset(c, 0, sizeof *c);
    c->fd = -1;
    strcpy(c->host, u->host);
    strcpy(c->path, u->path);
    if (auth_b64 && *auth_b64) {
        char *o = c->auth;
        fmt_str_append(&o, "Basic ");
        fmt_str_append(&o, auth_b64);
        *o = 0;
    }
    c->tls = u->use_tls;

    int fd = tcp_connect_host(u->host, u->port, timeout_s);
    if (fd < 0) {
        int e = errno;
        char *o = c->err;
        fmt_str_append(&o, "connect: ");
        fmt_str_append(&o, errno_name(e));
        fmt_str_append(&o, " (errno=");
        fmt_i64_append(&o, e);
        fmt_str_append(&o, ")");
        *o = 0;
        return;
    }
    if (c->tls) {
        if (bg_seed() == 0) {
            close(fd);
            char *o = c->err;
            fmt_str_append(&o, "tls: entropy seed failed");
            *o = 0;
            return;
        }
        uint32_t days = UNIX_EPOCH_DAYS + (uint32_t)(now_sec / 86400);
        uint32_t secs = (uint32_t)(now_sec % 86400);
        int hs = bg_handshake(c->host, fd, days, secs);
        /* The peer sent a record larger than our I/O buffer -- its Certificate
           message, on a peer that ignored the fragment length we asked for.
           Grow once to a buffer that holds any legal record and retry on a
           fresh connection; the old one is dead either way. */
        if (hs == BG_ERR_TOO_LARGE && bg_grow_iobuf()) {
            close(fd);
            fd = tcp_connect_host(u->host, u->port, timeout_s);
            if (fd < 0) {
                int e = errno;
                char *o = c->err;
                fmt_str_append(&o, "reconnect after tls buffer grow: ");
                fmt_str_append(&o, errno_name(e));
                fmt_str_append(&o, " (errno=");
                fmt_i64_append(&o, e);
                fmt_str_append(&o, ")");
                *o = 0;
                return;
            }
            char msg[96];
            char *o = msg;
            fmt_str_append(&o,
                "push: peer sent an oversized record; TLS buffer grown to ");
            fmt_i64_append(&o, bg_iobuf_size());
            fmt_str_append(&o, " bytes\n");
            size_t len = (size_t)(o - msg);
            size_t off = 0;
            while (off < len) {
                ssize_t w = write(2, msg + off, len - off);
                if (w <= 0) break;
                off += (size_t)w;
            }
            hs = bg_handshake(c->host, fd, days, secs);
        }
        if (hs != 0) {
            close(fd);
            char *o = c->err;
            fmt_str_append(&o, "tls err=");
            fmt_i64_append(&o, hs);
            *o = 0;
            return;
        }
    }
    c->fd = fd;
    c->open = true;
}

int conn_push(struct rw_conn *c, const void *body, size_t body_len) {
    if (!c->open) return 0;
    char head[512];
    char *o = head;
    fmt_str_append(&o, "POST ");
    fmt_str_append(&o, c->path);
    fmt_str_append(&o, " HTTP/1.1\r\nHost: ");
    fmt_str_append(&o, c->host);
    fmt_str_append(&o, "\r\n");
    if (c->auth[0]) {
        fmt_str_append(&o, "Authorization: ");
        fmt_str_append(&o, c->auth);
        fmt_str_append(&o, "\r\n");
    }
    fmt_str_append(&o,
        "Content-Type: application/x-protobuf\r\n"
        "Content-Length: ");
    fmt_u64_append(&o, body_len);
    fmt_str_append(&o, "\r\nConnection: keep-alive\r\n\r\n");
    size_t h = (size_t)(o - head);
    if (conn_write_all(c, head, h) != 0 ||
        (body_len > 0 && conn_write_all(c, body, body_len) != 0)) {
        c->open = false;
        return -1;
    }
    struct http_resp r;
    read_response(c, &r);
    if (r.dead) c->open = false;
    if (r.code == 0) return -1;
    return r.code;
}

void conn_close(struct rw_conn *c) {
    if (c->tls && c->open) bg_close();
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->open = false;
}

bool conn_alive(const struct rw_conn *c) { return c->open && c->fd >= 0; }
