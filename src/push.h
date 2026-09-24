#ifndef PUSH_H
#define PUSH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Pushed-connection wrapper kept across the whole cycle (keep-alive). */
struct rw_conn {
    int            fd;          /* -1 when closed */
    bool           tls;         /* post-handshake data goes through bearglue */
    bool           open;
    char           host[256];
    char           path[512];
    char           auth[256];   /* "Basic base64(user:pass)" payload already */
    char           err[128];
};

struct rw_url {
    char     host[256];
    uint16_t port;
    char     path[512];
    bool     use_tls;
};

bool parse_rw_url(const char *raw, struct rw_url *u);
void base64_encode(const char *in, size_t n, char *out);   /* out >= 4*((n+2)/3)+1 */
int  basic_auth(const char *user, const char *pass, char *out, size_t out_sz); /* -> 0/1 */

/* Blocking TCP connect (IPv4, SO_RCVTIMEO when timeout_s > 0). Returns fd or
   -1 (set errno). Exposed for tests/run_tests.c. */
int  tcp_connect_host(const char *host, uint16_t port, int timeout_s);

/* Open a connection (plain or TLS) and, for https, perform the BearSSL
 * handshake once. Keeps the error in c->err on failure and leaves c->fd == -1. */
void conn_open(struct rw_conn *c, const struct rw_url *u, const char *auth_b64,
               int64_t now_sec, int timeout_s);
int  conn_push(struct rw_conn *c, const void *body, size_t body_len); /* -> http code, or <= 0 */
void conn_close(struct rw_conn *c);
bool conn_alive(const struct rw_conn *c);

#endif