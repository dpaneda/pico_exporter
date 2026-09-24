#ifndef BEARGLUE_H
#define BEARGLUE_H

/* bearglue.c exported API: static-storage BearSSL TLS client. Contexts live in
   .bss, one client per process, reused across push cycles. */

#include <stddef.h>
#include <stdint.h>

#include "bearssl.h"   /* for br_x509_trust_anchor in bg_set_ta below */

/* Fragment length requested through RFC 6066: ssl_engine.c derives it from the
   size of the buffer it is handed and the ClientHello advertises it, so asking
   is the same as sizing the buffer. 16384 reproduces BR_SSL_BUFSIZE_MONO and
   requests nothing.

   A peer is free to ignore the request and send a larger record anyway -- its
   Certificate message typically, which for a two-cert RSA chain runs ~3.2 kB.
   That is not a silent problem: BearSSL rejects the record with
   BG_ERR_TOO_LARGE, and bg_grow_iobuf() recovers by moving to a full-size
   buffer, so the small default stays safe against any server.

   2048 rather than 4096 saves 2 kB of resident .bss. Verified against the
   production endpoint (otlp-gateway-prod-us-central-0.grafana.net) and the
   harness one (prometheus-us-central1.grafana.net): both complete the
   handshake -- RSA chain included -- inside the 2373-byte buffer, so they
   honour the extension rather than merely tolerating the request. Re-run
   `run_tests tls` against a new endpoint before trusting it there; a peer
   that ignores the request costs a full-size heap buffer, which is worse
   than not asking. */
#ifndef BG_MAX_FRAG
#define BG_MAX_FRAG 2048
#endif
#define BG_IOBUF_SIZE (BG_MAX_FRAG + 325)

/* br_ssl_engine_last_error() value for a record that did not fit the I/O
   buffer (BR_ERR_TOO_LARGE); duplicated so callers need no BearSSL header.
   bearglue.c static-asserts that it still matches. */
#define BG_ERR_TOO_LARGE 6

int  bg_seed(void);   /* 1 ok, 0 on /dev/urandom failure */
int  bg_handshake(const char *host, int fd, uint32_t days, uint32_t secs);
int  bg_write_all(const unsigned char *buf, int len);   /* 0 ok, -1 on failure */
int  bg_read_some(unsigned char *buf, int len);         /* bytes or <= 0 */
void bg_close(void);
int  bg_last_error(void);   /* br_ssl_engine_last_error */
int  bg_iobuf_size(void);   /* current I/O buffer size */
int  bg_grow_iobuf(void);   /* 1 if it grew: retry the handshake */

/* Replaces the default trust-anchor set for subsequent handshakes (the
   compile-in anchors are the default until this is called). `tas` must live
   for the process lifetime. Ignored by BG_INSECURE_NO_VERIFY builds. */
void bg_set_ta(const br_x509_trust_anchor *tas, size_t n);

/* Test seam: report the first handshake as an oversized record so the
   recovery path in conn_open() can be exercised. Compiled out of nothing by
   default; only the test harness enables it. */
void bg_test_force_too_large(int on);

/* Build-time feature: define BG_INSECURE_NO_VERIFY to skip X.509 validation
   (chain, dates, server name) and trust every well-formed certificate.
   Security-weak: enables MITM. The compiled-in trust anchors are dropped from
   the binary entirely, at the price of losing certificate identity. */

#endif