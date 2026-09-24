/* bearglue.c - static-storage BearSSL client for the remote-write push path.
   Contexts and the I/O buffer live in .bss and are reused across cycles, so the
   TLS cost is a fixed constant. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "bearglue.h"
#include "bearssl.h"

#ifndef BG_INSECURE_NO_VERIFY
#ifndef BG_TA_HEADER
#define BG_TA_HEADER "bearssl_ta_digicert_g2.h"
#endif
#include BG_TA_HEADER   /* defines TAs[] and TAs_NUM */

static const br_x509_trust_anchor *g_tas = TAs;
static size_t                     g_tas_num = TAs_NUM;
#else
/* BG_INSECURE_NO_VERIFY: no trust anchors are compiled in; g_tas stays for
   bg_set_ta()'s API but the insecure engine never reads it. */
static const br_x509_trust_anchor *g_tas = NULL;
static size_t                     g_tas_num = 0;
#endif
static int                        g_force_too_large = 0;

static br_ssl_client_context   g_cc;
#ifndef BG_INSECURE_NO_VERIFY
static br_x509_minimal_context g_xc;
#endif
static br_sslio_context        g_ioc;
/* BG_IOBUF_SIZE (see bearglue.h) asks the peer for a fragment length instead of
   reserving the 16,709 B that any legal record could need. g_buf starts on this
   static buffer and only moves to a full-size heap one if a peer actually sends
   an oversized record. */
_Static_assert(BG_ERR_TOO_LARGE == BR_ERR_TOO_LARGE,
               "BG_ERR_TOO_LARGE drifted from BearSSL");
_Static_assert(BG_IOBUF_SIZE <= BR_SSL_BUFSIZE_MONO,
               "BG_MAX_FRAG above 16384 is not a legal fragment length");
static unsigned char           g_iobuf[BG_IOBUF_SIZE];
static unsigned char          *g_buf = g_iobuf;
static size_t                  g_buflen = sizeof g_iobuf;
static int                     g_fd = -1;
static unsigned char           g_seed[64];
static int                     g_seeded = 0;

/* --- suites TLS 1.2 + AES-128-GCM (A53 no tiene AES-NI pero el endpoint
   soporta GCM; mantener solo esta suite reduce el código de BearSSL). */
static const uint16_t g_suites[] = {
    BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
};

static int bg_sock_read(void *ctx, unsigned char *buf, size_t len) {
    ssize_t n = read(*(int *)ctx, buf, len);
    return n <= 0 ? -1 : (int)n;
}
static int bg_sock_write(void *ctx, const unsigned char *buf, size_t len) {
    ssize_t n = write(*(int *)ctx, buf, len);
    return n <= 0 ? -1 : (int)n;
}

/* Reads the entropy seed once. Returns 1 on success, 0 on failure. */
int bg_seed(void) {
    int fd, ok;
    if (g_seeded) return 1;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    ok = read(fd, g_seed, sizeof g_seed) == (ssize_t)sizeof g_seed;
    close(fd);
    g_seeded = ok;
    return ok;
}

/* Replaces the default trust-anchor set (see bg_set_ta in bearglue.h). */
void bg_set_ta(const br_x509_trust_anchor *tas, size_t n) {
    g_tas = tas;
    g_tas_num = n;
}

void bg_test_force_too_large(int on) { g_force_too_large = on; }

#ifdef BG_INSECURE_NO_VERIFY
/* Accept-any X.509 engine: ignores the chain, the validity dates and the
   server name, and accepts every certificate. The leaf public key is still
   parsed with BearSSL's x509_decoder so the ECDHE/RSA ServerKeyExchange
   signature can be verified - without a usable leaf key that message cannot be
   checked and the handshake fails. This is `curl -k`/InsecureSkipVerify
   semantics: anyone able to present a well-formed certificate can MITM the
   connection. For test/lab endpoints only.

   The leaf certificate is buffered whole and handed to br_x509_decoder in a
   single push: the decoder's T0 VM pauses whenever a chunk runs out, so
   chunked feeding depends on chunk-boundary + length-bookkeeping subtleties
   this engine does not want to own. 16 KiB covers any server whose record
   buffer the TLS engine here can grow to (BG_RECVMAX, see push.c). */
#define BG_AA_MAX_CERT 16384

typedef struct {
    const br_x509_class     *vtable;
    unsigned char            leaf[BG_AA_MAX_CERT];
    size_t                   leaf_len;
    unsigned                 certs_seen;
    int                      in_leaf;
    int                      leaf_ok;
    br_x509_decoder_context  dec;
} bg_aa_ctx;

static bg_aa_ctx g_aa;
static const br_x509_class bg_aa_vtable;   /* forward: start_chain stores it */

static void bg_aa_start_chain(const br_x509_class **ctx, const char *name) {
    (void)name;
    bg_aa_ctx *c = (bg_aa_ctx *)(void *)ctx;
    *ctx = &bg_aa_vtable;
    c->certs_seen = 0;
    c->in_leaf = 0;
    c->leaf_len = 0;
    c->leaf_ok = 0;
}

static void bg_aa_start_cert(const br_x509_class **ctx, uint32_t length) {
    (void)length;
    bg_aa_ctx *c = (bg_aa_ctx *)(void *)ctx;
    c->in_leaf = c->certs_seen++ == 0;   /* only the end-entity key matters */
    c->leaf_len = 0;
}

static void bg_aa_append(const br_x509_class **ctx,
                         const unsigned char *buf, size_t len) {
    bg_aa_ctx *c = (bg_aa_ctx *)(void *)ctx;
    if (!c->in_leaf) return;
    if (len > sizeof c->leaf - c->leaf_len) return;   /* oversize: fail later */
    memcpy(c->leaf + c->leaf_len, buf, len);
    c->leaf_len += len;
}

static void bg_aa_end_cert(const br_x509_class **ctx) {
    bg_aa_ctx *c = (bg_aa_ctx *)(void *)ctx;
    if (!c->in_leaf) return;
    c->in_leaf = 0;
    if (c->leaf_len == 0 || c->leaf_len > sizeof c->leaf) return;
    br_x509_decoder_init(&c->dec, 0, 0);
    br_x509_decoder_push(&c->dec, c->leaf, c->leaf_len);
    br_x509_decoder_push(&c->dec, 0, 0);   /* end of DER */
    c->leaf_ok = br_x509_decoder_last_error(&c->dec) == 0;
}

static unsigned bg_aa_end_chain(const br_x509_class **ctx) {
    bg_aa_ctx *c = (bg_aa_ctx *)(void *)ctx;
    return c->leaf_ok ? 0 : 1;
}

static const br_x509_pkey *bg_aa_get_pkey(const br_x509_class *const *ctx,
                                          unsigned *usages) {
    bg_aa_ctx *c = (bg_aa_ctx *)(void *)ctx;
    if (usages) *usages = BR_KEYTYPE_SIGN | BR_KEYTYPE_KEYX;
    return br_x509_decoder_get_pkey(&c->dec);
}

static const br_x509_class bg_aa_vtable = {
    sizeof(bg_aa_ctx),
    bg_aa_start_chain,
    bg_aa_start_cert,
    bg_aa_append,
    bg_aa_end_cert,
    bg_aa_end_chain,
    bg_aa_get_pkey,
};
#endif /* BG_INSECURE_NO_VERIFY */

/* Handshake over an already-connected fd. days/secs feed X.509 date
   validation. Returns br_ssl_engine_last_error(): 0 means success. */
int bg_handshake(const char *host, int fd, uint32_t days, uint32_t secs) {
#ifdef BG_INSECURE_NO_VERIFY
    (void)days;  /* no certificate validation to feed the date into */
    (void)secs;
#endif
    if (g_force_too_large) {
        /* Test seam, off by default. Reports the first handshake as an
           oversized record so conn_open's recovery path can be exercised:
           every TLS stack tested (OpenSSL 3.6, the Grafana gateway) honours
           the RFC 6066 fragment length, so there is no easy way to provoke
           it for real. */
        static int forced;
        if (!forced) {
            forced = 1;
            return BG_ERR_TOO_LARGE;
        }
    }
    if (!bg_seed()) return -1;
    g_fd = fd;
    br_ssl_client_zero(&g_cc);
    br_ssl_engine_set_versions(&g_cc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&g_cc.eng, g_suites,
                             sizeof g_suites / sizeof g_suites[0]);
    br_ssl_engine_set_ec(&g_cc.eng, &br_ec_p256_m15);
    br_ssl_engine_set_hash(&g_cc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_prf_sha256(&g_cc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_default_aes_gcm(&g_cc.eng);
    /* rsavrfy verifies the ServerKeyExchange signature. Omitting it fails with
       26 BR_ERR_INVALID_ALGORITHM; set_default_rsapub is NOT a substitute. */
    br_ssl_engine_set_default_rsavrfy(&g_cc.eng);

    #ifndef BG_INSECURE_NO_VERIFY
    br_x509_minimal_init(&g_xc, &br_sha256_vtable, g_tas, g_tas_num);
    br_x509_minimal_set_hash(&g_xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_rsa(&g_xc, br_rsa_pkcs1_vrfy_get_default());
    /* Set the date explicitly: BearSSL only falls back to time(NULL) when
       BR_USE_UNIX_TIME was detected at compile time, and leaving it unset means
       validation failure. Not depending on that keeps the musl cross-build
       behaving like the native one. */
    br_x509_minimal_set_time(&g_xc, days, secs);
    br_ssl_engine_set_x509(&g_cc.eng, &g_xc.vtable);
#else
    /* BearSSL dispatches the first x509 callback by reading the context's
       FIRST slot (the vtable) before calling into it, so the accept-any
       context must be pre-wired here; start_chain re-stores the same value. */
    g_aa.vtable = &bg_aa_vtable;
    br_ssl_engine_set_x509(&g_cc.eng, &g_aa.vtable);
#endif

    br_ssl_engine_inject_entropy(&g_cc.eng, g_seed, sizeof g_seed);
    br_ssl_engine_set_buffer(&g_cc.eng, g_buf, g_buflen, 0);
    if (!br_ssl_client_reset(&g_cc, host, 0))
        return br_ssl_engine_last_error(&g_cc.eng);
    br_sslio_init(&g_ioc, &g_cc.eng, bg_sock_read, &g_fd, bg_sock_write, &g_fd);
    /* Force the handshake to complete now so errors surface here. */
    if (br_sslio_flush(&g_ioc) < 0)
        return br_ssl_engine_last_error(&g_cc.eng);
    return br_ssl_engine_last_error(&g_cc.eng);
}

int bg_write_all(const unsigned char *buf, int len) {
    if (br_sslio_write_all(&g_ioc, buf, (size_t)len) < 0) return -1;
    return br_sslio_flush(&g_ioc) < 0 ? -1 : 0;
}

int bg_read_some(unsigned char *buf, int len) {
    return br_sslio_read(&g_ioc, buf, (size_t)len);
}

void bg_close(void) {
    br_sslio_close(&g_ioc);
    g_fd = -1;
}

int bg_last_error(void) { return br_ssl_engine_last_error(&g_cc.eng); }

int bg_iobuf_size(void) { return (int)g_buflen; }

/* Moves to a buffer that holds any legal record, once per process. Returns 1
   when it grew, meaning the caller should retry the handshake on a fresh
   connection; 0 when already full size or out of memory. The block is kept for
   the life of the process on purpose: a peer that needed it once will need it
   every cycle. */
int bg_grow_iobuf(void) {
    if (g_buflen >= BR_SSL_BUFSIZE_MONO) return 0;
    unsigned char *p = malloc(BR_SSL_BUFSIZE_MONO);
    if (!p) return 0;
    g_buf = p;
    g_buflen = BR_SSL_BUFSIZE_MONO;
    return 1;
}
