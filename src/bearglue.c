/* bearglue.c - heap-free BearSSL client for the remote-write push path.
   Contexts and the I/O buffer live in two anonymous page mappings (session:
   kept across cycles; handshake: dropped at idle) and are reused across cycles,
   so the TLS cost is a fixed constant. */
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
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

_Static_assert(BG_ERR_TOO_LARGE == BR_ERR_TOO_LARGE,
               "BG_ERR_TOO_LARGE drifted from BearSSL");
_Static_assert(BG_IOBUF_SIZE <= BR_SSL_BUFSIZE_MONO,
               "BG_MAX_FRAG above 16384 is not a legal fragment length");

/* Session state: the client context and the record buffer. Mapped once, on
   the first handshake, into pages of its own instead of .bss so that what
   must survive a cycle and what must not never share a page. */
struct bg_session {
    br_ssl_client_context cc;
    unsigned char         iobuf[BG_IOBUF_SIZE];
};
static struct bg_session      *g_ss;
static br_sslio_context        g_ioc;

/* g_buf starts on the session pages' iobuf and only moves to a full-size
   mapping if a peer actually sends an oversized record. g_buflen is what the
   fragment-length extension advertises, so it is right before any mapping
   exists. */
static unsigned char          *g_buf;
static size_t                  g_buflen = BG_IOBUF_SIZE;

unsigned char *bg_hs_base;
size_t         bg_hs_len;

static int                     g_fd = -1;
static unsigned char           g_seed[64];
static int                     g_seeded = 0;

static void *map_pages(size_t n) {
    size_t len = (n + 4095) & ~(size_t)4095;
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

/* TLS 1.2 + AES-128-GCM only: the A53 has no AES-NI, but the endpoint
   supports GCM and keeping a single suite shrinks BearSSL's code. */
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

#ifndef BG_INSECURE_NO_VERIFY
typedef br_x509_minimal_context bg_hs_ctx;
#else
typedef bg_aa_ctx bg_hs_ctx;
#endif
static bg_hs_ctx *g_hs;

/* Maps the session and handshake pages the first time. 0 ok, -1 on ENOMEM.
   g_buf is only pointed at the session iobuf if bg_grow_iobuf has not already
   moved it: the fallback path can grow before the first mapping exists. */
static int bg_map(void) {
    if (!g_ss) {
        g_ss = map_pages(sizeof *g_ss);
        if (!g_ss) return -1;
        if (!g_buf) g_buf = g_ss->iobuf;
    }
    if (!g_hs) {
        g_hs = map_pages(sizeof *g_hs);
        if (!g_hs) return -1;
        bg_hs_base = (unsigned char *)g_hs;
        bg_hs_len = (sizeof *g_hs + 4095) & ~(size_t)4095;
    }
    return 0;
}

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
    if (bg_map() != 0) return -1;
    g_fd = fd;
    br_ssl_client_zero(&g_ss->cc);
    br_ssl_engine_set_versions(&g_ss->cc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&g_ss->cc.eng, g_suites,
                             sizeof g_suites / sizeof g_suites[0]);
    br_ssl_engine_set_ec(&g_ss->cc.eng, &br_ec_p256_m15);
    br_ssl_engine_set_hash(&g_ss->cc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_prf_sha256(&g_ss->cc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_default_aes_gcm(&g_ss->cc.eng);
    /* rsavrfy verifies the ServerKeyExchange signature. Omitting it fails with
       26 BR_ERR_INVALID_ALGORITHM; set_default_rsapub is NOT a substitute. */
    br_ssl_engine_set_default_rsavrfy(&g_ss->cc.eng);
    /* The X.509 context is evicted between cycles; a renegotiation would be
       the one way for the peer to make BearSSL read it mid-connection. */
    br_ssl_engine_add_flags(&g_ss->cc.eng, BR_OPT_NO_RENEGOTIATION);

#ifndef BG_INSECURE_NO_VERIFY
    br_x509_minimal_init(g_hs, &br_sha256_vtable, g_tas, g_tas_num);
    br_x509_minimal_set_hash(g_hs, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_rsa(g_hs, br_rsa_pkcs1_vrfy_get_default());
    /* Set the date explicitly: BearSSL only falls back to time(NULL) when
       BR_USE_UNIX_TIME was detected at compile time, and leaving it unset means
       validation failure. Not depending on that keeps the musl cross-build
       behaving like the native one. */
    br_x509_minimal_set_time(g_hs, days, secs);
    br_ssl_engine_set_x509(&g_ss->cc.eng, &g_hs->vtable);
#else
    /* BearSSL dispatches the first x509 callback by reading the context's
       FIRST slot (the vtable) before calling into it, so the accept-any
       context must be pre-wired here; start_chain re-stores the same value. */
    g_hs->vtable = &bg_aa_vtable;
    br_ssl_engine_set_x509(&g_ss->cc.eng, &g_hs->vtable);
#endif

    br_ssl_engine_inject_entropy(&g_ss->cc.eng, g_seed, sizeof g_seed);
    br_ssl_engine_set_buffer(&g_ss->cc.eng, g_buf, g_buflen, 0);
    if (!br_ssl_client_reset(&g_ss->cc, host, 0))
        return br_ssl_engine_last_error(&g_ss->cc.eng);
    br_sslio_init(&g_ioc, &g_ss->cc.eng, bg_sock_read, &g_fd, bg_sock_write, &g_fd);
    /* Force the handshake to complete now so errors surface here. */
    if (br_sslio_flush(&g_ioc) < 0)
        return br_ssl_engine_last_error(&g_ss->cc.eng);
    return br_ssl_engine_last_error(&g_ss->cc.eng);
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

int bg_last_error(void) {
    return g_ss ? br_ssl_engine_last_error(&g_ss->cc.eng) : -1;
}

int bg_iobuf_size(void) { return (int)g_buflen; }

int bg_session_id_len(void) {
    br_ssl_session_parameters pp;
    if (!g_ss) return -1;
    br_ssl_engine_get_session_parameters(&g_ss->cc.eng, &pp);
    return pp.session_id_len;
}

/* Moves to a buffer that holds any legal record, once per process. Returns 1
   when it grew, meaning the caller should retry the handshake on a fresh
   connection; 0 when already full size or out of memory. The block is an
   anonymous mapping kept for the life of the process on purpose: a peer that
   needed it once will need it every cycle. The small buffer inside the session
   pages is then simply unused. */
int bg_grow_iobuf(void) {
    if (g_buflen >= BR_SSL_BUFSIZE_MONO) return 0;
    unsigned char *p = map_pages(BR_SSL_BUFSIZE_MONO);
    if (!p) return 0;
    g_buf = p;
    g_buflen = BR_SSL_BUFSIZE_MONO;
    return 1;
}
