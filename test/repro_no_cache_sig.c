/*
 * Self-contained demonstration that a provider returning *no_cache = 1 from its
 * query_operation makes EVP_DigestSign catastrophically slow: do_sigver_init
 * fetches the key's keymgmt from its provider on EVERY EVP_DigestSignInit
 * (evp_keymgmt_fetch_from_prov). OpenSSL caches that method unless the provider
 * says no_cache=1, in which case it reconstructs the provider's whole method
 * table (ossl_method_construct, O(algorithm count)) on every single signature.
 *
 * This is the mechanism behind oqsprovider's fast-signature slowdown on OpenSSL
 * >= 3.5: oqsprovider sets rt_algo_filter_enabled=1 there (to runtime-hide
 * ML-DSA/SLH-DSA now provided natively) and returns
 * *no_cache = rt_algo_filter_enabled for the WHOLE provider. On 3.4 the filter
 * is off, no_cache=0, methods are cached, and signing is fast.
 *
 * No third-party providers: a tiny in-process "stub" provider registers one
 * trivial signature + NPAD trivial keymgmts (to mimic a realistic algorithm
 * count). no_cache is a runtime argument so the SAME binary shows both cases.
 *
 * Build (against any OpenSSL 3.4 / 3.5 / main libcrypto):
 *   cc ossl_sig_init_regression.c -o repro -I<ossl>/include -L<ossl>/lib64 \
 *      -lcrypto -Wl,-rpath,<ossl>/lib64
 * Run:   ./repro <iterations> <no_cache 0|1>
 *
 * Observed (same binary, 200 keymgmts), ms/op:
 *              no_cache=0   no_cache=1
 *   OpenSSL 3.4.2   0.0007       0.60
 *   OpenSSL main    0.0008       0.53
 * i.e. OpenSSL's behaviour is identical across versions; ONLY the no_cache flag
 * matters. callgrind attributes the no_cache=1 cost to
 *   EVP_DigestSignInit_ex -> do_sigver_init -> evp_keymgmt_fetch_from_prov
 *   -> ossl_method_construct (per call).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define NPAD 200        /* number of keymgmt algorithms the stub provider offers */

/* ---------- trivial keymgmt ("stubkey" and NPAD-1 padding names) ---------- */
typedef struct { int v; } STUBKEY;

static void *km_new(void *provctx) { (void)provctx; return OPENSSL_zalloc(sizeof(STUBKEY)); }
static void  km_free(void *k) { OPENSSL_free(k); }
static int   km_has(const void *k, int sel) { (void)k; (void)sel; return 1; }
static void *km_gen_init(void *pc, int sel, const OSSL_PARAM p[]) { (void)pc;(void)sel;(void)p; return OPENSSL_zalloc(sizeof(STUBKEY)); }
static void *km_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg) { (void)cb;(void)cbarg; return genctx; }
static void  km_gen_cleanup(void *genctx) { (void)genctx; }
static const char *km_query_name(int operation_id)
{
    return operation_id == OSSL_OP_SIGNATURE ? "stubsig" : NULL;
}
static const OSSL_DISPATCH km_funcs[] = {
    { OSSL_FUNC_KEYMGMT_NEW,        (void (*)(void))km_new },
    { OSSL_FUNC_KEYMGMT_FREE,       (void (*)(void))km_free },
    { OSSL_FUNC_KEYMGMT_HAS,        (void (*)(void))km_has },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,   (void (*)(void))km_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,        (void (*)(void))km_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,(void (*)(void))km_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))km_query_name },
    { 0, NULL }
};

/* ---------- trivial one-shot signature ("stubsig") ---------- */
static void *sig_newctx(void *pc, const char *propq) { (void)propq; (void)pc; return OPENSSL_zalloc(1); }
static void  sig_freectx(void *c) { OPENSSL_free(c); }
static int   sig_dsi(void *c, const char *mdname, void *provkey, const OSSL_PARAM p[])
{ (void)c;(void)mdname;(void)provkey;(void)p; return 1; }
static int   sig_ds(void *c, unsigned char *sig, size_t *siglen, size_t sigsize,
                    const unsigned char *tbs, size_t tbslen)
{
    (void)c; (void)tbs; (void)tbslen;
    if (sig == NULL) { *siglen = 64; return 1; }
    if (sigsize < 64) return 0;
    memset(sig, 0x5a, 64);
    *siglen = 64;
    return 1;
}
static const OSSL_DISPATCH sig_funcs[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,            (void (*)(void))sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,           (void (*)(void))sig_freectx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,  (void (*)(void))sig_dsi },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,       (void (*)(void))sig_ds },
    { 0, NULL }
};

/* ---------- provider: NPAD keymgmts + 1 signature ---------- */
static OSSL_ALGORITHM km_algs[NPAD + 1];
static char           km_names[NPAD][160];
static const OSSL_ALGORITHM sig_algs[] = {
    { "stubsig", "provider=stub", sig_funcs, "stub signature" },
    { NULL, NULL, NULL, NULL }
};
static int g_no_cache = 1;     /* set from argv[2]; mirrors oqsprovider's flag */
static const OSSL_ALGORITHM *prov_query(void *pc, int op, int *no_cache)
{
    (void)pc; *no_cache = g_no_cache;
    if (op == OSSL_OP_KEYMGMT)   return km_algs;
    if (op == OSSL_OP_SIGNATURE) return sig_algs;
    return NULL;
}
static const OSSL_DISPATCH prov_funcs[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))prov_query },
    { 0, NULL }
};
static int stub_init(const OSSL_CORE_HANDLE *h, const OSSL_DISPATCH *in,
                     const OSSL_DISPATCH **out, void **provctx)
{
    (void)h; (void)in;
    int i;
    /* "stubkey" is the real one used for keygen; the rest are padding so the
     * provider has a realistic KEYMGMT algorithm count. Each carries several
     * colon-separated aliases + a long OID, mirroring how real providers name
     * algorithms — this is what ossl_method_construct's namemap work chews on. */
    snprintf(km_names[0], sizeof(km_names[0]),
             "stubkey:2.16.840.1.101.3.4.9.0:stub-alg-0:stub-alias-a-0:stub-alias-b-0");
    for (i = 1; i < NPAD; i++)
        snprintf(km_names[i], sizeof(km_names[i]),
                 "pad%d:2.16.840.1.101.3.4.9.%d:pad-alg-%d:pad-alias-a-%d:pad-alias-b-%d",
                 i, i, i, i, i);
    for (i = 0; i < NPAD; i++) {
        km_algs[i].algorithm_names = km_names[i];
        km_algs[i].property_definition = "provider=stub";
        km_algs[i].implementation = km_funcs;
        km_algs[i].algorithm_description = "stub keymgmt";
    }
    km_algs[NPAD].algorithm_names = NULL;
    *out = prov_funcs;
    *provctx = (void *)h;
    return 1;
}

static double now_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 200000;
    if (argc > 2) g_no_cache = atoi(argv[2]);
    const unsigned char msg[] = "reproducer message";
    size_t mlen = sizeof(msg) - 1;

    if (!OSSL_PROVIDER_add_builtin(NULL, "stub", stub_init)
        || OSSL_PROVIDER_load(NULL, "stub") == NULL) {
        fprintf(stderr, "stub provider load failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(NULL, "stubkey", "provider=stub");
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &k) <= 0) {
        fprintf(stderr, "keygen failed\n"); ERR_print_errors_fp(stderr); return 1;
    }
    EVP_PKEY_CTX_free(g);

    /* Warm up once (populate any legitimately-cached state). */
    unsigned char sig[64]; size_t sl = sizeof(sig);
    EVP_MD_CTX *w = EVP_MD_CTX_new();
    if (EVP_DigestSignInit_ex(w, NULL, NULL, NULL, "provider=stub", k, NULL) <= 0
        || EVP_DigestSign(w, sig, &sl, msg, mlen) <= 0) {
        fprintf(stderr, "sign failed\n"); ERR_print_errors_fp(stderr); return 1;
    }
    EVP_MD_CTX_free(w);

    /* Timed: fresh EVP_MD_CTX + init + one-shot sign, as ordinary one-shot
     * signing does (each op independent, key passed to init each time). */
    double t0 = now_ms();
    for (int i = 0; i < N; i++) {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        EVP_DigestSignInit_ex(c, NULL, NULL, NULL, "provider=stub", k, NULL);
        sl = sizeof(sig);
        EVP_DigestSign(c, sig, &sl, msg, mlen);
        EVP_MD_CTX_free(c);
    }
    double t1 = now_ms();

    printf("stubsig DigestSign  no_cache=%d  provider_keymgmts=%d : "
           "%.5f ms/op over %d\n", g_no_cache, NPAD, (t1 - t0) / N, N);
    EVP_PKEY_free(k);
    return 0;
}
