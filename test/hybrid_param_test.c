/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * EVP_PKEY parameter round-trip / gettable-param parity (analog of oqsprovider's
 * oqs_test_evp_pkey_params, hybrid slice).
 *
 * Exercises the keymgmt export/import + get_params surface directly, without
 * going through DER encoders (that path is covered by hybrid_encode_test): for
 * each hybrid KEM and signature it
 *   - queries the standard descriptor params (bits, security-bits, max-size) and
 *     asserts they are populated and sane;
 *   - for KEMs, reads ENCODED_PUBLIC_KEY and checks its length equals the sum of
 *     the component public-key lengths (raw-concat wire form);
 *   - exports the public key with EVP_PKEY_todata(), re-imports it with
 *     EVP_PKEY_fromdata(), and requires EVP_PKEY_eq() == 1;
 *   - for signatures, additionally signs with the original key and verifies with
 *     the param-reimported public key, proving the reimport is functional and
 *     not merely byte-equal.
 *
 * Drives the full master tables. Algorithms whose components are unavailable
 * (e.g. Frodo/BIKE/HQC without oqsprovider, or any PQ on 3.4) self-skip.
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

/* OSSL_DISPATCH_END (a { 0, NULL } terminator) was added in OpenSSL 3.2; spell
 * it out on 3.0/3.1 so the in-test deterministic-RAND provider still builds. */
#ifndef OSSL_DISPATCH_END
# define OSSL_DISPATCH_END { 0, NULL }
#endif

static int tests, passed, failed, skipped;
#define FAIL(...) do { failed++; printf("FAIL: "); printf(__VA_ARGS__); \
    printf("\n"); ERR_print_errors_fp(stdout); } while (0)

static EVP_PKEY *keygen(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *k = NULL;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0)
        EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    return k;
}

/* Common descriptor-param + public-key todata/fromdata/eq round-trip.
 * Returns 1 on success, 0 on hard failure. */
static int common_params(OSSL_LIB_CTX *ctx, EVP_PKEY *k, const char *alg)
{
    OSSL_PARAM *params = NULL;
    EVP_PKEY *copy = NULL;
    EVP_PKEY_CTX *fc = NULL;
    int bits = 0, sec = 0, size = 0, ok = 0;

    if (EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_BITS, &bits) <= 0 || bits <= 0)
        { FAIL("%s: BITS not reported", alg); goto end; }
    if (EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_SECURITY_BITS, &sec) <= 0
            || sec <= 0)
        { FAIL("%s: SECURITY_BITS not reported", alg); goto end; }
    if (EVP_PKEY_get_int_param(k, OSSL_PKEY_PARAM_MAX_SIZE, &size) <= 0
            || size <= 0)
        { FAIL("%s: MAX_SIZE not reported", alg); goto end; }

    /* Export public key to OSSL_PARAMs, re-import, compare. */
    if (EVP_PKEY_todata(k, EVP_PKEY_PUBLIC_KEY, &params) <= 0 || params == NULL)
        { FAIL("%s: todata(PUBLIC) failed", alg); goto end; }
    fc = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &copy, EVP_PKEY_PUBLIC_KEY, params) <= 0
            || copy == NULL)
        { FAIL("%s: fromdata(PUBLIC) failed", alg); goto end; }
    if (EVP_PKEY_eq(k, copy) != 1)
        { FAIL("%s: EVP_PKEY_eq after param round-trip != 1", alg); goto end; }
    ok = 1;
end:
    OSSL_PARAM_free(params);
    EVP_PKEY_free(copy);
    EVP_PKEY_CTX_free(fc);
    return ok;
}

/*
 * ---------------------------------------------------------------------------
 * DRBG threading (issue #44): the probabilistic component operations — keygen,
 * encapsulate, sign — must draw randomness from the DRBG of the provider's OWN
 * library context, not the global default. We prove it with a tiny deterministic
 * RAND provider installed as the DRBG of a private libctx: if a component op
 * genuinely observes that DRBG, the same op run in two independent libctxs that
 * both carry the same deterministic DRBG yields byte-identical output, while the
 * same op under the real (entropic) DRBG yields something different (confirming
 * the op is truly randomized, so the match is not a keygen artefact).
 *
 * The RAND below is a self-contained builtin provider using only public API
 * (mirrors OpenSSL's test/testutil/fake_random.c, minus the internal-header
 * callback hook): a per-instance counter emitted as a deterministic byte stream.
 * ---------------------------------------------------------------------------
 */
typedef struct { int state; unsigned char ctr; } DET_RAND;

static void *det_rand_newctx(void *provctx, void *parent,
                             const OSSL_DISPATCH *parent_disp)
{
    DET_RAND *r = OPENSSL_zalloc(sizeof(*r));

    if (r != NULL)
        r->state = EVP_RAND_STATE_UNINITIALISED;
    return r;
}

static void det_rand_freectx(void *vr) { OPENSSL_free(vr); }

static int det_rand_instantiate(void *vr, unsigned int strength, int pr,
                                const unsigned char *pstr, size_t pstr_len,
                                const OSSL_PARAM params[])
{
    DET_RAND *r = vr;

    r->state = EVP_RAND_STATE_READY;
    r->ctr = 0;                     /* fresh, repeatable stream per instance */
    return 1;
}

static int det_rand_uninstantiate(void *vr)
{
    ((DET_RAND *)vr)->state = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int det_rand_generate(void *vr, unsigned char *out, size_t outlen,
                             unsigned int strength, int pr,
                             const unsigned char *adin, size_t adinlen)
{
    DET_RAND *r = vr;

    while (outlen-- > 0)
        *out++ = r->ctr++;
    return 1;
}

static int det_rand_enable_locking(void *vr) { return 1; }

static int det_rand_get_ctx_params(void *vr, OSSL_PARAM params[])
{
    DET_RAND *r = vr;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE)) != NULL
            && !OSSL_PARAM_set_int(p, r->state))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH)) != NULL
            && !OSSL_PARAM_set_int(p, 256))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST)) != NULL
            && !OSSL_PARAM_set_size_t(p, INT_MAX))
        return 0;
    return 1;
}

static const OSSL_PARAM *det_rand_gettable_ctx_params(void *vr, void *provctx)
{
    static const OSSL_PARAM t[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };
    return t;
}

static const OSSL_DISPATCH det_rand_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))det_rand_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))det_rand_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))det_rand_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))det_rand_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))det_rand_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))det_rand_enable_locking },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))det_rand_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))det_rand_get_ctx_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM det_rand_algs[] = {
    { "DET", "provider=det-rand", det_rand_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *det_rand_query(void *provctx, int op, int *no_cache)
{
    *no_cache = 0;
    return op == OSSL_OP_RAND ? det_rand_algs : NULL;
}

static const OSSL_DISPATCH det_rand_method[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))det_rand_query },
    OSSL_DISPATCH_END
};

static int det_rand_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                         const OSSL_DISPATCH **out, void **provctx)
{
    if ((*provctx = OSSL_LIB_CTX_new()) == NULL)
        return 0;
    *out = det_rand_method;
    return 1;
}

/*
 * A private libctx with default + hybrid loaded. If det != 0 the deterministic
 * RAND above is installed as the DRBG; otherwise the real DRBG is used. The
 * provider handles are retained so they can be unloaded before the libctx is
 * freed — required for a leak-clean teardown under LeakSanitizer (same pattern
 * as hybrid_compctx_test). `ctx == NULL` means setup failed.
 */
typedef struct {
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *provs[3];    /* [det-rand], default, hybrid */
    int n;
} DRBG_ENV;

static DRBG_ENV drbg_env(int det)
{
    DRBG_ENV e;
    const char *mods = getenv("OPENSSL_MODULES");

    memset(&e, 0, sizeof(e));
    if ((e.ctx = OSSL_LIB_CTX_new()) == NULL)
        return e;
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(e.ctx, mods);
    if (det) {
        if (!OSSL_PROVIDER_add_builtin(e.ctx, "det-rand", det_rand_init)
                || !RAND_set_DRBG_type(e.ctx, "DET", NULL, NULL, NULL)
                || (e.provs[e.n] = OSSL_PROVIDER_load(e.ctx, "det-rand"))
                       == NULL)
            goto err;
        e.n++;
    }
    if ((e.provs[e.n] = OSSL_PROVIDER_load(e.ctx, "default")) == NULL)
        goto err;
    e.n++;
    if ((e.provs[e.n] = OSSL_PROVIDER_load(e.ctx, "hybrid")) == NULL)
        goto err;
    e.n++;
    return e;
err:
    while (e.n-- > 0)
        OSSL_PROVIDER_unload(e.provs[e.n]);
    OSSL_LIB_CTX_free(e.ctx);
    e.ctx = NULL;
    return e;
}

static void drbg_env_free(DRBG_ENV *e)
{
    while (e->n-- > 0)
        OSSL_PROVIDER_unload(e->provs[e->n]);
    OSSL_LIB_CTX_free(e->ctx);
}

/* The hybrid's concatenated PUBLIC-key octet, via todata (or NULL). It is a
 * deterministic function of the private key, so it fingerprints a keygen for
 * BOTH families (unlike the private octet, which the keymgmt only exports for
 * raw-key classical components, not EC/RSA). */
static unsigned char *key_pub_bytes(EVP_PKEY *k, size_t *len)
{
    OSSL_PARAM *params = NULL, *p;
    unsigned char *out = NULL;

    if (EVP_PKEY_todata(k, EVP_PKEY_PUBLIC_KEY, &params) > 0
            && (p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        out = OPENSSL_memdup(p->data, p->data_size);
        *len = p->data_size;
    }
    OSSL_PARAM_free(params);
    return out;
}

/* keygen -> the hybrid public-key octet (or NULL if components unavailable). */
static unsigned char *op_keygen(OSSL_LIB_CTX *ctx, const char *alg, size_t *len)
{
    EVP_PKEY *k = keygen(ctx, alg);
    unsigned char *b = (k != NULL) ? key_pub_bytes(k, len) : NULL;

    EVP_PKEY_free(k);
    return b;
}

/* encapsulate to a fixed public key (its encoded bytes, imported into `ctx` so
 * only the encapsulation randomness varies) -> ciphertext (or NULL). */
static unsigned char *op_encaps(OSSL_LIB_CTX *ctx, const char *alg,
                                const unsigned char *pub, size_t publen,
                                size_t *len)
{
    EVP_PKEY_CTX *fc = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *pk = NULL;
    EVP_PKEY_CTX *kc = NULL;
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    OSSL_PARAM pp[2];

    pp[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                              (void *)pub, publen);
    pp[1] = OSSL_PARAM_construct_end();
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &pk, EVP_PKEY_PUBLIC_KEY, pp) <= 0)
        goto end;
    kc = EVP_PKEY_CTX_new_from_pkey(ctx, pk, "provider=hybrid");
    if (kc == NULL || EVP_PKEY_encapsulate_init(kc, NULL) <= 0
            || EVP_PKEY_encapsulate(kc, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL
            || EVP_PKEY_encapsulate(kc, ct, &ctlen, ss, &sslen) <= 0) {
        OPENSSL_free(ct);
        ct = NULL;
    } else {
        *len = ctlen;
    }
end:
    OPENSSL_free(ss);
    EVP_PKEY_CTX_free(fc);
    EVP_PKEY_CTX_free(kc);
    EVP_PKEY_free(pk);
    return ct;
}

/* keygen + sign one fixed message under `ctx` -> signature (or NULL). Both the
 * keygen and the signing draw from ctx's DRBG, so a deterministic DRBG makes the
 * whole chain reproducible; if EITHER op ignored the libctx DRBG, two runs under
 * the same deterministic DRBG would diverge. (Transporting one fixed key instead
 * is not possible here: the keymgmt does not export an EC private octet — see
 * key_pub_bytes.) */
static unsigned char *op_keygen_sign(OSSL_LIB_CTX *ctx, const char *alg,
                                     const unsigned char *msg, size_t msglen,
                                     size_t *len)
{
    EVP_PKEY *pk = keygen(ctx, alg);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char *sig = NULL;
    size_t n = 0;

    if (pk == NULL || m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                     pk, NULL) <= 0
            || EVP_DigestSign(m, NULL, &n, msg, msglen) <= 0
            || (sig = OPENSSL_malloc(n)) == NULL
            || EVP_DigestSign(m, sig, &n, msg, msglen) <= 0) {
        OPENSSL_free(sig);
        sig = NULL;
    } else {
        *len = n;
    }
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(pk);
    return sig;
}

/* Verdict for one probabilistic op run under: det DRBG (a), the same det DRBG in
 * a second libctx (b), and the live DRBG (live). Same det DRBG must reproduce
 * byte-for-byte (the op observed that libctx's DRBG); the live DRBG must differ
 * (the op is genuinely randomized, so the match is not an artefact). */
static void drbg_verdict(const char *alg, const char *what,
                         const unsigned char *a, size_t la,
                         const unsigned char *b, size_t lb,
                         const unsigned char *live, size_t ll)
{
    if (a == NULL || b == NULL || live == NULL)
        FAIL("%s: %s: op failed under a configured DRBG", alg, what);
    else if (la != lb || memcmp(a, b, la) != 0)
        FAIL("%s: %s: same deterministic DRBG gave different output -> op did "
             "not observe the libctx DRBG", alg, what);
    else if (la == ll && memcmp(a, live, la) == 0)
        FAIL("%s: %s: deterministic and live DRBG matched -> op not actually "
             "randomized", alg, what);
    else {
        printf("PASS (det reproduces, live differs)\n");
        passed++;
    }
}

/* First hybrid alg (KEM if is_kem, else SIG) that keygens under default+hybrid;
 * NULL if none (e.g. no PQ components in this build). Returned name is a
 * static-lifetime table pointer. Chooses generically rather than hardcoding, and
 * naturally skips any alg the cede-to-default lever withdraws. */
static const char *first_alg(int is_kem)
{
    DRBG_ENV e = drbg_env(0);
    const char *name = NULL;
    size_t i, n = is_kem ? HYBRID_KEM_ALG_COUNT : HYBRID_SIG_ALG_COUNT;

    for (i = 0; i < n && name == NULL; i++) {
        const char *a = is_kem ? hybrid_kem_table[i].hybrid_name
                               : hybrid_sig_table[i].hybrid_name;
        EVP_PKEY *k = keygen(e.ctx, a);

        if (k != NULL)
            name = a;
        EVP_PKEY_free(k);
        ERR_clear_error();
    }
    drbg_env_free(&e);
    return name;
}

/* keygen (KEM or SIG): identical deterministic DRBG in two independent libctxs
 * must give identical private keys; the live DRBG must give a different one. */
static void check_drbg_keygen(const char *alg)
{
    DRBG_ENV d1 = drbg_env(1), d2 = drbg_env(1), r = drbg_env(0);
    unsigned char *a = NULL, *b = NULL, *live = NULL;
    size_t la = 0, lb = 0, ll = 0;

    printf("  %-24s DRBG keygen ... ", alg);
    fflush(stdout);
    tests++;
    if (d1.ctx == NULL || d2.ctx == NULL || r.ctx == NULL) {
        FAIL("%s: libctx setup failed", alg);
        goto end;
    }
    a = op_keygen(d1.ctx, alg, &la);
    b = op_keygen(d2.ctx, alg, &lb);
    live = op_keygen(r.ctx, alg, &ll);
    drbg_verdict(alg, "keygen", a, la, b, lb, live, ll);
end:
    OPENSSL_free(a); OPENSSL_free(b); OPENSSL_free(live);
    drbg_env_free(&d1); drbg_env_free(&d2); drbg_env_free(&r);
}

/* encapsulate: one fixed public key, encapsulated under each libctx. Same
 * deterministic DRBG -> identical ciphertext; live DRBG -> different. */
static void check_drbg_encaps(const char *alg)
{
    DRBG_ENV gen = drbg_env(0);
    DRBG_ENV d1 = drbg_env(1), d2 = drbg_env(1), r = drbg_env(0);
    EVP_PKEY *base = NULL;
    unsigned char *pub = NULL, *a = NULL, *b = NULL, *live = NULL;
    size_t publen = 0, la = 0, lb = 0, ll = 0;

    printf("  %-24s DRBG encaps ... ", alg);
    fflush(stdout);
    tests++;
    if (gen.ctx == NULL || d1.ctx == NULL || d2.ctx == NULL || r.ctx == NULL) {
        FAIL("%s: libctx setup failed", alg);
        goto end;
    }
    if ((base = keygen(gen.ctx, alg)) == NULL
            || (publen = EVP_PKEY_get1_encoded_public_key(base, &pub)) == 0) {
        FAIL("%s: base key/public export failed", alg);
        goto end;
    }
    a = op_encaps(d1.ctx, alg, pub, publen, &la);
    b = op_encaps(d2.ctx, alg, pub, publen, &lb);
    live = op_encaps(r.ctx, alg, pub, publen, &ll);
    drbg_verdict(alg, "encaps", a, la, b, lb, live, ll);
end:
    OPENSSL_free(pub); OPENSSL_free(a); OPENSSL_free(b); OPENSSL_free(live);
    EVP_PKEY_free(base);
    drbg_env_free(&gen);
    drbg_env_free(&d1); drbg_env_free(&d2); drbg_env_free(&r);
}

/* sign: keygen+sign one fixed message under each libctx. Same deterministic
 * DRBG -> identical signature; live DRBG -> different (ECDSA and ML-DSA both
 * draw per-signature randomness). */
static void check_drbg_sign(const char *alg)
{
    static const unsigned char msg[] = "issue-44 DRBG threading probe";
    DRBG_ENV d1 = drbg_env(1), d2 = drbg_env(1), r = drbg_env(0);
    unsigned char *a = NULL, *b = NULL, *live = NULL;
    size_t la = 0, lb = 0, ll = 0;

    printf("  %-24s DRBG sign ... ", alg);
    fflush(stdout);
    tests++;
    if (d1.ctx == NULL || d2.ctx == NULL || r.ctx == NULL) {
        FAIL("%s: libctx setup failed", alg);
        goto end;
    }
    a = op_keygen_sign(d1.ctx, alg, msg, sizeof(msg), &la);
    b = op_keygen_sign(d2.ctx, alg, msg, sizeof(msg), &lb);
    live = op_keygen_sign(r.ctx, alg, msg, sizeof(msg), &ll);
    drbg_verdict(alg, "sign", a, la, b, lb, live, ll);
end:
    OPENSSL_free(a); OPENSSL_free(b); OPENSSL_free(live);
    drbg_env_free(&d1); drbg_env_free(&d2); drbg_env_free(&r);
}

static void check_kem(OSSL_LIB_CTX *ctx, const HYBRID_KEM_INFO *info)
{
    const char *alg = info->hybrid_name;
    EVP_PKEY *k = NULL;
    unsigned char *enc = NULL;
    size_t enclen, want, a1 = 0, a2 = 0;

    printf("  %-24s KEM params ... ", alg);
    fflush(stdout);
    tests++;
    if ((k = keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        return;
    }
    if (!common_params(ctx, k, alg))
        goto end;

    /* ENCODED_PUBLIC_KEY length must equal the concatenated component pubkeys. */
    enclen = EVP_PKEY_get1_encoded_public_key(k, &enc);
    /* component pub sizes via throwaway single-component keys */
    {
        EVP_PKEY *c1 = EVP_PKEY_Q_keygen(ctx, "provider=hybrid",
                                         info->alg1_group ? "EC" : info->alg1_name,
                                         info->alg1_group);
        EVP_PKEY *c2 = EVP_PKEY_Q_keygen(ctx, NULL, info->alg2_name);
        unsigned char *b1 = NULL, *b2 = NULL;

        if (c1 != NULL)
            a1 = EVP_PKEY_get1_encoded_public_key(c1, &b1);
        if (c2 != NULL)
            EVP_PKEY_get_octet_string_param(c2, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0,
                                            &a2);
        OPENSSL_free(b1); OPENSSL_free(b2);
        EVP_PKEY_free(c1); EVP_PKEY_free(c2);
        ERR_clear_error();
    }
    want = a1 + a2;
    if (enclen == 0)
        FAIL("%s: ENCODED_PUBLIC_KEY empty", alg);
    else if (a1 && a2 && enclen != want)
        FAIL("%s: ENCODED_PUBLIC_KEY %zu != component sum %zu", alg, enclen, want);
    else {
        printf("PASS (bits/sec/size ok, enc=%zu)\n", enclen);
        passed++;
    }
end:
    OPENSSL_free(enc);
    EVP_PKEY_free(k);
}

/* Sign with signer, verify with verifier (both hybrid provider). */
static int sig_ok(OSSL_LIB_CTX *ctx, EVP_PKEY *signer, EVP_PKEY *verifier)
{
    const unsigned char msg[] = "param-reimport functional check";
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ok = 0;

    if (m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                     signer, NULL) <= 0
            || EVP_DigestSign(m, NULL, &siglen, msg, sizeof(msg)) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto end;
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    ok = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                   verifier, NULL) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg)) == 1;
end:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    return ok;
}

static void check_sig(OSSL_LIB_CTX *ctx, const HYBRID_SIG_INFO *info)
{
    const char *alg = info->hybrid_name;
    EVP_PKEY *k = NULL, *copy = NULL;
    EVP_PKEY_CTX *fc = NULL;
    OSSL_PARAM *params = NULL;

    printf("  %-24s SIG params ... ", alg);
    fflush(stdout);
    tests++;
    if ((k = keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        return;
    }
    if (!common_params(ctx, k, alg))
        goto end;

    /* Functional: reimport the public key via params and verify a real sig. */
    if (EVP_PKEY_todata(k, EVP_PKEY_PUBLIC_KEY, &params) <= 0
            || (fc = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid")) == NULL
            || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &copy, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        FAIL("%s: public reimport failed", alg);
        goto end;
    }
    if (!sig_ok(ctx, k, copy)) {
        FAIL("%s: sign(orig)/verify(param-reimported pub) failed", alg);
        goto end;
    }
    printf("PASS (bits/sec/size ok, reimport verifies)\n");
    passed++;
end:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(fc);
    EVP_PKEY_free(copy);
    EVP_PKEY_free(k);
}

/*
 * Item 12: OSSL_FUNC_KEYMGMT_MATCH / EVP_PKEY_eq must be commutative and must
 * compare a PUBLIC-only key against the PRIVATE key of the same pair (libssl
 * validates a cert's public key against a loaded private key this way). The
 * existing round-trip (common_params) compares a keypair against its full copy;
 * this adds the public-vs-private and both-directions checks, plus a distinct-key
 * negative so a trivially-always-equal match would be caught.
 */
static void check_match(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY *priv = NULL, *pub = NULL, *other = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *fc = NULL;

    printf("  %-24s match commutativity ... ", alg);
    fflush(stdout);
    tests++;
    if ((priv = keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        return;
    }

    /* A PUBLIC-only key rebuilt from priv's exported public material. */
    if (EVP_PKEY_todata(priv, EVP_PKEY_PUBLIC_KEY, &params) <= 0
            || (fc = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid")) == NULL
            || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &pub, EVP_PKEY_PUBLIC_KEY, params) <= 0
            || pub == NULL) {
        FAIL("%s: public-only import failed", alg);
        goto end;
    }
    /* An independent keypair for the negative (must-differ) case. */
    if ((other = keygen(ctx, alg)) == NULL) {
        FAIL("%s: second keygen failed", alg);
        goto end;
    }

    /* Public-only vs private of the SAME pair: equal, in both directions. */
    if (EVP_PKEY_eq(priv, pub) != 1 || EVP_PKEY_eq(pub, priv) != 1) {
        FAIL("%s: pub-only vs priv not equal (or not commutative)", alg);
        goto end;
    }
    /* Distinct pairs: not equal, in both directions. */
    if (EVP_PKEY_eq(priv, other) == 1 || EVP_PKEY_eq(other, priv) == 1) {
        FAIL("%s: distinct keys reported equal", alg);
        goto end;
    }
    printf("PASS (pub==priv both ways, distinct differ)\n");
    passed++;
end:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(fc);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(other);
}

/*
 * Item 11: EVP_PKEY_fromdata must reject an empty or invalid selection rather
 * than fabricate a usable key (a built-but-empty key with no material). The
 * existing import tests are all positive-path; this is the negative guard.
 */
static void check_neg_import(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *fc = NULL;
    EVP_PKEY *out = NULL;
    OSSL_PARAM empty[1];
    int bad = 0;

    printf("  %-24s negative import ... ", alg);
    fflush(stdout);
    tests++;
    empty[0] = OSSL_PARAM_construct_end();

    fc = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0) {
        printf("SKIP (fromdata unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto end;
    }

    /* (a) KEYPAIR selection with NO params supplied -> must fail. */
    if (EVP_PKEY_fromdata(fc, &out, EVP_PKEY_KEYPAIR, empty) > 0 && out != NULL)
        bad = 1;
    EVP_PKEY_free(out); out = NULL;
    ERR_clear_error();

    /* (b) empty selection (0) -> must fail. */
    if (EVP_PKEY_fromdata(fc, &out, 0, empty) > 0 && out != NULL)
        bad = 1;
    EVP_PKEY_free(out); out = NULL;
    ERR_clear_error();

    if (bad)
        FAIL("%s: fromdata accepted an empty/invalid selection", alg);
    else {
        printf("PASS (empty/invalid selection rejected)\n");
        passed++;
    }
end:
    EVP_PKEY_CTX_free(fc);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    /* Optional: enables Frodo/BIKE/HQC and the oqs-only sig bases. */
    OSSL_PROVIDER_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("hybrid EVP_PKEY parameter round-trip (full inventory)\n");
    printf("=====================================================\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check_kem(ctx, &hybrid_kem_table[i]);
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        check_sig(ctx, &hybrid_sig_table[i]);

    printf("\nmatch()/EVP_PKEY_eq commutativity + public-vs-private (item 12)\n");
    printf("==============================================================\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check_match(ctx, hybrid_kem_table[i].hybrid_name);
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        check_match(ctx, hybrid_sig_table[i].hybrid_name);

    printf("\nnegative import: empty/invalid selection is rejected (item 11)\n");
    printf("==============================================================\n");
    {
        const char *kem = first_alg(1), *sig = first_alg(0);

        if (kem != NULL)
            check_neg_import(ctx, kem);
        if (sig != NULL)
            check_neg_import(ctx, sig);
        if (kem == NULL && sig == NULL)
            printf("  (no hybrid components available -> skipped)\n");
    }

    /*
     * Issue #44: the probabilistic component operations (keygen/encaps/sign)
     * must draw randomness from the DRBG of the provider's OWN library context,
     * not the global default. Exercised on the first available KEM and signature
     * (chosen generically; skipped if this build has no PQ components).
     */
    {
        const char *kem = first_alg(1), *sig = first_alg(0);

        printf("\nDRBG threading (component ops observe the libctx DRBG)\n");
        printf("=====================================================\n");
        if (kem != NULL) {
            check_drbg_keygen(kem);
            check_drbg_encaps(kem);
        } else {
            printf("  (no hybrid KEM available -> keygen/encaps skipped)\n");
        }
        if (sig != NULL) {
            check_drbg_keygen(sig);
            check_drbg_sign(sig);
        } else {
            printf("  (no hybrid signature available -> sign skipped)\n");
        }
    }

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
