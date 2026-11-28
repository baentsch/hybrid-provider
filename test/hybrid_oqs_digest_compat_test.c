/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * oqsprovider digest compatibility (HYBRID_CONF_OQS_DIGEST_COMPAT) vs
 * oqsprovider itself.
 *
 * Each provider runs in its own library context, so no fetch can select the
 * other's implementation of the same name:
 *   O   default + oqsprovider
 *   HC  default + oqsprovider (PQ halves it alone serves) + hybrid, compat ON
 *   HD  the same with compat OFF (the default)
 * Keys cross between contexts as SubjectPublicKeyInfo.
 *
 * For every hybrid signature oqsprovider also serves, in both directions:
 *   D  digest-sign naming SHA-256, SHA-384, SHA-512 and SHA3-256: each
 *      provider verifies the other's signature under the same digest, and not
 *      under another digest;
 *   R  raw EVP_PKEY_sign/verify over a 32-byte value: each provider verifies
 *      the other's signature;
 *   M  the message path (no digest) still crosses in compat mode.
 * Compat off (HD) must still refuse a named digest at init and through the
 * digest ctx-param. On OpenSSL 3.4+, HD's raw path must differ from
 * oqsprovider's (what the mode exists for). For rows oqsprovider doesn't
 * serve, HC signs H(m): verifies under the digest, not over m.
 * The lever is switched on by the environment variable (all versions) and, on
 * 3.5+, also by the config key through OSSL_PROVIDER_load_ex.
 *
 * Skipped wholesale when oqsprovider is unavailable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "hybrid_prov.h"
#include "prov_util.h"   /* hybrid_test_load/track, hybrid_test_libctx_free */
#include "key_util.h"    /* hybrid_test_other_digest */

static int tests, passed, failed, skipped;

#define HPROP "provider=hybrid"

static const char *const digests[] = { "SHA256", "SHA384", "SHA512",
                                       "SHA3-256" };
#define N_DIGESTS (sizeof(digests) / sizeof(digests[0]))

static const unsigned char msg[] = "oqsprovider digest compatibility";
static const unsigned char raw_in[32] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
};

/* One side of a cross: a library context and the property query that pins
 * the provider under test there. */
typedef struct {
    OSSL_LIB_CTX *ctx;
    const char *prop;
} SIDE;

typedef enum { COMPAT_OFF, COMPAT_ON } COMPAT;

static OSSL_LIB_CTX *new_side_ctx(const char *mods, int with_hybrid,
                                  COMPAT compat)
{
    OSSL_LIB_CTX *c = OSSL_LIB_CTX_new();

    if (c == NULL)
        return NULL;
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(c, mods);
    if (hybrid_test_load(c, "default") == NULL
            || hybrid_test_load(c, "oqsprovider") == NULL)
        goto err;
    if (with_hybrid) {
        /* The provider reads the lever once, at init. */
        if (compat == COMPAT_ON)
            setenv(HYBRID_ENV_OQS_DIGEST_COMPAT, "1", 1);
        else
            unsetenv(HYBRID_ENV_OQS_DIGEST_COMPAT);
        if (hybrid_test_load(c, "hybrid") == NULL)
            goto err;
        unsetenv(HYBRID_ENV_OQS_DIGEST_COMPAT);
    }
    ERR_clear_error();
    return c;
err:
    hybrid_test_libctx_free(c);
    return NULL;
}

static EVP_PKEY *keygen(const SIDE *s, const char *alg)
{
    EVP_PKEY *k = EVP_PKEY_Q_keygen(s->ctx, s->prop, alg);

    ERR_clear_error();
    return k;
}

/* `k`'s public key, moved into side `to` through its SPKI DER. */
static EVP_PKEY *move_pub(EVP_PKEY *k, const SIDE *from, const SIDE *to)
{
    OSSL_ENCODER_CTX *ec = OSSL_ENCODER_CTX_new_for_pkey(
        k, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", from->prop);
    OSSL_DECODER_CTX *dc = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    size_t len = 0;
    EVP_PKEY *v = NULL;

    if (ec == NULL || OSSL_ENCODER_to_data(ec, &der, &len) <= 0)
        goto end;
    dc = OSSL_DECODER_CTX_new_for_pkey(&v, "DER", "SubjectPublicKeyInfo",
                                       NULL, EVP_PKEY_PUBLIC_KEY, to->ctx,
                                       to->prop);
    p = der;
    if (dc == NULL || OSSL_DECODER_from_data(dc, &p, &len) <= 0) {
        EVP_PKEY_free(v);
        v = NULL;
    }
end:
    OSSL_DECODER_CTX_free(dc);
    OSSL_ENCODER_CTX_free(ec);
    OPENSSL_free(der);
    ERR_clear_error();
    return v;
}

/* Digest-sign `m` under `md` (NULL: none) into a new *sig (size-queried). */
static int md_sign(const SIDE *s, EVP_PKEY *k, const char *md,
                   const unsigned char *m, size_t mlen,
                   unsigned char **sig, size_t *siglen)
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int r = c != NULL
            && EVP_DigestSignInit_ex(c, NULL, md, s->ctx, s->prop, k, NULL) > 0
            && EVP_DigestSign(c, NULL, siglen, m, mlen) > 0
            && (*sig = OPENSSL_malloc(*siglen)) != NULL
            && EVP_DigestSign(c, *sig, siglen, m, mlen) > 0;

    EVP_MD_CTX_free(c);
    ERR_clear_error();
    return r;
}

static int md_verify(const SIDE *s, EVP_PKEY *k, const char *md,
                     const unsigned char *m, size_t mlen,
                     const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int r = c != NULL
            && EVP_DigestVerifyInit_ex(c, NULL, md, s->ctx, s->prop, k,
                                       NULL) > 0
            && EVP_DigestVerify(c, sig, siglen, m, mlen) == 1;

    EVP_MD_CTX_free(c);
    ERR_clear_error();
    return r;
}

static int raw_sign(const SIDE *s, EVP_PKEY *k, unsigned char **sig,
                    size_t *siglen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(s->ctx, k, s->prop);
    int r = c != NULL && EVP_PKEY_sign_init(c) > 0
            && EVP_PKEY_sign(c, NULL, siglen, raw_in, sizeof(raw_in)) > 0
            && (*sig = OPENSSL_malloc(*siglen)) != NULL
            && EVP_PKEY_sign(c, *sig, siglen, raw_in, sizeof(raw_in)) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return r;
}

static int raw_verify(const SIDE *s, EVP_PKEY *k, const unsigned char *sig,
                      size_t siglen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(s->ctx, k, s->prop);
    int r = c != NULL && EVP_PKEY_verify_init(c) > 0
            && EVP_PKEY_verify(c, sig, siglen, raw_in, sizeof(raw_in)) == 1;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return r;
}

typedef enum { PATH_DIGEST, PATH_RAW } PATH;

/*
 * Sign on `s` with a fresh key, verify on `v` with its public key: under `vmd`
 * on the digest path (smd/vmd: the signer's and verifier's digest, NULL for
 * none), or raw. 1 iff it verifies; -1 if the signer failed (a setup error,
 * not a verdict).
 */
static int cross(const char *alg, const SIDE *s, const SIDE *v, PATH path,
                 const char *smd, const char *vmd)
{
    EVP_PKEY *sk = keygen(s, alg), *vk = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int r = -1;

    if (sk == NULL || (vk = move_pub(sk, s, v)) == NULL)
        goto end;
    if (path == PATH_RAW) {
        if (!raw_sign(s, sk, &sig, &siglen))
            goto end;
        r = raw_verify(v, vk, sig, siglen);
    } else {
        if (!md_sign(s, sk, smd, msg, sizeof(msg), &sig, &siglen))
            goto end;
        r = md_verify(v, vk, vmd, msg, sizeof(msg), sig, siglen);
    }
end:
    OPENSSL_free(sig);
    EVP_PKEY_free(sk);
    EVP_PKEY_free(vk);
    return r;
}

#define EXPECT(cond, what)                                                   \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("FAIL: %s\n", what);                                      \
            ERR_print_errors_fp(stdout);                                     \
            ok = 0;                                                          \
            goto end;                                                        \
        }                                                                    \
    } while (0)

/* Rows oqsprovider serves: the full cross, both directions. */
static void check_cross(const char *alg, const SIDE *o, const SIDE *hc,
                        const SIDE *hd)
{
    char what[160];
    size_t i;
    int ok = 1;

    tests++;
    printf("  %-26s hybrid(compat)<->oqsprovider ... ", alg);
    fflush(stdout);

    for (i = 0; i < N_DIGESTS; i++) {
        const char *md = digests[i], *alt = hybrid_test_other_digest(md);

        snprintf(what, sizeof(what), "D: oqs %s sig -> hybrid", md);
        EXPECT(cross(alg, o, hc, PATH_DIGEST, md, md) == 1, what);
        snprintf(what, sizeof(what), "D: hybrid %s sig -> oqs", md);
        EXPECT(cross(alg, hc, o, PATH_DIGEST, md, md) == 1, what);
        snprintf(what, sizeof(what), "D: hybrid %s sig verified under %s",
                 md, alt);
        EXPECT(cross(alg, hc, o, PATH_DIGEST, md, alt) == 0, what);
        snprintf(what, sizeof(what),
                 "D: oqs %s sig verified by hybrid under %s", md, alt);
        EXPECT(cross(alg, o, hc, PATH_DIGEST, md, alt) == 0, what);
    }
    EXPECT(cross(alg, o, hc, PATH_RAW, NULL, NULL) == 1, "R: oqs -> hybrid");
    EXPECT(cross(alg, hc, o, PATH_RAW, NULL, NULL) == 1, "R: hybrid -> oqs");
    EXPECT(cross(alg, o, hc, PATH_DIGEST, NULL, NULL) == 1,
           "M: oqs message sig -> hybrid");
    EXPECT(cross(alg, hc, o, PATH_DIGEST, NULL, NULL) == 1,
           "M: hybrid message sig -> oqs");
    if (OpenSSL_version_num() >= HYBRID_OQS_PREHASHED_RAW_FROM)
        EXPECT(cross(alg, o, hd, PATH_RAW, NULL, NULL) == 0
               && cross(alg, hd, o, PATH_RAW, NULL, NULL) == 0,
               "R: compat off crossed the raw path (the mode would be moot)");
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
}

/* Rows oqsprovider doesn't serve: compat signs H(m), self-consistently. */
static void check_self(const char *alg, const SIDE *hc)
{
    EVP_PKEY *probe = keygen(hc, alg);
    int ok = 1;

    tests++;
    printf("  %-26s hybrid(compat) self, no oqs peer ... ", alg);
    fflush(stdout);
    if (probe == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--;
        return;
    }
    EVP_PKEY_free(probe);
    EXPECT(cross(alg, hc, hc, PATH_DIGEST, "SHA256", "SHA256") == 1,
           "SHA256 sig does not verify under SHA256");
    EXPECT(cross(alg, hc, hc, PATH_DIGEST, "SHA256", NULL) == 0,
           "SHA256 sig verified over the message");
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
}

/* Compat off: a named digest is refused, at init and as the ctx-param. */
static void check_off(const char *alg, const SIDE *hd)
{
    EVP_PKEY *k = keygen(hd, alg);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *c = NULL;
    int ok = 1;

    tests++;
    printf("  %-26s hybrid(default) refuses digests ... ", alg);
    fflush(stdout);
    if (k == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--;
        goto out;
    }
    EXPECT(m != NULL && EVP_DigestSignInit_ex(m, NULL, "SHA256", hd->ctx,
                                              hd->prop, k, NULL) <= 0,
           "digest-sign init accepted SHA256");
    EXPECT((c = EVP_PKEY_CTX_new_from_pkey(hd->ctx, k, hd->prop)) != NULL
           && EVP_PKEY_sign_init(c) > 0, "raw sign init");
    EXPECT(EVP_PKEY_CTX_set_signature_md(c, EVP_sha256()) <= 0,
           "raw set_signature_md accepted SHA256");
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
out:
    ERR_clear_error();
    EVP_PKEY_CTX_free(c);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(k);
}

/* The digest ctx-param is advertised only with the lever on. */
static int settable_digest(const SIDE *s, const char *alg)
{
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(s->ctx, alg, s->prop);
    const OSSL_PARAM *p = sig != NULL
                              ? EVP_SIGNATURE_settable_ctx_params(sig) : NULL;
    int r = p != NULL
            && OSSL_PARAM_locate_const(p, OSSL_SIGNATURE_PARAM_DIGEST) != NULL;

    EVP_SIGNATURE_free(sig);
    ERR_clear_error();
    return r;
}

static void check_lever(const char *mods, const char *alg, const SIDE *hc,
                        const SIDE *hd)
{
    int ok = 1;
#if OPENSSL_VERSION_PREREQ(3, 5)
    OSSL_LIB_CTX *cc = OSSL_LIB_CTX_new();
    OSSL_PARAM params[2];
    SIDE side = { cc, HPROP };
#endif

    tests++;
    printf("  %-26s lever: env var%s ... ", alg,
#if OPENSSL_VERSION_PREREQ(3, 5)
           " + config key"
#else
           ""
#endif
           );
    fflush(stdout);
    EXPECT(settable_digest(hc, alg), "env var on: digest not settable");
    EXPECT(!settable_digest(hd, alg), "lever off: digest settable");
#if OPENSSL_VERSION_PREREQ(3, 5)
    params[0] = OSSL_PARAM_construct_utf8_string(
                    HYBRID_CONF_OQS_DIGEST_COMPAT, (char *)"yes", 0);
    params[1] = OSSL_PARAM_construct_end();
    unsetenv(HYBRID_ENV_OQS_DIGEST_COMPAT);
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(cc, mods);
    EXPECT(hybrid_test_load(cc, "default") != NULL
           && hybrid_test_load(cc, "oqsprovider") != NULL
           && hybrid_test_track(cc, OSSL_PROVIDER_load_ex(cc, "hybrid",
                                                          params)) != NULL,
           "load_ex with the config key");
    EXPECT(settable_digest(&side, alg), "config key on: digest not settable");
    EXPECT(cross(alg, &side, &side, PATH_DIGEST, "SHA256", "SHA256") == 1,
           "config key on: SHA256 digest-sign");
#else
    (void)mods;
#endif
end:
#if OPENSSL_VERSION_PREREQ(3, 5)
    hybrid_test_libctx_free(cc);
#endif
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
}

int main(void)
{
    const char *mods = getenv("OPENSSL_MODULES");
    OSSL_LIB_CTX *octx, *hcctx = NULL, *hdctx = NULL;
    SIDE o, hc, hd;
    const char *lever_alg = NULL;
    size_t i;

    if ((octx = new_side_ctx(mods, 0, COMPAT_OFF)) == NULL) {
        printf("oqsprovider unavailable -- SKIPPING digest-compat interop\n");
        return 0;
    }
    if ((hcctx = new_side_ctx(mods, 1, COMPAT_ON)) == NULL
            || (hdctx = new_side_ctx(mods, 1, COMPAT_OFF)) == NULL) {
        fprintf(stderr, "failed to load the hybrid provider\n");
        ERR_print_errors_fp(stderr);
        hybrid_test_libctx_free(octx);
        hybrid_test_libctx_free(hcctx);
        return 1;
    }
    o = (SIDE){ octx, NULL };
    hc = (SIDE){ hcctx, HPROP };
    hd = (SIDE){ hdctx, HPROP };

    printf("oqsprovider digest compatibility (%zu hybrid signatures)\n",
           (size_t)HYBRID_SIG_ALG_COUNT);
    printf("======================================================\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *alg = hybrid_sig_table[i].hybrid_name;
        EVP_PKEY *probe = keygen(&o, alg);

        if (probe != NULL) {
            check_cross(alg, &o, &hc, &hd);
            if (lever_alg == NULL)
                lever_alg = alg;
        } else {
            check_self(alg, &hc);
        }
        EVP_PKEY_free(probe);
        check_off(alg, &hd);
    }
    if (lever_alg != NULL)
        check_lever(mods, lever_alg, &hc, &hd);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);
    hybrid_test_libctx_free(octx);
    hybrid_test_libctx_free(hcctx);
    hybrid_test_libctx_free(hdctx);
    return failed == 0 ? 0 : 1;
}
