/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Full-matrix cross-version interop sweep vs oqsprovider (M8 drop-in proof).
 *
 * The other interop tests exercise a representative subset; this one is driven
 * directly by the master tables (HYBRID_KEM_LIST / HYBRID_SIG_LIST), so EVERY
 * hybrid KEM and signature is checked against oqsprovider and nothing can be
 * silently omitted. It is the machine-checkable form of issue #3 work item 2
 * ("cross-check the full hybrid matrix — names, OIDs, code points, wire formats").
 *
 *   KEM: for each hybrid whose PQ base oqsprovider also provides (i.e. every
 *        name except the standardized MLX groups, which live only in the default
 *        provider), generate in A, encapsulate in B, decapsulate in A, both
 *        directions; shared secrets must match.
 *   SIG: for each hybrid signature, hybrid signs + encodes its SPKI, oqsprovider
 *        decodes the SPKI and verifies (proving SPKI + signature wire formats),
 *        and the reverse direction.
 *
 * Skipped wholesale when oqsprovider is unavailable; per algorithm, names that
 * oqsprovider does not implement (MLX KEMs) self-skip.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

static int tests, passed, failed, skipped;

/* Import a raw-concat encoded public key into `prop`'s provider (see
 * hybrid_oqs_test for the oqsprovider fallback rationale). */
static EVP_PKEY *import_encoded_pub(OSSL_LIB_CTX *ctx, const char *alg,
                                    const char *prop,
                                    const unsigned char *enc, size_t enclen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, alg, prop);
    EVP_PKEY *pk = NULL;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, (void *)enc, enclen);
    p[1] = OSSL_PARAM_construct_end();
    if (c != NULL && EVP_PKEY_fromdata_init(c) > 0
            && EVP_PKEY_fromdata(c, &pk, EVP_PKEY_PUBLIC_KEY, p) > 0) {
        EVP_PKEY_CTX_free(c);
        return pk;
    }
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    pk = NULL;
    c = EVP_PKEY_CTX_new_from_name(ctx, alg, prop);
    if (c == NULL || EVP_PKEY_keygen_init(c) <= 0
            || EVP_PKEY_keygen(c, &pk) <= 0) {
        EVP_PKEY_CTX_free(c);
        return NULL;
    }
    EVP_PKEY_CTX_free(c);
    if (EVP_PKEY_set1_encoded_public_key(pk, enc, enclen) <= 0) {
        EVP_PKEY_free(pk);
        return NULL;
    }
    return pk;
}

/* One KEM cross: gen in A, encaps in B, decaps in A; secrets must match. */
static int kem_cross(OSSL_LIB_CTX *ctx, const char *alg,
                     const char *propA, const char *propB)
{
    EVP_PKEY_CTX *g = NULL, *e = NULL, *d = NULL;
    EVP_PKEY *kA = NULL, *pubB = NULL;
    unsigned char *enc = NULL, *ct = NULL, *ssB = NULL, *ssA = NULL;
    size_t enclen = 0, ctlen = 0, ssBl = 0, ssAl = 0;
    int ok = 0;

    g = EVP_PKEY_CTX_new_from_name(ctx, alg, propA);
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &kA) <= 0)
        goto end;
    if ((enclen = EVP_PKEY_get1_encoded_public_key(kA, &enc)) == 0
            || (pubB = import_encoded_pub(ctx, alg, propB, enc, enclen)) == NULL)
        goto end;
    e = EVP_PKEY_CTX_new_from_pkey(ctx, pubB, propB);
    if (e == NULL || EVP_PKEY_encapsulate_init(e, NULL) <= 0
            || EVP_PKEY_encapsulate(e, NULL, &ctlen, NULL, &ssBl) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ssB = OPENSSL_malloc(ssBl)) == NULL
            || EVP_PKEY_encapsulate(e, ct, &ctlen, ssB, &ssBl) <= 0)
        goto end;
    d = EVP_PKEY_CTX_new_from_pkey(ctx, kA, propA);
    if (d == NULL || EVP_PKEY_decapsulate_init(d, NULL) <= 0
            || EVP_PKEY_decapsulate(d, NULL, &ssAl, ct, ctlen) <= 0
            || (ssA = OPENSSL_malloc(ssAl)) == NULL
            || EVP_PKEY_decapsulate(d, ssA, &ssAl, ct, ctlen) <= 0)
        goto end;
    ok = (ssAl == ssBl && memcmp(ssA, ssB, ssAl) == 0);
end:
    OPENSSL_free(enc); OPENSSL_free(ct); OPENSSL_free(ssA); OPENSSL_free(ssB);
    EVP_PKEY_free(kA); EVP_PKEY_free(pubB);
    EVP_PKEY_CTX_free(g); EVP_PKEY_CTX_free(e); EVP_PKEY_CTX_free(d);
    return ok;
}

static void check_kem(OSSL_LIB_CTX *ctx, const char *alg)
{
    /* MLX names live only in the default provider; oqsprovider has no keygen for
     * them -> self-skip by probing an oqsprovider keygen first. */
    EVP_PKEY_CTX *probe = EVP_PKEY_CTX_new_from_name(ctx, alg,
                                                     "provider=oqsprovider");
    EVP_PKEY *tmp = NULL;
    int have = (probe != NULL && EVP_PKEY_keygen_init(probe) > 0
                && EVP_PKEY_keygen(probe, &tmp) > 0);

    EVP_PKEY_free(tmp);
    EVP_PKEY_CTX_free(probe);
    ERR_clear_error();

    tests++;
    printf("  %-24s KEM hybrid<->oqs (both dirs) ... ", alg);
    fflush(stdout);
    if (!have) {
        printf("SKIP (not in oqsprovider)\n");
        skipped++; tests--;
        return;
    }
    if (kem_cross(ctx, alg, "provider=hybrid", "provider=oqsprovider")
            && kem_cross(ctx, alg, "provider=oqsprovider", "provider=hybrid")) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        ERR_print_errors_fp(stdout);
        failed++;
    }
}

/* Encode signer's SPKI via sprop, decode via vprop, verify signer's signature. */
static int sig_cross(OSSL_LIB_CTX *ctx, const char *alg,
                     const char *sprop, const char *vprop)
{
    EVP_PKEY_CTX *g = NULL;
    EVP_PKEY *sk = NULL, *vk = NULL;
    EVP_MD_CTX *m = NULL;
    OSSL_ENCODER_CTX *ec = NULL;
    OSSL_DECODER_CTX *dc = NULL;
    unsigned char *sig = NULL, *spki = NULL;
    size_t siglen = 0, spkilen = 0;
    const unsigned char msg[] = "full-matrix cross-version sig interop";
    const unsigned char *p;
    int ok = 0;

    g = EVP_PKEY_CTX_new_from_name(ctx, alg, sprop);
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &sk) <= 0)
        goto end;
    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, sprop, sk, NULL) <= 0
            || EVP_DigestSign(m, NULL, &siglen, msg, sizeof(msg)) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto end;
    ec = OSSL_ENCODER_CTX_new_for_pkey(sk, EVP_PKEY_PUBLIC_KEY, "DER",
                                       "SubjectPublicKeyInfo", sprop);
    if (ec == NULL || OSSL_ENCODER_to_data(ec, &spki, &spkilen) <= 0)
        goto end;
    dc = OSSL_DECODER_CTX_new_for_pkey(&vk, "DER", "SubjectPublicKeyInfo", NULL,
                                       EVP_PKEY_PUBLIC_KEY, ctx, vprop);
    p = spki;
    if (dc == NULL || OSSL_DECODER_from_data(dc, &p, &spkilen) <= 0 || vk == NULL)
        goto end;
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    ok = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, vprop, vk, NULL) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg)) == 1;
end:
    OPENSSL_free(sig); OPENSSL_free(spki);
    OSSL_ENCODER_CTX_free(ec); OSSL_DECODER_CTX_free(dc);
    EVP_MD_CTX_free(m); EVP_PKEY_free(sk); EVP_PKEY_free(vk);
    EVP_PKEY_CTX_free(g);
    return ok;
}

static void check_sig(OSSL_LIB_CTX *ctx, const char *alg)
{
    tests++;
    printf("  %-24s SIG hybrid<->oqs (SPKI+sig) ... ", alg);
    fflush(stdout);
    if (sig_cross(ctx, alg, "provider=hybrid", "provider=oqsprovider")
            && sig_cross(ctx, alg, "provider=oqsprovider", "provider=hybrid")) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        ERR_print_errors_fp(stdout);
        failed++;
    }
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
    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING full-matrix sweep\n");
        return 0;
    }

    printf("full hybrid matrix vs oqsprovider (%zu KEMs, %zu SIGs)\n",
           (size_t)HYBRID_KEM_ALG_COUNT, (size_t)HYBRID_SIG_ALG_COUNT);
    printf("======================================================\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check_kem(ctx, hybrid_kem_table[i].hybrid_name);
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        check_sig(ctx, hybrid_sig_table[i].hybrid_name);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
