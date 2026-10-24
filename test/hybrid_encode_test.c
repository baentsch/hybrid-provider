/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * M2 encoder test: cross-provider public-key (SPKI) + signature interop.
 *
 * For each hybrid signature algorithm: generate a key and sign a message with
 * the hybrid provider, encode the public key as SubjectPublicKeyInfo (DER) via
 * the hybrid provider's encoder, then decode that SPKI with oqsprovider and use
 * the resulting oqsprovider key to verify the hybrid provider's signature.
 *
 * Success proves the SPKI byte format AND the signature wire format both match
 * oqsprovider. Skipped when oqsprovider is unavailable.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include "hybrid_prov.h"   /* HYBRID_SIG_* master table (issue #78) */

static int tests, passed, failed, skipped;

/*
 * Every hybrid signature is exercised (all HYBRID_SIG_LIST rows, across every PQ
 * family and both classical types) — derived from the master table rather than a
 * hand sample (issue #78). The interop peer is oqsprovider; algorithms a given
 * oqsprovider build does not serve are runtime-probed and skipped, not failed.
 */
static int provider_has(OSSL_LIB_CTX *ctx, const char *alg, const char *prop)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, prop);
    int ok = g != NULL && EVP_PKEY_keygen_init(g) > 0;

    ERR_clear_error();
    EVP_PKEY_CTX_free(g);
    return ok;
}

static void check(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = NULL;
    EVP_PKEY *hkey = NULL, *okey = NULL;
    EVP_MD_CTX *md = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    unsigned char *sig = NULL, *spki = NULL;
    size_t siglen = 0, spkilen = 0;
    const unsigned char *p;
    const unsigned char msg[] = "cross-provider SPKI + signature interop";
    const char *stage = "keygen";

    tests++;
    printf("  %-26s hybrid SPKI+sig -> oqs verify ... ", alg);
    fflush(stdout);

    /* keygen + sign with the hybrid provider */
    g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
        || EVP_PKEY_keygen(g, &hkey) <= 0)
        goto fail;
    stage = "sign";
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestSignInit_ex(md, NULL, NULL, ctx, "provider=hybrid",
                                 hkey, NULL) <= 0
        || EVP_DigestSign(md, NULL, &siglen, msg, sizeof(msg)) <= 0)
        goto fail;
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(md, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto fail;

    /* encode the public key as SPKI DER via the hybrid provider */
    stage = "encoder-ctx";
    ectx = OSSL_ENCODER_CTX_new_for_pkey(hkey, EVP_PKEY_PUBLIC_KEY, "DER",
                                         "SubjectPublicKeyInfo",
                                         "provider=hybrid");
    if (ectx == NULL || OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0)
        goto fail;
    stage = "encode";
    if (OSSL_ENCODER_to_data(ectx, &spki, &spkilen) <= 0)
        goto fail;

    /* decode that SPKI with oqsprovider */
    stage = "decode";
    dctx = OSSL_DECODER_CTX_new_for_pkey(&okey, "DER", "SubjectPublicKeyInfo",
                                         NULL, EVP_PKEY_PUBLIC_KEY, ctx,
                                         "provider=oqsprovider");
    p = spki;
    if (dctx == NULL || OSSL_DECODER_from_data(dctx, &p, &spkilen) <= 0
        || okey == NULL)
        goto fail;

    /* verify the hybrid provider's signature with the oqsprovider key */
    stage = "verify";
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, "provider=oqsprovider",
                                   okey, NULL) <= 0
        || EVP_DigestVerify(md, sig, siglen, msg, sizeof(msg)) != 1)
        goto fail;

    printf("PASS\n");
    passed++;
    goto done;
fail:
    printf("FAIL (stage=%s)\n", stage);
    ERR_print_errors_fp(stdout);
    failed++;
done:
    OPENSSL_free(sig);
    OPENSSL_free(spki);
    OSSL_ENCODER_CTX_free(ectx);
    OSSL_DECODER_CTX_free(dctx);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(hkey);
    EVP_PKEY_free(okey);
    EVP_PKEY_CTX_free(g);
}

/* Reverse: oqsprovider signs + writes SPKI; hybrid decodes it and verifies. */
static void check_decode(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = NULL;
    EVP_PKEY *okey = NULL, *hkey = NULL;
    EVP_MD_CTX *md = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    unsigned char *sig = NULL, *spki = NULL;
    size_t siglen = 0, spkilen = 0;
    const unsigned char *p;
    const unsigned char msg[] = "reverse: oqs SPKI decoded by hybrid";
    const char *stage = "keygen";

    tests++;
    printf("  %-26s oqs SPKI+sig -> hybrid verify ... ", alg);
    fflush(stdout);

    g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=oqsprovider");
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
        || EVP_PKEY_keygen(g, &okey) <= 0)
        goto fail;
    stage = "sign";
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestSignInit_ex(md, NULL, NULL, ctx, "provider=oqsprovider",
                                 okey, NULL) <= 0
        || EVP_DigestSign(md, NULL, &siglen, msg, sizeof(msg)) <= 0)
        goto fail;
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(md, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto fail;

    stage = "encode(oqs)";
    ectx = OSSL_ENCODER_CTX_new_for_pkey(okey, EVP_PKEY_PUBLIC_KEY, "DER",
                                         "SubjectPublicKeyInfo",
                                         "provider=oqsprovider");
    if (ectx == NULL || OSSL_ENCODER_to_data(ectx, &spki, &spkilen) <= 0)
        goto fail;

    stage = "decode(hybrid)";
    dctx = OSSL_DECODER_CTX_new_for_pkey(&hkey, "DER", "SubjectPublicKeyInfo",
                                         NULL, EVP_PKEY_PUBLIC_KEY, ctx,
                                         "provider=hybrid");
    p = spki;
    if (dctx == NULL || OSSL_DECODER_from_data(dctx, &p, &spkilen) <= 0
        || hkey == NULL)
        goto fail;

    stage = "verify(hybrid)";
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, "provider=hybrid",
                                   hkey, NULL) <= 0
        || EVP_DigestVerify(md, sig, siglen, msg, sizeof(msg)) != 1)
        goto fail;

    printf("PASS\n");
    passed++;
    goto done;
fail:
    printf("FAIL (stage=%s)\n", stage);
    ERR_print_errors_fp(stdout);
    failed++;
done:
    OPENSSL_free(sig);
    OPENSSL_free(spki);
    OSSL_ENCODER_CTX_free(ectx);
    OSSL_DECODER_CTX_free(dctx);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(okey);
    EVP_PKEY_free(hkey);
    EVP_PKEY_CTX_free(g);
}

/* Encode key's PKCS8 (PrivateKeyInfo, DER) via provider `prop`. */
static int enc_p8(OSSL_LIB_CTX *ctx, EVP_PKEY *pk, const char *prop,
                  unsigned char **der, size_t *derlen)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(
        pk, EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", prop);
    int ok = e != NULL && OSSL_ENCODER_to_data(e, der, derlen) > 0;

    OSSL_ENCODER_CTX_free(e);
    return ok;
}

/* Decode a PKCS8 (PrivateKeyInfo, DER) into an EVP_PKEY via provider `prop`. */
static EVP_PKEY *dec_p8(OSSL_LIB_CTX *ctx, const char *alg, const char *prop,
                        const unsigned char *der, size_t derlen)
{
    EVP_PKEY *pk = NULL;
    OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(
        &pk, "DER", "PrivateKeyInfo", NULL, EVP_PKEY_KEYPAIR, ctx, prop);
    const unsigned char *p = der;

    if (d == NULL || OSSL_DECODER_from_data(d, &p, &derlen) <= 0)
        pk = NULL;
    OSSL_DECODER_CTX_free(d);
    return pk;
}

/* Sign msg with signer (provider sprop), verify with verifier (vprop). */
static int sign_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *signer, const char *sprop,
                       EVP_PKEY *verifier, const char *vprop)
{
    const unsigned char msg[] = "private-key round-trip";
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ok = 0;

    if (md == NULL
        || EVP_DigestSignInit_ex(md, NULL, NULL, ctx, sprop, signer, NULL) <= 0
        || EVP_DigestSign(md, NULL, &siglen, msg, sizeof(msg)) <= 0
        || (sig = OPENSSL_malloc(siglen)) == NULL
        || EVP_DigestSign(md, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto end;
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    ok = md != NULL
        && EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, vprop, verifier,
                                   NULL) > 0
        && EVP_DigestVerify(md, sig, siglen, msg, sizeof(msg)) == 1;
end:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md);
    return ok;
}

/* Private-key PKCS8 round-trip, both directions. */
static void check_priv(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = NULL;
    EVP_PKEY *a = NULL, *b = NULL;
    unsigned char *der = NULL;
    size_t derlen = 0;

    /* Direction A: hybrid private -> oqs (oqs signs, hybrid verifies). */
    tests++;
    printf("  %-26s priv hybrid->oqs (PKCS8) ... ", alg);
    fflush(stdout);
    g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    if (g != NULL && EVP_PKEY_keygen_init(g) > 0 && EVP_PKEY_keygen(g, &a) > 0
        && enc_p8(ctx, a, "provider=hybrid", &der, &derlen)
        && (b = dec_p8(ctx, alg, "provider=oqsprovider", der, derlen)) != NULL
        && sign_verify(ctx, b, "provider=oqsprovider", a, "provider=hybrid")) {
        printf("PASS\n"); passed++;
    } else {
        printf("FAIL\n"); ERR_print_errors_fp(stdout); failed++;
    }
    OPENSSL_free(der); der = NULL; derlen = 0;
    EVP_PKEY_free(a); a = NULL;
    EVP_PKEY_free(b); b = NULL;
    EVP_PKEY_CTX_free(g); g = NULL;

    /* Direction B: oqs private -> hybrid (hybrid signs, oqs verifies). */
    tests++;
    printf("  %-26s priv oqs->hybrid (PKCS8) ... ", alg);
    fflush(stdout);
    g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=oqsprovider");
    if (g != NULL && EVP_PKEY_keygen_init(g) > 0 && EVP_PKEY_keygen(g, &a) > 0
        && enc_p8(ctx, a, "provider=oqsprovider", &der, &derlen)
        && (b = dec_p8(ctx, alg, "provider=hybrid", der, derlen)) != NULL
        && sign_verify(ctx, b, "provider=hybrid", a, "provider=oqsprovider")) {
        printf("PASS\n"); passed++;
    } else {
        printf("FAIL\n"); ERR_print_errors_fp(stdout); failed++;
    }
    OPENSSL_free(der);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    EVP_PKEY_CTX_free(g);
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
        fprintf(stderr, "failed to load default/hybrid\n");
        return 1;
    }
    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING\n");
        return 0;
    }

    printf("hybrid SPKI encode -> oqsprovider decode + verify\n");
    printf("=================================================\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *alg = hybrid_sig_table[i].hybrid_name;

        if (!provider_has(ctx, alg, "provider=oqsprovider")) {
            printf("  %-28s SKIPPED (oqsprovider does not serve it here)\n", alg);
            skipped++;
            continue;
        }
        check(ctx, alg);
        check_decode(ctx, alg);
        check_priv(ctx, alg);
    }
    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
