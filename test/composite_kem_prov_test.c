/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM provider-level test: drive every combo through EVP by
 * name (provider=hybrid), exercising keymgmt + KEM + encoders + decoders as the
 * provider registers them. Per combo:
 *   1. keygen a composite key;
 *   2. encapsulate to it, decapsulate with it, assert the shared secrets match;
 *   3. round-trip the PUBLIC key through the SPKI encoder+decoder, encapsulate to
 *      the decoded key, decapsulate with the original, assert secrets match;
 *   4. round-trip the PRIVATE key through the PKCS#8 encoder+decoder, decapsulate
 *      the step-2 ciphertext with the decoded key, assert it recovers the secret.
 * Needs ML-KEM from the default provider (3.5+); each combo self-skips otherwise.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "composite_kem_prov.h"

static int tests, passed, failed, skipped;

/* Resolve from ANY loaded provider (no provider= restriction): standardized ML-KEM
 * comes from the default provider (3.5+), the experimental Frodo/BIKE/HQC halves
 * from oqsprovider. */
static int have_alg(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

static EVP_PKEY *keygen(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, "provider=hybrid");
    EVP_PKEY *k = NULL;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0)
        EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static int encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *pub,
                  unsigned char **ct, size_t *ctlen,
                  unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, pub, "provider=hybrid");
    int ok = 0;

    if (c != NULL && EVP_PKEY_encapsulate_init(c, NULL) > 0
            && EVP_PKEY_encapsulate(c, NULL, ctlen, NULL, sslen) > 0
            && (*ct = OPENSSL_malloc(*ctlen)) != NULL
            && (*ss = OPENSSL_malloc(*sslen)) != NULL
            && EVP_PKEY_encapsulate(c, *ct, ctlen, *ss, sslen) > 0)
        ok = 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

static int decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *prv,
                  const unsigned char *ct, size_t ctlen,
                  unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, prv, "provider=hybrid");
    int ok = 0;

    if (c != NULL && EVP_PKEY_decapsulate_init(c, NULL) > 0
            && EVP_PKEY_decapsulate(c, NULL, sslen, ct, ctlen) > 0
            && (*ss = OPENSSL_malloc(*sslen)) != NULL
            && EVP_PKEY_decapsulate(c, *ss, sslen, ct, ctlen) > 0)
        ok = 1;
    EVP_PKEY_CTX_free(c);
    return ok;
}

/* Encode pkey to DER (structure = SubjectPublicKeyInfo or PrivateKeyInfo). */
static unsigned char *encode_der(EVP_PKEY *k, int selection,
                                 const char *structure, size_t *len)
{
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(k, selection, "DER",
                                                           structure,
                                                           "provider=hybrid");
    unsigned char *out = NULL;

    if (ectx != NULL)
        OSSL_ENCODER_to_data(ectx, &out, len);
    OSSL_ENCODER_CTX_free(ectx);
    return out;
}

static EVP_PKEY *decode_der(OSSL_LIB_CTX *ctx, const char *name,
                            int selection, const char *structure,
                            const unsigned char *der, size_t derlen)
{
    EVP_PKEY *k = NULL;
    OSSL_DECODER_CTX *dctx =
        OSSL_DECODER_CTX_new_for_pkey(&k, "DER", structure, name, selection,
                                      ctx, "provider=hybrid");
    const unsigned char *p = der;
    size_t l = derlen;

    if (dctx != NULL)
        OSSL_DECODER_from_data(dctx, &p, &l);
    OSSL_DECODER_CTX_free(dctx);
    return k;
}

static void check(OSSL_LIB_CTX *ctx, const COMPOSITE_KEM_INFO *info)
{
    EVP_PKEY *key = NULL, *pub = NULL, *prv = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL, *ss3 = NULL, *ss4 = NULL;
    unsigned char *ct2 = NULL, *spki = NULL, *p8 = NULL;
    size_t ctlen = 0, ct2len = 0, ss1l = 0, ss2l = 0, ss3l = 0, ss4l = 0;
    size_t spkilen = 0, p8len = 0;
    int step = 0;   /* how far we got, for the failure label */

    tests++;
    printf("  %-22s keygen/encaps/decaps + SPKI + PKCS8 ... ", info->name);
    fflush(stdout);

    if (!have_alg(ctx, info->pq_alg)) {
        printf("SKIP (%s unavailable)\n", info->pq_alg);
        skipped++; tests--;
        return;
    }

    /* 1-2. keygen + direct encaps/decaps round-trip. A NULL key here means the
     * composite algorithm is not registered on this build (e.g. a standardized,
     * seed-based combo below 3.5, where that tier is withdrawn) — skip, not fail. */
    if ((key = keygen(ctx, info->name)) == NULL) {
        printf("SKIP (%s not registered here)\n", info->name);
        skipped++; tests--; ERR_clear_error();
        goto done;
    }
    step = 1;
    if (!encaps(ctx, key, &ct, &ctlen, &ss1, &ss1l)) goto fail;
    if (!decaps(ctx, key, ct, ctlen, &ss2, &ss2l)) goto fail;
    if (ss1l != ss2l || memcmp(ss1, ss2, ss1l) != 0) goto fail;
    step = 2;

    /* 3. public SPKI encode -> decode -> encaps -> decaps with original. */
    if ((spki = encode_der(key, EVP_PKEY_PUBLIC_KEY,
                           "SubjectPublicKeyInfo", &spkilen)) == NULL) goto fail;
    if ((pub = decode_der(ctx, info->name, EVP_PKEY_PUBLIC_KEY,
                          "SubjectPublicKeyInfo", spki, spkilen)) == NULL)
        goto fail;
    if (!encaps(ctx, pub, &ct2, &ct2len, &ss3, &ss3l)) goto fail;
    if (!decaps(ctx, key, ct2, ct2len, &ss4, &ss4l)) goto fail;
    if (ss3l != ss4l || memcmp(ss3, ss4, ss3l) != 0) goto fail;
    step = 3;

    /* 4. private PKCS8 encode -> decode -> decapsulate the step-2 ciphertext. */
    if ((p8 = encode_der(key, EVP_PKEY_KEYPAIR, "PrivateKeyInfo",
                         &p8len)) == NULL) goto fail;
    if ((prv = decode_der(ctx, info->name, EVP_PKEY_KEYPAIR,
                          "PrivateKeyInfo", p8, p8len)) == NULL) goto fail;
    OPENSSL_free(ss2); ss2 = NULL; ss2l = 0;
    if (!decaps(ctx, prv, ct, ctlen, &ss2, &ss2l)) goto fail;
    if (ss1l != ss2l || memcmp(ss1, ss2, ss1l) != 0) goto fail;

    printf("PASS\n");
    passed++;
    goto done;
fail:
    printf("FAIL (after step %d)\n", step);
    ERR_print_errors_fp(stdout);
    failed++;
done:
    OPENSSL_free(ct); OPENSSL_free(ct2); OPENSSL_free(spki); OPENSSL_free(p8);
    OPENSSL_clear_free(ss1, ss1l); OPENSSL_clear_free(ss2, ss2l);
    OPENSSL_clear_free(ss3, ss3l); OPENSSL_clear_free(ss4, ss4l);
    EVP_PKEY_free(key); EVP_PKEY_free(pub); EVP_PKEY_free(prv);
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
    OSSL_PROVIDER_load(ctx, "oqsprovider");   /* optional: experimental tier */
    ERR_clear_error();

    printf("composite (LAMPS) ML-KEM provider round-trips\n");
    printf("=============================================\n");
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        check(ctx, &composite_kem_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);
    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
