/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * M3 acceptance test: cross-provider KEM interop between the hybrid provider
 * and oqsprovider (built from GitHub main) for the OQS-legacy ML-KEM hybrids.
 *
 * These algorithms have no default-provider equivalent, so oqsprovider is the
 * interop peer. Keys are exchanged via the TLS-share ENCODED_PUBLIC_KEY form
 * (raw concatenation, identical in both providers). For each algorithm and each
 * direction we generate a keypair in provider A, hand its encoded public key to
 * provider B, encapsulate in B, decapsulate in A, and require equal secrets.
 *
 * Skipped (not failed) when oqsprovider is not on the module path.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static int tests = 0, passed = 0, failed = 0;

static const char *legacy_kems[] = {
    /* ML-KEM hybrids */
    "x25519_mlkem512", "p256_mlkem512", "bp256_mlkem512",
    "p384_mlkem768",   "x448_mlkem768", "bp384_mlkem768",
    "p521_mlkem1024",  "bp512_mlkem1024",
    /* FrodoKEM hybrids */
    "p256_frodo640aes", "x25519_frodo640aes",
    "p256_frodo640shake", "x25519_frodo640shake",
    "p384_frodo976aes", "x448_frodo976aes",
    "p384_frodo976shake", "x448_frodo976shake",
    "p521_frodo1344aes", "p521_frodo1344shake",
    /* BIKE hybrids */
    "p256_bikel1", "x25519_bikel1", "p384_bikel3", "x448_bikel3", "p521_bikel5",
    /* HQC hybrids */
    "p256_hqc1", "x25519_hqc1", "p384_hqc3", "x448_hqc3", "p521_hqc5",
};

/*
 * Import an encoded (raw-concat) public key into `prop`'s provider.
 *
 * The hybrid provider accepts fromdata(ENCODED_PUBLIC_KEY) directly. oqsprovider
 * only accepts its prefixed PUB_KEY via fromdata, so for it we fall back to the
 * canonical TLS-keyshare path: generate a throwaway key of the algorithm and
 * overwrite its public part via EVP_PKEY_set1_encoded_public_key (encaps uses
 * only the public component).
 */
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

    /* Fallback: temp keygen + set1_encoded_public_key. */
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

/* Generate in provider A, encapsulate in provider B, decapsulate in A. */
static void cross(OSSL_LIB_CTX *ctx, const char *alg,
                  const char *propA, const char *propB, const char *label)
{
    EVP_PKEY_CTX *g = NULL, *e = NULL, *d = NULL;
    EVP_PKEY *kA = NULL, *pubB = NULL;
    unsigned char *enc = NULL, *ct = NULL, *ssB = NULL, *ssA = NULL;
    size_t enclen = 0, ctlen = 0, ssB_len = 0, ssA_len = 0;

    tests++;
    printf("  %-16s %s ... ", alg, label);
    fflush(stdout);

    g = EVP_PKEY_CTX_new_from_name(ctx, alg, propA);
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
        || EVP_PKEY_keygen(g, &kA) <= 0)
        goto fail;

    enclen = EVP_PKEY_get1_encoded_public_key(kA, &enc);
    if (enclen == 0)
        goto fail;

    pubB = import_encoded_pub(ctx, alg, propB, enc, enclen);
    if (pubB == NULL)
        goto fail;

    /* Encapsulate in provider B */
    e = EVP_PKEY_CTX_new_from_pkey(ctx, pubB, propB);
    if (e == NULL || EVP_PKEY_encapsulate_init(e, NULL) <= 0
        || EVP_PKEY_encapsulate(e, NULL, &ctlen, NULL, &ssB_len) <= 0)
        goto fail;
    ct = OPENSSL_malloc(ctlen);
    ssB = OPENSSL_malloc(ssB_len);
    if (ct == NULL || ssB == NULL
        || EVP_PKEY_encapsulate(e, ct, &ctlen, ssB, &ssB_len) <= 0)
        goto fail;

    /* Decapsulate in provider A */
    d = EVP_PKEY_CTX_new_from_pkey(ctx, kA, propA);
    if (d == NULL || EVP_PKEY_decapsulate_init(d, NULL) <= 0
        || EVP_PKEY_decapsulate(d, NULL, &ssA_len, ct, ctlen) <= 0)
        goto fail;
    ssA = OPENSSL_malloc(ssA_len);
    if (ssA == NULL
        || EVP_PKEY_decapsulate(d, ssA, &ssA_len, ct, ctlen) <= 0)
        goto fail;

    if (ssA_len != ssB_len || memcmp(ssA, ssB, ssA_len) != 0) {
        printf("FAIL (shared-secret mismatch, %zu vs %zu)\n", ssA_len, ssB_len);
        failed++;
        goto done;
    }
    printf("PASS\n");
    passed++;
    goto done;

fail:
    printf("FAIL (op error)\n");
    ERR_print_errors_fp(stdout);
    failed++;
done:
    OPENSSL_free(enc);
    OPENSSL_free(ct);
    OPENSSL_free(ssA);
    OPENSSL_free(ssB);
    EVP_PKEY_free(kA);
    EVP_PKEY_free(pubB);
    EVP_PKEY_CTX_free(g);
    EVP_PKEY_CTX_free(e);
    EVP_PKEY_CTX_free(d);
}

/* Hybrid sigs whose PQ base exists only in oqsprovider. */
static const char *oqs_sigs[] = {
    "p256_falcon512", "rsa3072_falcon512", "p521_falcon1024",
    "p256_falconpadded512", "rsa3072_falconpadded512", "p521_falconpadded1024",
    "p256_mayo1", "p256_mayo2", "p384_mayo3", "p521_mayo5",
};

/*
 * Sign/verify self-consistency for a hybrid signature composed by the hybrid
 * provider (PQ base sourced from oqsprovider in the same libctx). Also checks a
 * tampered message is rejected.
 */
static void sig_selfcheck(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const unsigned char msg[] = "hybrid signature interop message";
    unsigned char bad[sizeof(msg)];

    tests++;
    printf("  %-24s sign/verify (base from oqs) ... ", alg);
    fflush(stdout);

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
        || EVP_PKEY_keygen(g, &pkey) <= 0)
        goto fail;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestSignInit_ex(md, NULL, NULL, ctx, "provider=hybrid",
                                 pkey, NULL) <= 0
        || EVP_DigestSign(md, NULL, &siglen, msg, sizeof(msg)) <= 0)
        goto fail;
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(md, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto fail;

    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, "provider=hybrid",
                                   pkey, NULL) <= 0
        || EVP_DigestVerify(md, sig, siglen, msg, sizeof(msg)) != 1)
        goto fail;

    /* tampered message must NOT verify */
    memcpy(bad, msg, sizeof(msg));
    bad[0] ^= 0x01;
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, "provider=hybrid",
                                   pkey, NULL) <= 0
        || EVP_DigestVerify(md, sig, siglen, bad, sizeof(bad)) == 1)
        goto fail;

    printf("PASS\n");
    passed++;
    goto done;
fail:
    printf("FAIL\n");
    ERR_print_errors_fp(stdout);
    failed++;
done:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(g);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i, n = sizeof(legacy_kems) / sizeof(legacy_kems[0]);

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);

    if (OSSL_PROVIDER_load(ctx, "default") == NULL
        || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING cross-provider tests\n");
        printf("(run test/setup_oqs_interop.sh to build the interop peer)\n");
        return 0;
    }

    printf("hybrid <-> oqsprovider KEM interop (OQS-legacy ML-KEM hybrids)\n");
    printf("=============================================================\n");
    for (i = 0; i < n; i++) {
        cross(ctx, legacy_kems[i], "provider=hybrid", "provider=oqsprovider",
              "hybrid-gen / oqs-encaps");
        cross(ctx, legacy_kems[i], "provider=oqsprovider", "provider=hybrid",
              "oqs-gen / hybrid-encaps");
    }
    printf("\nhybrid signatures with oqsprovider PQ base (self-consistency)\n");
    printf("=============================================================\n");
    for (i = 0; i < sizeof(oqs_sigs) / sizeof(oqs_sigs[0]); i++)
        sig_selfcheck(ctx, oqs_sigs[i]);

    printf("\nResults: %d/%d passed, %d failed\n", passed, tests, failed);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
