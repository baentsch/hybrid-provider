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
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

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

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
