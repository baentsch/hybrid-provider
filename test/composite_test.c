/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) provider test (issue #6): drive the composite provider
 * through the public EVP API by name — keygen, one-shot EVP_DigestSign /
 * EVP_DigestVerify, and a tamper check — for every row in the master table.
 * Standardized ML-DSA combos need only the default provider; the experimental
 * tier needs oqsprovider; each combo self-skips when its components are absent.
 *
 * Proves the provider wiring (keymgmt + signature dispatch + registration). Wire-
 * format interop is a separate, external matter (Bouncy Castle / OpenSSL-native).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "composite_prov.h"

static int tests, passed, failed, skipped;

static void check(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const unsigned char msg[] = "composite provider EVP round-trip";
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *m = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    tests++;
    printf("  %-22s %s ... ", info->name,
           info->tier == COMPOSITE_TIER_EXPERIMENTAL ? "(exp)" : "(std)");
    fflush(stdout);

    gctx = EVP_PKEY_CTX_new_from_name(ctx, info->name, "provider=composite");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &key) <= 0) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, "provider=composite",
                                     key, NULL) <= 0
            || EVP_DigestSign(m, NULL, &siglen, msg, sizeof(msg) - 1) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg) - 1) <= 0) {
        printf("FAIL (sign)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=composite",
                                       key, NULL) <= 0
            || EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg) - 1) != 1) {
        printf("FAIL (verify)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }

    sig[siglen - 1] ^= 0x01;
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    if (m != NULL
            && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=composite",
                                       key, NULL) > 0
            && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg) - 1) == 1) {
        printf("FAIL (tampered signature verified)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();
    printf("PASS (sig=%zu)\n", siglen);
    passed++;
done:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gctx);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "composite") == NULL) {
        fprintf(stderr, "failed to load default/composite providers\n");
        return 1;
    }
    OSSL_PROVIDER_load(ctx, "oqsprovider");   /* optional: experimental tier */
    ERR_clear_error();

    printf("composite (LAMPS) provider — keygen + sign/verify via EVP\n");
    printf("=========================================================\n");
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check(ctx, &composite_sig_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
