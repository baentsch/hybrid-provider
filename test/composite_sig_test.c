/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) combiner self-consistency test (issue #6, first slice).
 *
 * Exercises composite_sign()/composite_verify() directly with EVP-generated
 * component keys — no provider registration yet. For each combo in the master
 * table it generates the PQ + classical components (from the default provider,
 * or oqsprovider for the experimental tier), signs a message, verifies it (must
 * pass), then tampers a byte and verifies again (must fail). Combos whose
 * components are unavailable (e.g. ML-DSA on 3.4, or mayo2 without oqsprovider)
 * self-skip.
 *
 * This proves the combiner plumbing + component delegation; it does NOT prove
 * wire-format interop (that needs Bouncy Castle / OpenSSL-native as a peer).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "composite_prov.h"

static int tests, passed, failed, skipped;

static EVP_PKEY *keygen_pq(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info,
                           const char *propq)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, info->pq_alg, propq);
    EVP_PKEY *k = NULL;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0)
        EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static EVP_PKEY *keygen_trad(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const char *p = "provider=default";

    if (strcmp(info->trad_alg, "EC") == 0)
        return EVP_PKEY_Q_keygen(ctx, p, "EC", info->trad_group);
    if (strcmp(info->trad_alg, "ED25519") == 0
            || strcmp(info->trad_alg, "ED448") == 0)
        return EVP_PKEY_Q_keygen(ctx, p, info->trad_alg);
    /* RSA / RSA-PSS: a plain 3072-bit RSA key, PSS applied at signing time. */
    return EVP_PKEY_Q_keygen(ctx, p, "RSA", (size_t)3072);
}

static void check(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const char *pqprop = info->tier == COMPOSITE_TIER_EXPERIMENTAL
                             ? "provider=oqsprovider" : "provider=default";
    const unsigned char msg[] = "composite LAMPS combiner self-consistency";
    EVP_PKEY *pq = NULL, *trad = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    tests++;
    printf("  %-22s %s ... ", info->name,
           info->tier == COMPOSITE_TIER_EXPERIMENTAL ? "(exp)" : "(std)");
    fflush(stdout);

    if ((pq = keygen_pq(ctx, info, pqprop)) == NULL
            || (trad = keygen_trad(ctx, info)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }
    if (!composite_sign(info, pq, trad, ctx, pqprop, "provider=default",
                        msg, sizeof(msg) - 1, &sig, &siglen)) {
        printf("FAIL (sign)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (!composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                          msg, sizeof(msg) - 1, sig, siglen)) {
        printf("FAIL (verify good)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    /* Tamper the last byte (in the traditional component) — must reject. */
    sig[siglen - 1] ^= 0x01;
    if (composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                         msg, sizeof(msg) - 1, sig, siglen)) {
        printf("FAIL (tampered signature verified)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();
    printf("PASS (sig=%zu)\n", siglen);
    passed++;
done:
    OPENSSL_free(sig);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL) {
        fprintf(stderr, "failed to load default provider\n");
        return 1;
    }
    OSSL_PROVIDER_load(ctx, "oqsprovider");   /* optional: experimental tier */
    ERR_clear_error();

    printf("composite (LAMPS) combiner self-consistency\n");
    printf("===========================================\n");
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check(ctx, &composite_sig_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
