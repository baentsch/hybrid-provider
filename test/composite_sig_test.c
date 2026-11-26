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
 * pass), then tampers a byte and verifies again (must fail). A signature made
 * under a context string verifies only under that same context string (it is
 * bound into M'), and an over-long one is refused. Combos whose
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
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */

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
    /* RSA / RSA-PSS: a plain RSA key, PSS applied at signing time. */
    return EVP_PKEY_Q_keygen(ctx, p, "RSA", (size_t)COMPOSITE_RSA_TRAD_BITS);
}

static void check(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const char *pqprop = info->tier == COMPOSITE_TIER_EXPERIMENTAL
                             ? "provider=oqsprovider" : "provider=default";
    const unsigned char msg[] = "composite LAMPS combiner self-consistency";
    const unsigned char ctxa[] = { 'A' }, ctxb[] = { 'B' };
    unsigned char longctx[COMPOSITE_SIG_CTX_MAX + 1] = { 0 };
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
                        msg, sizeof(msg) - 1, NULL, 0, &sig, &siglen)) {
        printf("FAIL (sign)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (!composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                          msg, sizeof(msg) - 1, NULL, 0, sig, siglen)) {
        printf("FAIL (verify good)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    /* Tamper the last byte (in the traditional component) — must reject. */
    sig[siglen - 1] ^= 0x01;
    if (composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                         msg, sizeof(msg) - 1, NULL, 0, sig, siglen)) {
        printf("FAIL (tampered signature verified)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();

    /* Context string: bound into M', so only the same one verifies. */
    OPENSSL_free(sig);
    sig = NULL;
    if (!composite_sign(info, pq, trad, ctx, pqprop, "provider=default",
                        msg, sizeof(msg) - 1, ctxa, sizeof(ctxa), &sig, &siglen)
            || !composite_verify(info, pq, trad, ctx, pqprop,
                                 "provider=default", msg, sizeof(msg) - 1,
                                 ctxa, sizeof(ctxa), sig, siglen)) {
        printf("FAIL (sign/verify under a context string)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                         msg, sizeof(msg) - 1, ctxb, sizeof(ctxb), sig, siglen)
            || composite_verify(info, pq, trad, ctx, pqprop,
                                "provider=default", msg, sizeof(msg) - 1,
                                NULL, 0, sig, siglen)) {
        printf("FAIL (verified under a different context string)\n");
        failed++;
        goto done;
    }
    OPENSSL_free(sig);
    sig = NULL;
    if (composite_sign(info, pq, trad, ctx, pqprop, "provider=default",
                       msg, sizeof(msg) - 1, longctx, sizeof(longctx),
                       &sig, &siglen)) {
        printf("FAIL (over-long context string accepted)\n");
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
    if (hybrid_test_load(ctx, "default") == NULL) {
        fprintf(stderr, "failed to load default provider\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    hybrid_test_load(ctx, "oqsprovider");   /* optional: experimental tier */
    ERR_clear_error();

    printf("composite (LAMPS) combiner self-consistency\n");
    printf("===========================================\n");
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check(ctx, &composite_sig_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
