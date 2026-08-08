/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite signature certificate benchmark.
 *
 * For every composite in composite_sig_table (standardized ML-DSA combos AND the
 * experimental OQS-family combos) this measures the three quantities that matter
 * for a PKI deployment:
 *
 *   - cert size   : DER length of a self-signed X.509 certificate
 *   - cert-gen    : keypair generation time + X509_sign time (reported separately)
 *   - cert-verify : X509_verify time
 *
 * A short list of single-algorithm references (pure ML-DSA / Ed25519 from the
 * default provider) is included so the composite "tax" is readable. Combos whose
 * components are unavailable on the running provider mix are skipped, not failed
 * (e.g. the experimental tier needs oqsprovider).
 *
 * Each measurement runs until either a per-op time budget or an iteration cap is
 * hit, whichever comes first, so slow keygens (UOV/MQOM/CROSS) don't dominate the
 * wall clock while fast verifies still get enough samples to be stable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "../composite_prov.h"

#define CERT_VALIDITY_SECS (60L * 60 * 24 * 365)

#define KEYGEN_MIN_ITERS 2
#define KEYGEN_MAX_ITERS 50
#define OP_MIN_ITERS     5
#define OP_MAX_ITERS     500

/* Per-op wall-clock budget in ms (overridable via argv[1]); a measurement stops
 * at whichever of MIN_ITERS/budget/MAX_ITERS it reaches last/first respectively. */
static double g_budget_ms = 1000.0;

static double now_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

/* Generate one composite (provider=hybrid) or reference (provider=default) key. */
static EVP_PKEY *gen_key(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(ctx, name, propq);
    EVP_PKEY *key = NULL;

    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &key) <= 0) {
        ERR_clear_error();
        key = NULL;
    }
    EVP_PKEY_CTX_free(gctx);
    return key;
}

/* Build a self-signed (but not yet signed) certificate carrying key's pubkey. */
static X509 *make_cert(OSSL_LIB_CTX *ctx, EVP_PKEY *key)
{
    X509 *cert = X509_new_ex(ctx, NULL);
    X509_NAME *nm;

    if (cert != NULL
            && X509_set_version(cert, X509_VERSION_3)
            && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            && X509_gmtime_adj(X509_getm_notBefore(cert), 0) != NULL
            && X509_gmtime_adj(X509_getm_notAfter(cert), CERT_VALIDITY_SECS) != NULL
            && X509_set_pubkey(cert, key)
            && (nm = X509_get_subject_name(cert)) != NULL
            && X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                          (unsigned char *)"composite", -1, -1, 0)
            && X509_set_issuer_name(cert, nm))
        return cert;
    X509_free(cert);
    return NULL;
}

/*
 * Benchmark one algorithm. Returns 1 on success, 0 on hard error, -1 if the
 * algorithm is unavailable on this provider mix (skipped).
 */
static int bench_one(OSSL_LIB_CTX *ctx, const char *name, const char *tier,
                     const char *propq)
{
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    unsigned char *der = NULL;
    double t0, keygen_ms, sign_ms, verify_ms;
    int n, derlen = 0, ret = 0;

    /* Probe: if the first keygen fails, the components aren't available. */
    if ((key = gen_key(ctx, name, propq)) == NULL) {
        printf("  %-34s %-4s  SKIPPED (component unavailable)\n", name, tier);
        return -1;
    }

    /* keygen */
    t0 = now_ms();
    for (n = 0; n < KEYGEN_MAX_ITERS; n++) {
        EVP_PKEY_free(key);
        if ((key = gen_key(ctx, name, propq)) == NULL)
            goto err;
        if (n + 1 >= KEYGEN_MIN_ITERS && now_ms() - t0 >= g_budget_ms) {
            n++;
            break;
        }
    }
    keygen_ms = (now_ms() - t0) / n;

    if ((cert = make_cert(ctx, key)) == NULL)
        goto err;

    /* sign (cert generation proper) */
    t0 = now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        if (X509_sign(cert, key, NULL) == 0)
            goto err;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms) {
            n++;
            break;
        }
    }
    sign_ms = (now_ms() - t0) / n;

    if ((derlen = i2d_X509(cert, &der)) <= 0)
        goto err;

    /* verify */
    t0 = now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        if (X509_verify(cert, key) != 1)
            goto err;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms) {
            n++;
            break;
        }
    }
    verify_ms = (now_ms() - t0) / n;

    printf("  %-34s %-4s  %9.3f %9.3f %9.3f   %7d\n",
           name, tier, keygen_ms, sign_ms, verify_ms, derlen);
    ret = 1;
err:
    if (ret == 0)
        printf("  %-34s %-4s  ERROR\n", name, tier);
    OPENSSL_free(der);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ret;
}

/* Single-algorithm references that self-sign with a NULL digest (PQ / EdDSA). */
static const struct { const char *name; } refs[] = {
    { "ML-DSA-44" }, { "ML-DSA-65" }, { "ML-DSA-87" }, { "ED25519" },
};

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    size_t i;

    if (argc > 1) {
        double b = atof(argv[1]);

        if (b > 0.0)
            g_budget_ms = b;
    }
    if (ctx == NULL
            || OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "provider load failed\n");
        return 1;
    }
    OSSL_PROVIDER_load(ctx, "oqsprovider");   /* optional: experimental tier */

    printf("composite certificate benchmark — self-signed X.509 (DER)\n");
    printf("  %-34s %-4s  %9s %9s %9s   %7s\n",
           "algorithm", "tier", "keygen", "sign", "verify", "cert");
    printf("  %-34s %-4s  %9s %9s %9s   %7s\n",
           "", "", "(ms)", "(ms)", "(ms)", "(bytes)");

    /*
     * Grouped by NIST security level so the standardized ML-DSA composites sit
     * side-by-side with the experimental OQS-family composites at the same level
     * (security_bits: 128 -> L1, 192 -> L3, 256 -> L5). Within a level the std
     * ML-DSA rows print first, then the experimental rows.
     */
    {
        static const struct { int sb; const char *title; } levels[] = {
            { 128, "--- NIST level 1 (128-bit): ML-DSA-44 vs experimental ---" },
            { 192, "--- NIST level 3 (192-bit): ML-DSA-65 vs experimental ---" },
            { 256, "--- NIST level 5 (256-bit): ML-DSA-87 vs experimental ---" },
        };
        size_t lv;
        int tier;

        for (lv = 0; lv < sizeof(levels) / sizeof(levels[0]); lv++) {
            printf("  %s\n", levels[lv].title);
            for (tier = COMPOSITE_TIER_STANDARD;
                 tier <= COMPOSITE_TIER_EXPERIMENTAL; tier++) {
                for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
                    const COMPOSITE_SIG_INFO *info = &composite_sig_table[i];

                    if (info->security_bits != levels[lv].sb
                            || info->tier != tier)
                        continue;
                    bench_one(ctx, info->name,
                              tier == COMPOSITE_TIER_EXPERIMENTAL ? "exp" : "std",
                              "provider=hybrid");
                }
            }
        }
    }

    printf("  --- reference (single algorithm, default provider) ---\n");
    for (i = 0; i < sizeof(refs) / sizeof(refs[0]); i++)
        bench_one(ctx, refs[i].name, "ref", "provider=default");

    OSSL_LIB_CTX_free(ctx);
    return 0;
}
