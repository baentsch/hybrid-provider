/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite KEM benchmark — the KEM analogue of composite_bench (which benchmarks
 * composite signatures over X.509 certificates).
 *
 * For every composite ML-KEM in composite_kem_table (standardized ML-KEM combos
 * AND the experimental Frodo/BIKE/HQC combos) plus a few pure-KEM reference rows,
 * this measures the quantities that matter for a KEM deployment:
 *
 *   - keygen  : keypair generation time
 *   - encaps  : encapsulation time
 *   - decaps  : decapsulation time
 *   - pk      : SubjectPublicKeyInfo DER length (the public key on the wire)
 *   - ct      : composite ciphertext length (travels every handshake)
 *   - sk      : PKCS8 PrivateKeyInfo DER length (stored key material)
 *
 * Rows are grouped by NIST security level so the standardized ML-KEM composites
 * sit side-by-side with the experimental ones. Combos whose components are
 * unavailable on the running provider mix are skipped, not failed (the
 * experimental tier needs oqsprovider). Per-op wall-clock budget via argv[1].
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include "../composite_kem_prov.h"

#define KEYGEN_MIN_ITERS 2
#define KEYGEN_MAX_ITERS 50
#define OP_MIN_ITERS     5
#define OP_MAX_ITERS     500

static double g_budget_ms = 1000.0;

static double now_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

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

/* DER length of the key's SPKI (public) or PKCS8 (private) encoding, or 0. */
static size_t der_len(EVP_PKEY *key, int selection, const char *structure,
                      const char *propq)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(key, selection, "DER",
                                                        structure, propq);
    unsigned char *out = NULL;
    size_t len = 0;

    if (e != NULL)
        OSSL_ENCODER_to_data(e, &out, &len);
    OSSL_ENCODER_CTX_free(e);
    OPENSSL_free(out);
    return len;
}

/*
 * Benchmark one algorithm. Returns 1 on success, -1 if unavailable (skipped).
 */
static int bench_one(OSSL_LIB_CTX *ctx, const char *name, const char *tier,
                     const char *propq)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ec = NULL, *dc = NULL;
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0, pklen, sklen;
    double t0, keygen_ms, encaps_ms, decaps_ms;
    int n, ret = 0;

    if ((key = gen_key(ctx, name, propq)) == NULL) {
        printf("  %-30s %-4s  SKIPPED (component unavailable)\n", name, tier);
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

    pklen = der_len(key, EVP_PKEY_PUBLIC_KEY, "SubjectPublicKeyInfo", propq);
    sklen = der_len(key, EVP_PKEY_KEYPAIR, "PrivateKeyInfo", propq);

    /* size query once to learn ct/ss lengths + allocate reusable buffers */
    if ((ec = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq)) == NULL
            || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL)
        goto err;

    /* encaps */
    t0 = now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        size_t cl = ctlen, sl = sslen;

        if (EVP_PKEY_encapsulate(ec, ct, &cl, ss, &sl) <= 0)
            goto err;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms) {
            n++;
            break;
        }
    }
    encaps_ms = (now_ms() - t0) / n;

    /* decaps (of the last ct) */
    if ((dc = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq)) == NULL
            || EVP_PKEY_decapsulate_init(dc, NULL) <= 0)
        goto err;
    t0 = now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        size_t sl = sslen;

        if (EVP_PKEY_decapsulate(dc, ss, &sl, ct, ctlen) <= 0)
            goto err;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms) {
            n++;
            break;
        }
    }
    decaps_ms = (now_ms() - t0) / n;

    printf("  %-30s %-4s  %9.3f %9.3f %9.3f   %7zu %7zu %7zu\n",
           name, tier, keygen_ms, encaps_ms, decaps_ms, pklen, ctlen, sklen);
    ret = 1;
err:
    if (ret == 0)
        printf("  %-30s %-4s  ERROR\n", name, tier);
    OPENSSL_free(ct);
    OPENSSL_clear_free(ss, sslen);
    EVP_PKEY_CTX_free(ec);
    EVP_PKEY_CTX_free(dc);
    EVP_PKEY_free(key);
    return ret;
}

/* Single-algorithm KEM references (pure ML-KEM from the default provider). */
static const struct { const char *name; } refs[] = {
    { "ML-KEM-768" }, { "ML-KEM-1024" },
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

    printf("composite KEM benchmark — keygen / encaps / decaps + sizes\n");
    printf("  %-30s %-4s  %9s %9s %9s   %7s %7s %7s\n",
           "algorithm", "tier", "keygen", "encaps", "decaps", "pk", "ct", "sk");
    printf("  %-30s %-4s  %9s %9s %9s   %7s %7s %7s\n",
           "", "", "(ms)", "(ms)", "(ms)", "(bytes)", "(bytes)", "(bytes)");

    {
        static const struct { int sb; const char *title; } levels[] = {
            { 128, "--- NIST level 1 (128-bit): experimental only ---" },
            { 192, "--- NIST level 3 (192-bit): ML-KEM-768 vs experimental ---" },
            { 256, "--- NIST level 5 (256-bit): ML-KEM-1024 vs experimental ---" },
        };
        size_t lv;
        int tier;

        for (lv = 0; lv < sizeof(levels) / sizeof(levels[0]); lv++) {
            printf("  %s\n", levels[lv].title);
            for (tier = COMPOSITE_KEM_TIER_STANDARD;
                 tier <= COMPOSITE_KEM_TIER_EXPERIMENTAL; tier++) {
                for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++) {
                    const COMPOSITE_KEM_INFO *info = &composite_kem_table[i];

                    if (info->security_bits != levels[lv].sb || info->tier != tier)
                        continue;
                    bench_one(ctx, info->name,
                              tier == COMPOSITE_KEM_TIER_EXPERIMENTAL ? "exp"
                                                                      : "std",
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
