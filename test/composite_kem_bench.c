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
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
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

/*
 * Machine-checked composition-overhead guard for composite KEMs.
 *
 * A composite KEM encapsulation IS one ML-KEM encapsulation + one classical KEM
 * (DHKEM: ephemeral keygen + derive; or RSA-OAEP: encrypt) plus a small combiner
 * glue (the KDF over the concatenated secrets/keys). As with composite signatures
 * there is no native composite peer, so the peer is the SUM OF THE COMPONENTS: we
 * time each component's encaps/decaps standalone and assert the composite stays
 * within a tight multiple of their sum. Because the peer literally IS the two
 * components, any per-component cost (including oqsprovider's no_cache tax)
 * cancels. Keygen is excluded (randomised); only encaps/decaps are asserted.
 */
#define COMPOSITE_OVERHEAD_CEIL   1.6    /* combiner glue only; expected ~1.0x */
#define COMPOSITE_OVERHEAD_MIN_MS 0.010  /* below this, timing noise dominates */

static int g_guard_failures;             /* nonzero -> main() returns failure */

/* Generate a standalone classical component key matching a composite's trad half:
 * EC+group, X25519/X448, or RSA (for RSA-OAEP) + bits. NULL on error. */
static EVP_PKEY *gen_trad_key(OSSL_LIB_CTX *ctx, const COMPOSITE_KEM_INFO *info)
{
    int is_rsa = (strcmp(info->trad_alg, "RSA-OAEP") == 0);
    const char *name = is_rsa ? "RSA" : info->trad_alg;
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    EVP_PKEY *key = NULL;

    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0)
        goto done;
    if (strcmp(info->trad_alg, "EC") == 0 && info->trad_group != NULL) {
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)info->trad_group, 0);
        p[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(gctx, p) <= 0)
            goto done;
    } else if (is_rsa && info->trad_rsa_bits > 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, info->trad_rsa_bits) <= 0)
            goto done;
    }
    if (EVP_PKEY_keygen(gctx, &key) <= 0)
        key = NULL;
done:
    ERR_clear_error();
    EVP_PKEY_CTX_free(gctx);
    return key;
}

/*
 * Minimum single-op latency (ms) for an EVP_PKEY KEM encapsulate. The context is
 * (re)created and initialised INSIDE the loop, per op: the composite internally
 * sets up its two component operations on every encapsulate, and a
 * persistent-context peer would amortise the sub-provider fetch (including
 * oqsprovider's per-op no_cache tax) that the composite pays every time -- making
 * fast oqsprovider-component rows look artificially slow. Per-op setup keeps the
 * comparison symmetric (and mirrors the realistic one-encaps-per-handshake TLS
 * pattern). We take the minimum, not the mean, so scheduler/cache spikes -- which
 * only add time -- don't make the ratio of two small timings flaky (see the sig
 * bench's time_sign for the same reasoning).
 */
static double time_kem_encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq)
{
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    double t0, best = -1.0, r = -1.0;
    int n;

    /* size query (untimed) to allocate reusable output buffers */
    if (ec == NULL || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL)
        goto done;
    EVP_PKEY_CTX_free(ec);
    ec = NULL;
    t0 = now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        size_t cl = ctlen, sl = sslen;
        double a = now_ms(), dt;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
        int ok = c != NULL && EVP_PKEY_encapsulate_init(c, NULL) > 0
                 && EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl) > 0;

        dt = now_ms() - a;
        EVP_PKEY_CTX_free(c);
        if (!ok)
            goto done;
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
            break;
    }
    r = best;
done:
    OPENSSL_free(ct);
    OPENSSL_free(ss);
    EVP_PKEY_CTX_free(ec);
    if (r < 0)
        ERR_clear_error();
    return r;
}

/* Minimum single-op latency (ms) for a KEM decapsulate of a fixed ciphertext;
 * per-op context setup, for the same symmetry reason as time_kem_encaps. */
static double time_kem_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq)
{
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    double t0, best = -1.0, r = -1.0;
    int n;

    if (ec == NULL || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL
            || EVP_PKEY_encapsulate(ec, ct, &ctlen, ss, &sslen) <= 0)
        goto done;
    t0 = now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        size_t sl = sslen;
        double a = now_ms(), dt;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
        int ok = c != NULL && EVP_PKEY_decapsulate_init(c, NULL) > 0
                 && EVP_PKEY_decapsulate(c, ss, &sl, ct, ctlen) > 0;

        dt = now_ms() - a;
        EVP_PKEY_CTX_free(c);
        if (!ok)
            goto done;
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
            break;
    }
    r = best;
done:
    OPENSSL_free(ct);
    OPENSSL_free(ss);
    EVP_PKEY_CTX_free(ec);
    if (r < 0)
        ERR_clear_error();
    return r;
}

/* One DHKEM encapsulation cost: ephemeral keygen + derive to trad_pub. */
static int dh_encaps_once(OSSL_LIB_CTX *ctx, EVP_PKEY *trad_pub)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(ctx, trad_pub, NULL);
    EVP_PKEY_CTX *dctx = NULL;
    EVP_PKEY *eph = NULL;
    unsigned char *s = NULL;
    size_t l = 0;
    int ok = 0;

    if (kctx != NULL && EVP_PKEY_keygen_init(kctx) > 0
            && EVP_PKEY_keygen(kctx, &eph) > 0
            && (dctx = EVP_PKEY_CTX_new_from_pkey(ctx, eph, NULL)) != NULL
            && EVP_PKEY_derive_init(dctx) > 0
            && EVP_PKEY_derive_set_peer(dctx, trad_pub) > 0
            && EVP_PKEY_derive(dctx, NULL, &l) > 0
            && (s = OPENSSL_malloc(l)) != NULL
            && EVP_PKEY_derive(dctx, s, &l) > 0)
        ok = 1;
    OPENSSL_free(s);
    EVP_PKEY_free(eph);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);
    return ok;
}

/* One DHKEM decapsulation cost: derive trad_priv against a fixed peer key. */
static int dh_derive_once(OSSL_LIB_CTX *ctx, EVP_PKEY *priv, EVP_PKEY *peer)
{
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(ctx, priv, NULL);
    unsigned char *s = NULL;
    size_t l = 0;
    int ok = 0;

    if (dctx != NULL && EVP_PKEY_derive_init(dctx) > 0
            && EVP_PKEY_derive_set_peer(dctx, peer) > 0
            && EVP_PKEY_derive(dctx, NULL, &l) > 0
            && (s = OPENSSL_malloc(l)) != NULL
            && EVP_PKEY_derive(dctx, s, &l) > 0)
        ok = 1;
    OPENSSL_free(s);
    EVP_PKEY_CTX_free(dctx);
    return ok;
}

/* Classical KEM component times (encaps + decaps), dispatching DHKEM vs RSA-OAEP.
 * Returns 1 and sets *enc_ms/*dec_ms; 0 on error. */
static int time_trad_kem(OSSL_LIB_CTX *ctx, const COMPOSITE_KEM_INFO *info,
                         EVP_PKEY *trad, double *enc_ms, double *dec_ms)
{
    double t0;
    int n;

    if (strcmp(info->trad_alg, "RSA-OAEP") == 0) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, trad, NULL);
        unsigned char sec[32] = { 0 }, *ct = NULL;
        size_t ctlen = 0;
        double best;
        int ok = 0;

        /* encaps = OAEP encrypt of a random secret; decaps = OAEP decrypt. */
        if (c == NULL || EVP_PKEY_encrypt_init(c) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0
                || EVP_PKEY_encrypt(c, NULL, &ctlen, sec, sizeof(sec)) <= 0
                || (ct = OPENSSL_malloc(ctlen)) == NULL)
            goto rdone;
        t0 = now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            size_t cl = ctlen;
            double a = now_ms(), dt;

            if (EVP_PKEY_encrypt(c, ct, &cl, sec, sizeof(sec)) <= 0)
                goto rdone;
            dt = now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
                break;
        }
        *enc_ms = best;

        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(ctx, trad, NULL);
        if (c == NULL || EVP_PKEY_decrypt_init(c) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0)
            goto rdone;
        t0 = now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            unsigned char out[64];
            size_t ol = sizeof(out);
            double a = now_ms(), dt;

            if (EVP_PKEY_decrypt(c, out, &ol, ct, ctlen) <= 0)
                goto rdone;
            dt = now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
                break;
        }
        *dec_ms = best;
        ok = 1;
rdone:
        OPENSSL_free(ct);
        EVP_PKEY_CTX_free(c);
        if (!ok)
            ERR_clear_error();
        return ok;
    }

    /* DHKEM: encaps = ephemeral keygen + derive; decaps = one derive. Minimum
     * single-op latency, as for the KEM timers (see time_kem_encaps). */
    {
        EVP_PKEY *peer = gen_trad_key(ctx, info);   /* fixed peer for decaps */
        double best;
        int ok = 0;

        if (peer == NULL)
            goto ddone;
        t0 = now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            double a = now_ms(), dt;

            if (!dh_encaps_once(ctx, trad))
                goto ddone;
            dt = now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
                break;
        }
        *enc_ms = best;
        t0 = now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            double a = now_ms(), dt;

            if (!dh_derive_once(ctx, trad, peer))
                goto ddone;
            dt = now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
                break;
        }
        *dec_ms = best;
        ok = 1;
ddone:
        EVP_PKEY_free(peer);
        if (!ok)
            ERR_clear_error();
        return ok;
    }
}

/* Assert one op: composite time within ceiling x the summed-components time. */
static void guard_op(const char *alg, const char *op, double comp, double sum)
{
    if (sum < COMPOSITE_OVERHEAD_MIN_MS)
        return;                            /* too small to time reliably */
    printf("    %-26s %-6s  %8.3f vs sum %8.3f  (%.2fx)\n",
           alg, op, comp, sum, comp / sum);
    if (comp > sum * COMPOSITE_OVERHEAD_CEIL) {
        printf("    !! %s %s composition overhead %.2fx sum-of-components exceeds "
               "%.1fx ceiling\n", alg, op, comp / sum, COMPOSITE_OVERHEAD_CEIL);
        g_guard_failures++;
    }
}

/* Guard one composite KEM: encaps/decaps vs the sum of its two components. */
static void guard_kem(OSSL_LIB_CTX *ctx, const COMPOSITE_KEM_INFO *info)
{
    EVP_PKEY *comp = NULL, *pq = NULL, *trad = NULL;
    double ce, cd, pe, pd, te = 0, td = 0;

    if ((comp = gen_key(ctx, info->name, "provider=hybrid")) == NULL)
        return;                            /* unavailable; bench_one reported it */
    if ((pq = gen_key(ctx, info->pq_alg, NULL)) == NULL
            || (trad = gen_trad_key(ctx, info)) == NULL)
        goto done;

    ce = time_kem_encaps(ctx, comp, "provider=hybrid");
    cd = time_kem_decaps(ctx, comp, "provider=hybrid");
    pe = time_kem_encaps(ctx, pq, NULL);
    pd = time_kem_decaps(ctx, pq, NULL);
    if (ce < 0 || cd < 0 || pe < 0 || pd < 0
            || !time_trad_kem(ctx, info, trad, &te, &td))
        goto done;

    guard_op(info->name, "encaps", ce, pe + te);
    guard_op(info->name, "decaps", cd, pd + td);
done:
    EVP_PKEY_free(comp);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}

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

    /*
     * Composition-overhead guard: composite encaps/decaps vs the sum of its two
     * standalone components (see guard_kem). Available combos only.
     */
    printf("\ncomposition-overhead guard — composite vs sum-of-components "
           "(ceiling %.1fx, keygen excluded)\n", COMPOSITE_OVERHEAD_CEIL);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        guard_kem(ctx, &composite_kem_table[i]);
    if (g_guard_failures == 0)
        printf("  guard: PASS (all measured composites within ceiling)\n");
    else
        printf("  guard: FAIL (%d operation(s) over ceiling)\n", g_guard_failures);

    OSSL_LIB_CTX_free(ctx);
    return g_guard_failures == 0 ? 0 : 1;
}
