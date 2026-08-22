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
 *   - sk size     : DER length of the PKCS8 private key (PrivateKeyInfo)
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
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
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
    unsigned char *der = NULL, *skder = NULL;
    double t0, keygen_ms, sign_ms, verify_ms;
    int n, derlen = 0, sklen = 0, ret = 0;

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

    /* private-key size: DER length of the PKCS8 PrivateKeyInfo */
    if ((sklen = i2d_PrivateKey(key, &skder)) <= 0)
        goto err;

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

    printf("  %-34s %-4s  %9.3f %9.3f %9.3f   %7d %7d\n",
           name, tier, keygen_ms, sign_ms, verify_ms, derlen, sklen);
    ret = 1;
err:
    if (ret == 0)
        printf("  %-34s %-4s  ERROR\n", name, tier);
    OPENSSL_free(skder);
    OPENSSL_free(der);
    X509_free(cert);
    EVP_PKEY_free(key);
    return ret;
}

/* Single-algorithm references that self-sign with a NULL digest (PQ / EdDSA). */
static const struct { const char *name; } refs[] = {
    { "ML-DSA-44" }, { "ML-DSA-65" }, { "ML-DSA-87" }, { "ED25519" },
};

/*
 * Machine-checked composition-overhead guard for composite signatures.
 *
 * A composite signature IS one PQ signature + one classical signature over the
 * same prehashed message, plus a small additive glue (the M' prehash and the
 * component-signature concatenation). Unlike the hybrid family there is no native
 * composite peer to ratio against, so the peer is the SUM OF THE COMPONENTS: we
 * time a standalone sign/verify of each component and assert the composite stays
 * within a tight multiple of their sum. Because the peer literally IS the two
 * components, any per-component cost (including oqsprovider's no_cache tax) cancels
 * in the ratio -- what remains is the combiner's own overhead. Keygen is excluded
 * for the same reason as hybrid_bench (randomised, heavy-tailed); only the
 * repeatable sign/verify ops are asserted.
 */
#define COMPOSITE_OVERHEAD_CEIL   1.6    /* combiner glue only; expected ~1.0x */
#define COMPOSITE_OVERHEAD_MIN_MS 0.010  /* below this, timing noise dominates */

static int g_guard_failures;             /* nonzero -> main() returns failure */

/* Generate a standalone classical component key matching a composite's trad half
 * (EC+group, RSA/RSA-PSS+bits, or pure Ed). NULL on unavailable/error. */
static EVP_PKEY *gen_trad_key(OSSL_LIB_CTX *ctx, const char *alg,
                              const char *group, int rsa_bits)
{
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(ctx, alg, NULL);
    EVP_PKEY *key = NULL;

    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0)
        goto done;
    if (strcmp(alg, "EC") == 0 && group != NULL) {
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)group, 0);
        p[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(gctx, p) <= 0)
            goto done;
    } else if (strncmp(alg, "RSA", 3) == 0 && rsa_bits > 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, rsa_bits) <= 0)
            goto done;
    }
    if (EVP_PKEY_keygen(gctx, &key) <= 0)
        key = NULL;
done:
    ERR_clear_error();
    EVP_PKEY_CTX_free(gctx);
    return key;
}

#define GUARD_MSG_LEN 32
static const unsigned char guard_msg[GUARD_MSG_LEN] = { 0 };  /* content irrelevant */

/* One raw signature over guard_msg into *sig (caller frees). md may be NULL. */
static int do_sign(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                   unsigned char **sig, size_t *siglen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char *s = NULL;
    size_t l = 0;
    int ret = 0;

    if (m != NULL
            && EVP_DigestSignInit_ex(m, NULL, md, ctx, NULL, key, NULL) > 0
            && EVP_DigestSign(m, NULL, &l, guard_msg, GUARD_MSG_LEN) > 0
            && (s = OPENSSL_malloc(l)) != NULL
            && EVP_DigestSign(m, s, &l, guard_msg, GUARD_MSG_LEN) > 0) {
        *sig = s; *siglen = l; s = NULL; ret = 1;
    }
    OPENSSL_free(s);
    EVP_MD_CTX_free(m);
    if (!ret)
        ERR_clear_error();
    return ret;
}

/*
 * Minimum single-op latency (ms) over a budget-bounded run. We take the MIN, not
 * the mean: scheduler preemption and cache blips only ever ADD time, so the
 * fastest observed op is the cleanest estimate of the true compute cost.
 * Deterministic combiner overhead is present in every op (including the fastest),
 * so a real regression still shows; transient spikes -- which otherwise make the
 * ratio of two small timings flaky at the short ctest budget -- are filtered out.
 * -1.0 on error.
 */
static double time_sign(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md)
{
    double t0 = now_ms(), best = -1.0;
    int n;

    for (n = 0; n < OP_MAX_ITERS; n++) {
        unsigned char *s = NULL;
        size_t l = 0;
        double a = now_ms(), dt;

        if (!do_sign(ctx, key, md, &s, &l))
            return -1.0;
        dt = now_ms() - a;
        OPENSSL_free(s);
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
            break;
    }
    return best;
}

/* Minimum single-op latency (ms) for a raw verify of a fixed signature (see
 * time_sign for why the minimum). -1.0 on error. */
static double time_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                          const unsigned char *sig, size_t siglen)
{
    double t0 = now_ms(), best = -1.0;
    int n;

    for (n = 0; n < OP_MAX_ITERS; n++) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        double a = now_ms(), dt;
        int ok = m != NULL
                 && EVP_DigestVerifyInit_ex(m, NULL, md, ctx, NULL, key, NULL) > 0
                 && EVP_DigestVerify(m, sig, siglen, guard_msg, GUARD_MSG_LEN) == 1;

        dt = now_ms() - a;
        EVP_MD_CTX_free(m);
        if (!ok) {
            ERR_clear_error();
            return -1.0;
        }
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && now_ms() - t0 >= g_budget_ms)
            break;
    }
    return best;
}

/* Assert one op: composite time within ceiling x the summed-components time. */
static void guard_op(const char *alg, const char *op, double comp, double sum)
{
    if (sum < COMPOSITE_OVERHEAD_MIN_MS)
        return;                            /* too small to time reliably */
    printf("    %-30s %-6s  %8.3f vs sum %8.3f  (%.2fx)\n",
           alg, op, comp, sum, comp / sum);
    if (comp > sum * COMPOSITE_OVERHEAD_CEIL) {
        printf("    !! %s %s composition overhead %.2fx sum-of-components exceeds "
               "%.1fx ceiling\n", alg, op, comp / sum, COMPOSITE_OVERHEAD_CEIL);
        g_guard_failures++;
    }
}

/* Guard one composite: sign/verify vs the sum of its two standalone components. */
static void guard_sig(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    EVP_PKEY *comp = NULL, *pq = NULL, *trad = NULL;
    unsigned char *csig = NULL, *psig = NULL, *tsig = NULL;
    size_t cl = 0, pl = 0, tl = 0;
    double cs, cv, ps, pv, ts, tv;

    /* Composite must be available; if not, bench_one already reported the skip. */
    if ((comp = gen_key(ctx, info->name, "provider=hybrid")) == NULL)
        return;
    /* Build the sum-of-components peer with the same implementations the combiner
     * uses (propq NULL -> default query order in this libctx). */
    if ((pq = gen_key(ctx, info->pq_alg, NULL)) == NULL
            || (trad = gen_trad_key(ctx, info->trad_alg, info->trad_group,
                                    info->trad_rsa_bits)) == NULL)
        goto done;

    if (!do_sign(ctx, comp, NULL, &csig, &cl)
            || !do_sign(ctx, pq, NULL, &psig, &pl)
            || !do_sign(ctx, trad, info->trad_md, &tsig, &tl))
        goto done;

    cs = time_sign(ctx, comp, NULL);
    ps = time_sign(ctx, pq, NULL);
    ts = time_sign(ctx, trad, info->trad_md);
    cv = time_verify(ctx, comp, NULL, csig, cl);
    pv = time_verify(ctx, pq, NULL, psig, pl);
    tv = time_verify(ctx, trad, info->trad_md, tsig, tl);
    if (cs < 0 || ps < 0 || ts < 0 || cv < 0 || pv < 0 || tv < 0)
        goto done;

    guard_op(info->name, "sign", cs, ps + ts);
    guard_op(info->name, "verify", cv, pv + tv);
done:
    OPENSSL_free(csig);
    OPENSSL_free(psig);
    OPENSSL_free(tsig);
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

    printf("composite certificate benchmark — self-signed X.509 (DER)\n");
    printf("  %-34s %-4s  %9s %9s %9s   %7s %7s\n",
           "algorithm", "tier", "keygen", "sign", "verify", "cert", "sk");
    printf("  %-34s %-4s  %9s %9s %9s   %7s %7s\n",
           "", "", "(ms)", "(ms)", "(ms)", "(bytes)", "(bytes)");

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

    /*
     * Composition-overhead guard: composite sign/verify vs the sum of its two
     * standalone components (see guard_sig). Available combos only; the rest were
     * already reported as skipped above.
     */
    printf("\ncomposition-overhead guard — composite vs sum-of-components "
           "(ceiling %.1fx, keygen excluded)\n", COMPOSITE_OVERHEAD_CEIL);
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        guard_sig(ctx, &composite_sig_table[i]);
    if (g_guard_failures == 0)
        printf("  guard: PASS (all measured composites within ceiling)\n");
    else
        printf("  guard: FAIL (%d operation(s) over ceiling)\n", g_guard_failures);

    OSSL_LIB_CTX_free(ctx);
    return g_guard_failures == 0 ? 0 : 1;
}
