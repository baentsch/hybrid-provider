/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Benchmark X25519MLKEM768 across three configurations:
 *   1. default provider's native MLX hybrid          (OpenSSL 3.5+)
 *   2. hybrid provider, both components from default  (OpenSSL 3.5+)
 *   3. hybrid provider, X25519 from default and
 *      ML-KEM from oqsprovider                        (OpenSSL 3.4.x + oqs)
 *
 * Configurations that the running OpenSSL/provider mix cannot satisfy are
 * skipped rather than treated as failures, so the same binary can be run
 * against both a 3.5+ build (configs 1 and 2) and a 3.4.x build with
 * oqsprovider (config 3).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/crypto.h>     /* OpenSSL_version_num */

#define ITERATIONS 1000

/*
 * Composition-overhead regression guard (work-items item 20).
 *
 * The hybrid provider's job is to COMPOSE two component algorithms; the glue it
 * adds (buffer split/concat, the length prefix, an EVP_MD_CTX) is a small additive
 * constant next to the component crypto. This guard makes that machine-checked so
 * a regression (e.g. an accidental extra copy or fetch in the hot path) fails CI
 * instead of only showing up in the printed numbers.
 *
 * It compares the hybrid against the NATIVE peer that runs the SAME components,
 * per operation, and asserts a single tight ceiling. Two refinements keep the
 * measurement clean so ONE bound suffices instead of a menagerie of factors:
 *
 *   - Keygen is excluded (see check_overhead). Keygen is a randomised process for
 *     essentially every algorithm here (Falcon/NTRU rejection sampling, matrix
 *     expansion, fresh EC scalars), so its per-call time is itself a heavy-tailed
 *     random variable. A ratio on top of that measures keygen's intrinsic variance,
 *     not our glue. Only the repeatable steady-state ops (encaps/decaps,
 *     sign/verify) carry a clean composition signal, and there the delta is ~1.0x.
 *
 *   - A row is asserted only where the measurement is untainted: same PQ impl on
 *     both sides (FAIR) AND no oqsprovider no_cache tax. That tax (a per-op method
 *     reconstruction forced by oqsprovider's blanket no_cache=1 — an oqsprovider
 *     artifact, NOT our composition; see docs/ and design.md Performance) is
 *     version-gated inside oqsprovider at OpenSSL 3.5.0. So oqsprovider-component
 *     rows are asserted on pre-3.5 builds (whose CI legs exercise the identical
 *     composition core, tax-free) and merely reported on 3.5+. See oqs_no_cache_tax.
 *
 * With keygen and the tax removed, the observed steady-state delta is ~1.0x across
 * every algorithm, so a single 1.6x ceiling clears real noise while a genuine
 * composition regression (a doubled copy, an O(n) blowup) trips it comfortably.
 */
#define OVERHEAD_CEIL   1.6     /* composition glue only; the native peer is itself
                                 * a hybrid doing both halves, so expected ~1.0x */
#define OVERHEAD_MIN_MS 0.010   /* below this per-op, timing noise dominates */

typedef struct {
    double op[3];   /* KEM: keygen, encaps, decaps.  SIG: keygen, sign, verify. */
    int valid;      /* 1 once measured; 0 on skip/error (no assertion made) */
} BENCH_TIMES;

static const char *const KEM_OPS[3] = { "keygen", "encaps", "decaps" };
static const char *const SIG_OPS[3] = { "keygen", "sign",   "verify" };

static int overhead_failures;   /* nonzero -> main() returns failure */

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0
         + (end->tv_nsec - start->tv_nsec) / 1e6;
}

/*
 * Assert the hybrid stays within `ceil` x the native peer per operation (only
 * where both were measured and native is above the noise floor). Prints one line
 * per violation and bumps the global failure counter.
 */
static void check_overhead(const char *alg, const BENCH_TIMES *native,
                           const BENCH_TIMES *hybrid, const char *const ops[3],
                           double ceil)
{
    int i;

    if (!native->valid || !hybrid->valid)
        return;
    /*
     * Start at index 1: op[0] is keygen, which is randomised (rejection sampling,
     * fresh entropy) and thus a heavy-tailed random variable in its own right --
     * a hybrid/native ratio on it measures keygen's variance, not composition
     * overhead. It is printed for information but never asserted. The steady-state
     * ops (encaps/decaps, sign/verify) are the clean, repeatable signal.
     */
    for (i = 1; i < 3; i++) {
        if (native->op[i] < OVERHEAD_MIN_MS)
            continue;   /* too small to time reliably */
        if (hybrid->op[i] > native->op[i] * ceil) {
            printf("  !! %s %s: composition overhead %.2fx native "
                   "(%.4f vs %.4f ms) exceeds %.2fx ceiling\n",
                   alg, ops[i], hybrid->op[i] / native->op[i],
                   hybrid->op[i], native->op[i], ceil);
            overhead_failures++;
        }
    }
}

/*
 * select_propq picks which provider supplies the *hybrid* algorithm itself.
 * comp_propq (may be NULL) is forwarded to the hybrid provider as the property
 * query used when it generates its component keys, letting us steer X25519 and
 * ML-KEM to specific providers.
 *
 * Returns 1 on success, 0 on hard error, -1 if the configuration is
 * unavailable on this build (skipped).
 */
static int bench_kem(OSSL_LIB_CTX *libctx, const char *algname,
                     const char *select_propq, const char *comp_propq,
                     const char *label, int iterations, BENCH_TIMES *out)
{
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *ctext = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t ctlen, ss_enc_len;
    struct timespec t0, t1, t2, t3;
    double keygen_ms, encaps_ms, decaps_ms;
    int ret = 0;

    /* Probe once: if the very first keygen fails, treat as "unavailable". */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, select_propq);
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0) {
        ERR_clear_error();
        printf("  %-46s  SKIPPED (algorithm unavailable)\n", label);
        EVP_PKEY_CTX_free(gctx);
        return -1;
    }
    if (comp_propq != NULL) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_PROPERTIES, (char *)comp_propq, 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(gctx, params) <= 0) {
            ERR_clear_error();
            printf("  %-46s  SKIPPED (cannot set component properties)\n",
                   label);
            EVP_PKEY_CTX_free(gctx);
            return -1;
        }
    }
    if (EVP_PKEY_keygen(gctx, &key) <= 0) {
        if (getenv("BENCH_DEBUG") != NULL)
            ERR_print_errors_fp(stderr);
        ERR_clear_error();
        printf("  %-46s  SKIPPED (component provider unavailable)\n", label);
        EVP_PKEY_CTX_free(gctx);
        return -1;
    }
    EVP_PKEY_free(key);
    key = NULL;
    EVP_PKEY_CTX_free(gctx);
    gctx = NULL;

    /* --- Keygen benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iterations; i++) {
        EVP_PKEY *tmp = NULL;
        gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, select_propq);
        if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0) {
            fprintf(stderr, "%s: keygen init failed\n", label);
            goto err;
        }
        if (comp_propq != NULL) {
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_utf8_string(
                            OSSL_PKEY_PARAM_PROPERTIES, (char *)comp_propq, 0);
            params[1] = OSSL_PARAM_construct_end();
            EVP_PKEY_CTX_set_params(gctx, params);
        }
        if (EVP_PKEY_keygen(gctx, &tmp) <= 0) {
            fprintf(stderr, "%s: keygen failed\n", label);
            ERR_print_errors_fp(stderr);
            goto err;
        }
        if (i == 0)
            key = tmp;
        else
            EVP_PKEY_free(tmp);
        EVP_PKEY_CTX_free(gctx);
        gctx = NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Get sizes */
    ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, select_propq);
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0
        || EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &ss_enc_len) <= 0) {
        fprintf(stderr, "%s: size query failed\n", label);
        goto err;
    }
    EVP_PKEY_CTX_free(ectx);
    ectx = NULL;

    ctext = OPENSSL_malloc(ctlen);
    ss_enc = OPENSSL_malloc(ss_enc_len);
    ss_dec = OPENSSL_malloc(ss_enc_len);

    /* --- Encaps benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (int i = 0; i < iterations; i++) {
        size_t cl = ctlen, sl = ss_enc_len;
        ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, select_propq);
        if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0
            || EVP_PKEY_encapsulate(ectx, ctext, &cl, ss_enc, &sl) <= 0) {
            fprintf(stderr, "%s: encaps failed\n", label);
            goto err;
        }
        EVP_PKEY_CTX_free(ectx);
        ectx = NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    /* --- Decaps benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &t2);
    for (int i = 0; i < iterations; i++) {
        size_t sl = ss_enc_len;
        dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, select_propq);
        if (dctx == NULL || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0
            || EVP_PKEY_decapsulate(dctx, ss_dec, &sl, ctext, ctlen) <= 0) {
            fprintf(stderr, "%s: decaps failed\n", label);
            goto err;
        }
        EVP_PKEY_CTX_free(dctx);
        dctx = NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t3);

    keygen_ms = time_diff_ms(&t0, &t1) / iterations;
    encaps_ms = time_diff_ms(&t1, &t2) / iterations;
    decaps_ms = time_diff_ms(&t2, &t3) / iterations;

    printf("  %-46s  keygen: %7.3f ms  encaps: %7.3f ms  decaps: %7.3f ms\n",
           label, keygen_ms, encaps_ms, decaps_ms);

    if (out != NULL) {
        out->op[0] = keygen_ms;
        out->op[1] = encaps_ms;
        out->op[2] = decaps_ms;
        out->valid = 1;
    }
    ret = 1;

err:
    OPENSSL_free(ctext);
    OPENSSL_free(ss_enc);
    OPENSSL_free(ss_dec);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    return ret;
}

/* Does the named provider expose a standalone ML-KEM-768 KEM? */
static int provider_has_mlkem(OSSL_LIB_CTX *libctx, const char *provname)
{
    char propq[128];
    EVP_KEM *kem;
    int ok;

    snprintf(propq, sizeof(propq), "provider=%s", provname);
    kem = EVP_KEM_fetch(libctx, "MLKEM768", propq);
    ok = (kem != NULL);
    EVP_KEM_free(kem);
    ERR_clear_error();
    return ok;
}

/* Does the named provider expose a standalone ML-DSA-65 signature? */
static int provider_has_mldsa(OSSL_LIB_CTX *libctx, const char *provname)
{
    char propq[128];
    EVP_SIGNATURE *sig;
    int ok;

    snprintf(propq, sizeof(propq), "provider=%s", provname);
    sig = EVP_SIGNATURE_fetch(libctx, "MLDSA65", propq);
    ok = (sig != NULL);
    EVP_SIGNATURE_free(sig);
    ERR_clear_error();
    return ok;
}

/*
 * Benchmark a hybrid signature (keygen, sign, verify). select_propq picks the
 * hybrid algorithm; comp_propq (may be NULL) steers the component
 * sub-algorithms (i.e. which provider supplies ML-DSA). Returns 1 on success,
 * 0 on hard error, -1 if unavailable (skipped).
 */
static int bench_sig(OSSL_LIB_CTX *libctx, const char *algname,
                     const char *select_propq, const char *comp_propq,
                     const char *label, int iterations, BENCH_TIMES *out)
{
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sctx = NULL, *vctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0, maxlen = 0;
    const unsigned char msg[] = "hybrid signature benchmark message";
    size_t msglen = sizeof(msg) - 1;
    struct timespec t0, t1, t2, t3;
    double keygen_ms, sign_ms, verify_ms;
    int ret = 0;

    /* Probe: if keygen is unavailable, treat the config as skipped. */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, select_propq);
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0) {
        ERR_clear_error();
        printf("  %-40s  SKIPPED (algorithm unavailable)\n", label);
        EVP_PKEY_CTX_free(gctx);
        return -1;
    }
    if (comp_propq != NULL) {
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
                        OSSL_PKEY_PARAM_PROPERTIES, (char *)comp_propq, 0);
        params[1] = OSSL_PARAM_construct_end();
        EVP_PKEY_CTX_set_params(gctx, params);
    }
    if (EVP_PKEY_keygen(gctx, &key) <= 0) {
        ERR_clear_error();
        printf("  %-40s  SKIPPED (component provider unavailable)\n", label);
        EVP_PKEY_CTX_free(gctx);
        return -1;
    }
    EVP_PKEY_free(key);
    key = NULL;
    EVP_PKEY_CTX_free(gctx);
    gctx = NULL;

    /* --- Keygen benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < iterations; i++) {
        EVP_PKEY *tmp = NULL;
        gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, select_propq);
        if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0) {
            fprintf(stderr, "%s: keygen init failed\n", label);
            goto err;
        }
        if (comp_propq != NULL) {
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_utf8_string(
                            OSSL_PKEY_PARAM_PROPERTIES, (char *)comp_propq, 0);
            params[1] = OSSL_PARAM_construct_end();
            EVP_PKEY_CTX_set_params(gctx, params);
        }
        if (EVP_PKEY_keygen(gctx, &tmp) <= 0) {
            fprintf(stderr, "%s: keygen failed\n", label);
            goto err;
        }
        if (i == 0)
            key = tmp;
        else
            EVP_PKEY_free(tmp);
        EVP_PKEY_CTX_free(gctx);
        gctx = NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* Query signature size */
    sctx = EVP_MD_CTX_new();
    if (sctx == NULL
        || EVP_DigestSignInit_ex(sctx, NULL, NULL, libctx, select_propq,
                                 key, NULL) <= 0
        || EVP_DigestSign(sctx, NULL, &maxlen, msg, msglen) <= 0) {
        fprintf(stderr, "%s: sign size query failed\n", label);
        goto err;
    }
    EVP_MD_CTX_free(sctx);
    sctx = NULL;
    sig = OPENSSL_malloc(maxlen);
    if (sig == NULL)
        goto err;

    /* --- Sign benchmark --- */
    clock_gettime(CLOCK_MONOTONIC, &t1);
    for (int i = 0; i < iterations; i++) {
        siglen = maxlen;
        sctx = EVP_MD_CTX_new();
        if (sctx == NULL
            || EVP_DigestSignInit_ex(sctx, NULL, NULL, libctx, select_propq,
                                     key, NULL) <= 0
            || EVP_DigestSign(sctx, sig, &siglen, msg, msglen) <= 0) {
            fprintf(stderr, "%s: sign failed\n", label);
            goto err;
        }
        EVP_MD_CTX_free(sctx);
        sctx = NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    /* --- Verify benchmark (uses the signature from the last sign) --- */
    clock_gettime(CLOCK_MONOTONIC, &t2);
    for (int i = 0; i < iterations; i++) {
        vctx = EVP_MD_CTX_new();
        if (vctx == NULL
            || EVP_DigestVerifyInit_ex(vctx, NULL, NULL, libctx, select_propq,
                                       key, NULL) <= 0
            || EVP_DigestVerify(vctx, sig, siglen, msg, msglen) <= 0) {
            fprintf(stderr, "%s: verify failed\n", label);
            goto err;
        }
        EVP_MD_CTX_free(vctx);
        vctx = NULL;
    }
    clock_gettime(CLOCK_MONOTONIC, &t3);

    keygen_ms = time_diff_ms(&t0, &t1) / iterations;
    sign_ms = time_diff_ms(&t1, &t2) / iterations;
    verify_ms = time_diff_ms(&t2, &t3) / iterations;

    printf("  %-40s  keygen: %7.3f ms  sign: %7.3f ms  verify: %7.3f ms\n",
           label, keygen_ms, sign_ms, verify_ms);
    if (out != NULL) {
        out->op[0] = keygen_ms;
        out->op[1] = sign_ms;
        out->op[2] = verify_ms;
        out->valid = 1;
    }
    ret = 1;

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * A hybrid-vs-native comparison is only apples-to-apples ("fair") when both
 * sides end up exercising the SAME PQ implementation. That holds iff the PQ
 * component is served by the same provider the native peer uses internally:
 *   - MLX groups: native is the default provider and the hybrid also sources
 *     ML-KEM from default -> always fair.
 *   - OQS-legacy: native is oqsprovider (liboqs). The hybrid's
 *     "?provider=oqsprovider" only reaches liboqs if oqsprovider actually
 *     exposes that PQ primitive STANDALONE; otherwise it silently falls through
 *     to default's portable-C impl (e.g. ML-KEM/ML-DSA are ceded to default
 *     under OpenSSL 3.5), making the row UNFAIR (different implementations).
 * These probes decide the tag empirically so the numbers can't be misread.
 */
static int pq_from_oqs_kem(OSSL_LIB_CTX *libctx, const char *pqname)
{
    EVP_KEM *k = EVP_KEM_fetch(libctx, pqname, "provider=oqsprovider");
    int ok = (k != NULL);
    EVP_KEM_free(k);
    ERR_clear_error();
    return ok;
}

static int pq_from_oqs_sig(OSSL_LIB_CTX *libctx, const char *pqname)
{
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(libctx, pqname, "provider=oqsprovider");
    int ok = (s != NULL);
    EVP_SIGNATURE_free(s);
    ERR_clear_error();
    return ok;
}

/*
 * oqsprovider's blanket no_cache=1 -- which forces a full method reconstruction on
 * every component fetch (see docs/oqsprovider-no-cache-issue.md and design.md
 * Performance) -- is gated inside oqsprovider at OpenSSL 3.5.0. Below that, the
 * hybrid's component fetches are cached just like the native peer's, so an
 * oqsprovider-sourced row is a clean composition measurement; at/above it the
 * hybrid pays the tax per component per op and the ratio is inflated by an upstream
 * artifact, not our glue. So we assert oqsprovider-component rows only on pre-3.5
 * builds and merely report them on 3.5+ (the pre-3.5 CI legs run the identical
 * composition core, so coverage is unchanged).
 */
static int oqs_no_cache_tax(void)
{
    return OpenSSL_version_num() >= 0x30500000L;
}

/*
 * Print the per-row classification that says whether the ceiling is asserted on
 * this row. Three states: not comparable (UNFAIR), comparable but tax-tainted on
 * 3.5+ (reported only), or clean (steady-state ops asserted).
 */
static void print_row_class(const char *alg, int fair, int taxed)
{
    if (!fair)
        printf("%s:  [UNFAIR: hybrid PQ ceded to default portable-C vs native "
               "liboqs -- reported, not asserted]\n", alg);
    else if (taxed)
        printf("%s:  [FAIR but oqsprovider no_cache tax active (OpenSSL>=3.5) "
               "-- reported, not asserted]\n", alg);
    else
        printf("%s:  [FAIR: same PQ impl, no tax -- steady-state ops asserted "
               "<= %.1fx]\n", alg, OVERHEAD_CEIL);
}

/*
 * Compare one KEM hybrid across the providers that implement it: the native
 * implementation (default for MLX names, oqsprovider for OQS-legacy names) and
 * the hybrid provider. For the hybrid provider we source the PQ base from the
 * same place the native peer uses (comp_propq), so the delta is the hybrid
 * provider's composition overhead, not a different PQ implementation -- but the
 * ceiling is asserted only where that delta is clean (FAIR and tax-free).
 */
static void compare_kem(OSSL_LIB_CTX *libctx, const char *alg,
                        const char *native, const char *pq, int it)
{
    char lbl[80];
    int from_default = (native[0] == 'd');
    int fair = from_default ? 1 : pq_from_oqs_kem(libctx, pq);
    int taxed = fair && !from_default && oqs_no_cache_tax();
    BENCH_TIMES nt = { {0}, 0 }, ht = { {0}, 0 };

    print_row_class(alg, fair, taxed);
    snprintf(lbl, sizeof(lbl), "  %s (native)", native);
    bench_kem(libctx, alg, from_default ? "provider=default"
                                        : "provider=oqsprovider",
              NULL, lbl, it, &nt);
    snprintf(lbl, sizeof(lbl), "  hybrid (PQ from %s)", native);
    bench_kem(libctx, alg, "provider=hybrid",
              from_default ? "provider=default" : "?provider=oqsprovider",
              lbl, it, &ht);
    if (fair && !taxed)
        check_overhead(alg, &nt, &ht, KEM_OPS, OVERHEAD_CEIL);
}

/* Same, for a signature hybrid (native peer is always oqsprovider). */
static void compare_sig(OSSL_LIB_CTX *libctx, const char *alg,
                        const char *pq, int it)
{
    char lbl[80];
    int fair = pq_from_oqs_sig(libctx, pq);
    int taxed = fair && oqs_no_cache_tax();   /* native peer is always oqsprovider */
    BENCH_TIMES nt = { {0}, 0 }, ht = { {0}, 0 };

    print_row_class(alg, fair, taxed);
    snprintf(lbl, sizeof(lbl), "  oqsprovider (native)");
    bench_sig(libctx, alg, "provider=oqsprovider", NULL, lbl, it, &nt);
    snprintf(lbl, sizeof(lbl), "  hybrid");
    bench_sig(libctx, alg, "provider=hybrid", "?provider=oqsprovider", lbl, it,
              &ht);
    if (fair && !taxed)
        check_overhead(alg, &nt, &ht, SIG_OPS, OVERHEAD_CEIL);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *hybrid_prov = NULL, *dflt_prov = NULL, *oqs_prov = NULL;
    const char *modulepath;
    int it = ITERATIONS, has_oqs;
    size_t i;
    /* Each row carries its standalone PQ component name so the fair/unfair tag
     * can be decided empirically (does oqsprovider expose that PQ primitive?). */
    static const struct { const char *alg, *pq; } mlx_kems[] = {
        { "X25519MLKEM768", "MLKEM768" },
        { "SecP256r1MLKEM768", "MLKEM768" },
        { "SecP384r1MLKEM1024", "MLKEM1024" },
    };
    static const struct { const char *alg, *pq; } oqs_kems[] = {
        { "p256_mlkem512", "MLKEM512" },
        { "x25519_mlkem512", "MLKEM512" },
        { "p384_mlkem768", "MLKEM768" },
        { "p256_frodo640aes", "frodo640aes" },
        { "p256_hqc1", "hqc1" },
    };
    static const struct { const char *alg, *pq; } sig_algs[] = {
        { "p256_mldsa44", "MLDSA44" },
        { "p384_mldsa65", "MLDSA65" },
        { "p256_falcon512", "falcon512" },
        { "p256_mayo1", "mayo1" },
        { "p256_snova2454", "snova2454" },
    };

    if (argc > 1 && atoi(argv[1]) > 0)
        it = atoi(argv[1]);
    modulepath = getenv("OPENSSL_MODULES");

    /* Measure the HYBRID provider's own MLX implementation, not the default's:
     * without this the cede-to-default lever withdraws the MLX groups from the
     * hybrid provider and its rows would be skipped (and the tight default-
     * component ceiling never exercised). */
    setenv("HYBRID_CEDE_TO_DEFAULT", "0", 1);

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL || (dflt_prov = OSSL_PROVIDER_load(libctx, "default"))
                              == NULL) {
        fprintf(stderr, "cannot init libctx/default\n");
        return 1;
    }
    if (modulepath != NULL)
        OSSL_PROVIDER_set_default_search_path(libctx, modulepath);
    oqs_prov = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (oqs_prov != NULL) {
        /* Under OpenSSL 3.5 oqsprovider cedes standalone ML-KEM to default, so
         * probe a hybrid it actually owns. */
        EVP_KEM *k = EVP_KEM_fetch(libctx, "p256_mlkem512",
                                   "provider=oqsprovider");
        has_oqs = k != NULL;
        EVP_KEM_free(k);
    } else {
        has_oqs = 0;
    }
    ERR_clear_error();
    hybrid_prov = OSSL_PROVIDER_load(libctx, "hybrid");
    if (hybrid_prov == NULL) {
        fprintf(stderr, "cannot load hybrid provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Hybrid provider vs native performance (%d iterations)\n", it);
    printf("OpenSSL %s; oqsprovider %s\n", OpenSSL_version(OPENSSL_VERSION),
           has_oqs ? "loaded" : "not available");
    printf("=====================================================\n");
    printf("FAIR   = hybrid and native use the same PQ implementation; the delta\n"
           "         is pure composition overhead. Steady-state ops (encaps/decaps,\n"
           "         sign/verify) are asserted <= %.1fx; keygen is randomised, so\n"
           "         it is printed but never asserted.\n"
           "UNFAIR = the PQ primitive is ceded to default (portable C), so the\n"
           "         hybrid runs a DIFFERENT impl than native's liboqs; reported,\n"
           "         not asserted.\n"
           "TAXED  = FAIR, but on OpenSSL>=3.5 oqsprovider's no_cache=1 inflates the\n"
           "         ratio with a per-op fetch (an oqsprovider artifact, not our\n"
           "         glue); reported, not asserted (pre-3.5 legs assert it clean).\n",
           OVERHEAD_CEIL);

    printf("\n[KEM: MLX groups — hybrid vs default provider]\n");
    for (i = 0; i < sizeof(mlx_kems) / sizeof(mlx_kems[0]); i++)
        compare_kem(libctx, mlx_kems[i].alg, "default", mlx_kems[i].pq, it);

    if (has_oqs) {
        printf("\n[KEM: OQS-legacy hybrids — hybrid vs oqsprovider]\n");
        for (i = 0; i < sizeof(oqs_kems) / sizeof(oqs_kems[0]); i++)
            compare_kem(libctx, oqs_kems[i].alg, "oqsprovider",
                        oqs_kems[i].pq, it);

        printf("\n[SIG: hybrids — hybrid vs oqsprovider]\n");
        for (i = 0; i < sizeof(sig_algs) / sizeof(sig_algs[0]); i++)
            compare_sig(libctx, sig_algs[i].alg, sig_algs[i].pq, it);
    }
    printf("\n");

    if (overhead_failures == 0)
        printf("Composition-overhead guard: PASS (all asserted ops within "
               "ceiling)\n");
    else
        printf("Composition-overhead guard: FAIL (%d operation(s) over "
               "ceiling)\n", overhead_failures);

    OSSL_PROVIDER_unload(hybrid_prov);
    if (oqs_prov != NULL)
        OSSL_PROVIDER_unload(oqs_prov);
    OSSL_PROVIDER_unload(dflt_prov);
    OSSL_LIB_CTX_free(libctx);
    return overhead_failures == 0 ? 0 : 1;
}
