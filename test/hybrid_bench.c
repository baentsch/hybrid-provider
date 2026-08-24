/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Benchmark the hybrid provider against the native implementations, in two parts:
 *   Part 1 (informational): for every hybrid the provider serves, a side-by-side
 *     of the provider vs its native peer -- the default provider's own group where
 *     it has one (native MLX from OpenSSL 3.5+), else oqsprovider's own hybrid.
 *     The set of rows and each row's peer are discovered at runtime from the
 *     provider tables, so nothing is hardcoded and rows with no peer are skipped.
 *   Part 2 (asserted): the sum-of-components composition-overhead guard.
 *
 * Configurations the running OpenSSL/provider mix cannot satisfy are skipped, not
 * failed, so the same binary runs against a 3.5+ build and a 3.4.x + oqs build.
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
#include "../hybrid_prov.h"     /* hybrid_{kem,sig}_table for the guard */
#include "bench_util.h"

#define ITERATIONS 1000

/*
 * This file has two parts:
 *
 *   1. An informational report (bench_kem/bench_sig via compare_*): for each
 *      hybrid it prints the hybrid provider's keygen/encaps/decaps (or sign/verify)
 *      timings side-by-side with the NATIVE peer -- the default provider's built-in
 *      MLX for the standardized groups, oqsprovider's own hybrid otherwise. This is
 *      a showcase ("our EVP composition is as fast as the built-in"), NOT asserted.
 *
 *   2. The composition-overhead regression guard (work-items item 20), which is the
 *      SAME sum-of-components model as the composite benches (see bench_util.h): a
 *      hybrid IS its two constituent components plus a small combiner glue, so the
 *      guard asserts each hybrid's steady-state ops stay within HYBRID_OVERHEAD_CEIL
 *      of the sum of its components measured standalone. Iterating the provider's
 *      own hybrid_{kem,sig}_table means the peer fetches each component by the exact
 *      name the provider composes with -> same implementation by construction, so
 *      any per-component cost (incl. oqsprovider's no_cache tax) cancels: no native
 *      peer, no FAIR/UNFAIR matching, no version gating. Keygen is excluded
 *      (randomised, heavy-tailed) and timings are the minimum per-op latency.
 */
/* Combiner glue is small: ~1.0x for sigs, up to ~1.25x for the fastest KEMs; at
 * parity with oqsprovider's own hybrids. The ceiling is 1.4x (not 1.25x): a few
 * standardized composite signatures sit at ~1.3x on >=3.5, and the short ctest
 * smoke budget adds scheduler jitter to the sub-0.1ms primitives, so the extra
 * headroom keeps the guard from flaking. See bench_util.h for the model. */
#define HYBRID_OVERHEAD_CEIL 1.4

typedef struct {
    double op[3];   /* KEM: keygen, encaps, decaps.  SIG: keygen, sign, verify. */
    int valid;      /* 1 once measured; 0 on skip/error */
} BENCH_TIMES;

static double time_diff_ms(struct timespec *start, struct timespec *end)
{
    return (end->tv_sec - start->tv_sec) * 1000.0
         + (end->tv_nsec - start->tv_nsec) / 1e6;
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
 * Does `prov` (e.g. "default"/"oqsprovider") serve algorithm `name`? Probed via the
 * keymgmt path that the benches actually use, so the informational report discovers
 * its native peer dynamically instead of naming algorithms -- it adapts to whatever
 * each provider serves on the running OpenSSL (native MLX only from 3.5, oqs naming
 * for the legacy hybrids, etc.). Returns the provider string on success, else NULL.
 */
static const char *served_by(OSSL_LIB_CTX *libctx, const char *name,
                             const char *prov)
{
    char propq[64];
    EVP_PKEY_CTX *c;
    int ok;

    snprintf(propq, sizeof(propq), "provider=%s", prov);
    c = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;
    EVP_PKEY_CTX_free(c);
    if (!ok)
        ERR_clear_error();
    return ok ? prov : NULL;
}

/* The native peer for a KEM: default's built-in group if it has one, else
 * oqsprovider's own hybrid, else NULL (no peer -> row skipped in the report). */
static const char *kem_native_peer(OSSL_LIB_CTX *libctx, const char *name)
{
    const char *p = served_by(libctx, name, "default");

    return p != NULL ? p : served_by(libctx, name, "oqsprovider");
}

/*
 * Informational side-by-side print (NOT asserted -- the guard is the separate
 * sum-of-components pass): the native peer (default's built-in MLX for the
 * standardized groups, else oqsprovider's own hybrid) next to the hybrid provider.
 */
static void compare_kem(OSSL_LIB_CTX *libctx, const char *alg,
                        const char *native, int it)
{
    char lbl[80];
    int from_default = (native[0] == 'd');

    printf("%s:\n", alg);
    snprintf(lbl, sizeof(lbl), "  %s (native)", native);
    bench_kem(libctx, alg, from_default ? "provider=default"
                                        : "provider=oqsprovider",
              NULL, lbl, it, NULL);
    snprintf(lbl, sizeof(lbl), "  hybrid (PQ from %s)", native);
    bench_kem(libctx, alg, "provider=hybrid",
              from_default ? "provider=default" : "?provider=oqsprovider",
              lbl, it, NULL);
}

/* Same, for a signature hybrid (native peer is always oqsprovider). */
static void compare_sig(OSSL_LIB_CTX *libctx, const char *alg, int it)
{
    printf("%s:\n", alg);
    bench_sig(libctx, alg, "provider=oqsprovider", NULL, "  oqsprovider (native)",
              it, NULL);
    bench_sig(libctx, alg, "provider=hybrid", "?provider=oqsprovider", "  hybrid",
              it, NULL);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *hybrid_prov = NULL, *dflt_prov = NULL, *oqs_prov = NULL;
    const char *modulepath;
    int it = ITERATIONS, has_oqs, guard_failures = 0;
    size_t i;

    if (argc > 1 && atoi(argv[1]) > 0)
        it = atoi(argv[1]);
    /* The info report uses `it` iterations; the guard reuses the number as a ms
     * budget (floored so the short ctest smoke run still samples enough). */
    bench_set_budget_ms(it < 50 ? 50.0 : (double)it);
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
    has_oqs = oqs_prov != NULL;   /* per-alg availability is discovered below */
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
    printf("Part 1 (informational): hybrid provider vs the native peer, per op.\n"
           "Part 2 (asserted): the sum-of-components guard.\n");

    /* Part 1 iterates the provider's OWN hybrid tables and discovers each row's
     * native peer at runtime (see kem_native_peer) -- no algorithm is named here;
     * rows with no peer on this OpenSSL are simply not printed. */
    printf("\n[KEM: hybrid vs native peer]\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *name = hybrid_kem_table[i].hybrid_name;
        const char *peer = kem_native_peer(libctx, name);

        if (peer != NULL)
            compare_kem(libctx, name, peer, it);
    }

    if (has_oqs) {
        /* The default provider has no hybrid signatures, so oqsprovider is the
         * only possible native peer; discover which sigs it actually serves. */
        printf("\n[SIG: hybrid vs oqsprovider]\n");
        for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
            const char *name = hybrid_sig_table[i].hybrid_name;

            if (served_by(libctx, name, "oqsprovider") != NULL)
                compare_sig(libctx, name, it);
        }
    }

    /*
     * Composition-overhead guard: each hybrid's steady-state ops vs the sum of its
     * two components, iterating the provider's OWN tables so the peer fetches each
     * component by the exact name the provider composes with (same impl -> tax
     * cancels; see bench_util.h). Unlike Part 1 this needs no native peer -- only
     * the two components -- so it covers every hybrid, including those Part 1 skips.
     */
    if (bench_timing_unreliable()) {
        printf("\ncomposition-overhead guard — SKIPPED "
               "(timing unreliable under a sanitizer)\n");
    } else {
        printf("\ncomposition-overhead guard — hybrid vs sum-of-components "
               "(ceiling %.1fx, keygen excluded)\n", HYBRID_OVERHEAD_CEIL);
        for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
            const HYBRID_KEM_INFO *r = &hybrid_kem_table[i];

            bench_guard_kem(libctx, r->hybrid_name, "provider=hybrid",
                            r->alg2_name, r->alg1_name, r->alg1_group, 0,
                            HYBRID_OVERHEAD_CEIL, &guard_failures);
        }
        for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
            const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];
            /* classical component's own digest, per its PQ NIST level */
            const char *md = r->nist_level <= 1 ? "SHA256"
                           : r->nist_level <= 3 ? "SHA384" : "SHA512";
            int rsa_bits = (strcmp(r->alg1_name, "RSA") == 0) ? 3072 : 0;

            bench_guard_sig(libctx, r->hybrid_name, "provider=hybrid",
                            r->alg2_name, r->alg1_name, r->alg1_group, rsa_bits,
                            md, HYBRID_OVERHEAD_CEIL, &guard_failures);
        }
        if (guard_failures == 0)
            printf("  guard: PASS (all measured hybrids within ceiling)\n");
        else
            printf("  guard: FAIL (%d operation(s) over ceiling)\n",
                   guard_failures);
    }

    OSSL_PROVIDER_unload(hybrid_prov);
    if (oqs_prov != NULL)
        OSSL_PROVIDER_unload(oqs_prov);
    OSSL_PROVIDER_unload(dflt_prov);
    OSSL_LIB_CTX_free(libctx);
    return guard_failures == 0 ? 0 : 1;
}
