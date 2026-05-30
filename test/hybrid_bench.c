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

#define ITERATIONS 1000

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
                     const char *label, int iterations)
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

/* Does oqsprovider actually expose a standalone ML-KEM-768 KEM? */
static int oqs_has_mlkem(OSSL_LIB_CTX *libctx)
{
    EVP_KEM *kem = EVP_KEM_fetch(libctx, "MLKEM768", "provider=oqsprovider");
    int ok = (kem != NULL);

    EVP_KEM_free(kem);
    ERR_clear_error();
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *hybrid_prov = NULL, *dflt_prov = NULL, *oqs_prov = NULL;
    const char *modulepath;
    int iterations = ITERATIONS;
    int oqs_mlkem = 0;

    if (argc > 1)
        iterations = atoi(argv[1]);
    if (iterations < 1)
        iterations = ITERATIONS;

    modulepath = getenv("OPENSSL_MODULES");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create library context\n");
        return 1;
    }

    dflt_prov = OSSL_PROVIDER_load(libctx, "default");
    if (dflt_prov == NULL) {
        fprintf(stderr, "Failed to load default provider\n");
        return 1;
    }

    if (modulepath != NULL)
        OSSL_PROVIDER_set_default_search_path(libctx, modulepath);

    /* oqsprovider is optional: only config 3 needs it. */
    oqs_prov = OSSL_PROVIDER_load(libctx, "oqsprovider");
    if (oqs_prov != NULL)
        oqs_mlkem = oqs_has_mlkem(libctx);
    else
        ERR_clear_error();

    hybrid_prov = OSSL_PROVIDER_load(libctx, "hybrid");
    if (hybrid_prov == NULL) {
        fprintf(stderr, "Failed to load hybrid provider\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("X25519MLKEM768 benchmark (%d iterations)\n", iterations);
    printf("OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("oqsprovider: %s%s\n",
           oqs_prov != NULL ? "loaded" : "not available",
           oqs_prov != NULL
               ? (oqs_mlkem ? " (provides MLKEM768)"
                            : " (no standalone ML-KEM)")
               : "");
    printf("==================================================================="
           "==================\n");

    /* 1. default provider's native MLX hybrid */
    bench_kem(libctx, "X25519MLKEM768", "provider=default", NULL,
              "default provider (native MLX)", iterations);

    /* 2. hybrid provider composing both components from the default provider */
    bench_kem(libctx, "X25519MLKEM768", "provider=hybrid", "provider=default",
              "hybrid provider (X25519+ML-KEM from default)", iterations);

    /* 3. hybrid provider: X25519 from default, ML-KEM from oqsprovider.
     *    "?provider=oqsprovider" prefers oqsprovider where it has the
     *    component (ML-KEM) and falls back to default otherwise (X25519). */
    if (oqs_mlkem) {
        bench_kem(libctx, "X25519MLKEM768", "provider=hybrid",
                  "?provider=oqsprovider",
                  "hybrid provider (X25519 default, ML-KEM oqsprovider)",
                  iterations);
    } else {
        printf("  %-46s  SKIPPED (oqsprovider ML-KEM unavailable)\n",
               "hybrid provider (X25519 default, ML-KEM oqsprovider)");
    }

    printf("\n");

    OSSL_PROVIDER_unload(hybrid_prov);
    if (oqs_prov != NULL)
        OSSL_PROVIDER_unload(oqs_prov);
    OSSL_PROVIDER_unload(dflt_prov);
    OSSL_LIB_CTX_free(libctx);
    return 0;
}
