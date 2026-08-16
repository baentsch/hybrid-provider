/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cross-provider test-methodology coverage (work-items item 15).
 *
 * The rest of the suite pins `provider=hybrid` on every fetch and loads the
 * provider from an OPENSSL_MODULES path (an implicit .cnf-style activation). Two
 * things that a provider composing components from *whichever* provider supplies
 * them must also support went untested:
 *
 *   (1) UNPINNED (store) resolution. A caller that does NOT pin a property query
 *       must still reach the provider's algorithms via OpenSSL's normal
 *       implementation store. We run each functional round-trip twice — once with
 *       propquery = "provider=hybrid" (pinned) and once with propquery = NULL
 *       (unpinned) — and require both to pass. Hybrid signatures are used because
 *       the default provider ships no hybrid signatures, so an unpinned fetch
 *       resolves unambiguously to this provider.
 *
 *   (2) CONFIG-PARAMS-ONLY load, no .cnf. The provider's configuration keys must
 *       be settable programmatically via OSSL_PROVIDER_load_ex()'s parameter
 *       array, not only through a config-file section. We load with
 *       "cede-to-default=no" and confirm the hybrid provider then serves an MLX
 *       KEM the default provider also offers (which it withdraws by default) —
 *       proving the parameter was read and applied at init without any .cnf.
 *
 * All algorithms draw both halves from the default provider (>= 3.5), so no
 * oqsprovider is needed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/err.h>

static int tests, passed, failed, skipped;

/* Sign+verify round-trip for a hybrid signature under a given property query
 * (NULL = unpinned). Returns 1 on success, 0 on failure, -1 if unavailable. */
static int sig_roundtrip(OSSL_LIB_CTX *ctx, const char *alg, const char *propq)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, propq);
    EVP_PKEY *k = NULL;
    EVP_MD_CTX *md = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const unsigned char msg[] = "unpinned vs pinned round-trip";
    size_t msglen = sizeof(msg) - 1;
    int ret = -1;

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
            || EVP_PKEY_keygen(g, &k) <= 0) {
        ERR_clear_error();
        goto end;                            /* unavailable */
    }
    ret = 0;
    md = EVP_MD_CTX_new();
    if (md == NULL
            || EVP_DigestSignInit_ex(md, NULL, NULL, ctx, propq, k, NULL) <= 0
            || EVP_DigestSign(md, NULL, &siglen, msg, msglen) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(md, sig, &siglen, msg, msglen) <= 0)
        goto end;
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
            || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, propq, k, NULL) <= 0
            || EVP_DigestVerify(md, sig, siglen, msg, msglen) != 1)
        goto end;
    ret = 1;
end:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(g);
    return ret;
}

/* Can `alg` be generated from the hybrid provider (pinned)? */
static int hybrid_serves(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *k = NULL;
    int ok = g != NULL && EVP_PKEY_keygen_init(g) > 0
             && EVP_PKEY_keygen(g, &k) > 0;

    if (!ok)
        ERR_clear_error();
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(g);
    return ok;
}

/* (1) Same functional round-trip, pinned then unpinned; both must pass. */
static void check_dual_run(OSSL_LIB_CTX *ctx, const char *alg)
{
    int pinned, unpinned;

    tests++;
    printf("  %-16s pinned + unpinned sign/verify ... ", alg);
    fflush(stdout);

    pinned = sig_roundtrip(ctx, alg, "provider=hybrid");
    if (pinned < 0) {
        printf("SKIP (unavailable)\n");
        skipped++; tests--;
        return;
    }
    unpinned = sig_roundtrip(ctx, alg, NULL);
    if (pinned == 1 && unpinned == 1) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL (pinned=%d unpinned=%d)\n", pinned, unpinned);
        ERR_print_errors_fp(stdout);
        failed++;
    }
}

/* (2) Load the provider with config params only (no .cnf) and confirm the
 * cede-to-default key is honoured at init. */
static void check_conf_params_load(const char *mods)
{
    OSSL_LIB_CTX *ctx_no = OSSL_LIB_CTX_new();
    OSSL_LIB_CTX *ctx_def = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *hyb_no = NULL, *hyb_def = NULL;
    OSSL_PARAM params[2];
    int served_no, served_def;

    tests++;
    printf("  %-16s config-params-only load (no .cnf) ... ", "cede-to-default");
    fflush(stdout);

    /* A: load with "cede-to-default=no" via the load_ex parameter array. */
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx_no, mods);
    params[0] = OSSL_PARAM_construct_utf8_string(
                    "cede-to-default", (char *)"no", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (OSSL_PROVIDER_load(ctx_no, "default") == NULL
            || (hyb_no = OSSL_PROVIDER_load_ex(ctx_no, "hybrid", params))
                   == NULL) {
        printf("FAIL (load_ex)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto end;
    }
    served_no = hybrid_serves(ctx_no, "X25519MLKEM768");

    /* B: control — plain load, cede-to-default defaults ON, so the hybrid
     * withdraws the MLX group the default provider already serves. */
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx_def, mods);
    if (OSSL_PROVIDER_load(ctx_def, "default") == NULL
            || (hyb_def = OSSL_PROVIDER_load(ctx_def, "hybrid")) == NULL) {
        printf("FAIL (control load)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto end;
    }
    served_def = hybrid_serves(ctx_def, "X25519MLKEM768");

    /* The parameter must have flipped behaviour: served with cede=no, withdrawn
     * by default. If the default build already served it, the parameter proved
     * nothing — but that would contradict the cede-to-default contract. */
    if (served_no && !served_def) {
        printf("PASS (served with cede=no param, withdrawn by default)\n");
        passed++;
    } else {
        printf("FAIL (served_no=%d served_default=%d)\n",
               served_no, served_def);
        failed++;
    }
end:
    OSSL_PROVIDER_unload(hyb_no);
    OSSL_PROVIDER_unload(hyb_def);
    OSSL_LIB_CTX_free(ctx_no);
    OSSL_LIB_CTX_free(ctx_def);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");

    /* The env override would mask the config-param test; make sure the config
     * key (not the environment) is what decides cede-to-default here. */
    unsetenv("HYBRID_CEDE_TO_DEFAULT");

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    ERR_clear_error();

    printf("cross-provider test methodology\n");
    printf("===============================\n");

    printf("[pinned vs unpinned property-query resolution]\n");
    check_dual_run(ctx, "p256_mldsa44");
    check_dual_run(ctx, "p384_mldsa65");

    printf("[programmatic config parameters, no .cnf]\n");
    check_conf_params_load(mods);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
