/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cede-to-default test.
 *
 * Some of this provider's algorithms are also provided by the OpenSSL default
 * provider; they exist here only so the two can be compared for
 * interoperability, so in real operation the provider WITHDRAWS whatever the
 * default provider already serves in the same library context — from both the
 * algorithm query tables and the TLS capabilities. This is the default; it is
 * switchable off (env var HYBRID_CEDE_TO_DEFAULT=0 or config key
 * "cede-to-default = no") for the interop suite, which deliberately compares the
 * two implementations.
 *
 * The test is table-driven over the whole master inventory rather than a fixed
 * list of names: for every hybrid KEM and signature it takes "does the default
 * provider resolve this name?" as the oracle and asserts that
 *
 *   cede OFF (interop mode):  provider=hybrid resolves it — always (coexistence);
 *   cede ON  (default):       provider=hybrid resolves it IFF the default
 *                             provider does NOT serve it (ceded otherwise).
 *
 * So whatever the running default provider happens to serve (today, the
 * standardized MLX KEM groups; more on a future OpenSSL) is what gets ceded —
 * nothing about the set is hard-coded here. The lever is resolved per provider
 * init from getenv(), so the test flips the environment around each load, each
 * in its own library context.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

static int tests, passed, failed;
#define OK(cond, ...) do { tests++; if (cond) { passed++; } \
    else { failed++; printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); \
           ERR_print_errors_fp(stdout); } } while (0)

static int kem_resolves(OSSL_LIB_CTX *ctx, const char *name, const char *prov)
{
    EVP_KEM *k = EVP_KEM_fetch(ctx, name, prov);
    int r = (k != NULL);
    EVP_KEM_free(k);
    ERR_clear_error();
    return r;
}

static int sig_resolves(OSSL_LIB_CTX *ctx, const char *name, const char *prov)
{
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(ctx, name, prov);
    int r = (s != NULL);
    EVP_SIGNATURE_free(s);
    ERR_clear_error();
    return r;
}

/* Load default + hybrid into a fresh libctx with the cede lever forced to
 * `cede` (via HYBRID_CEDE_TO_DEFAULT, read at hybrid init). Caller frees ctx. */
static OSSL_LIB_CTX *load(const char *mods, int cede)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    setenv("HYBRID_CEDE_TO_DEFAULT", cede ? "1" : "0", 1);
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        OSSL_LIB_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

int main(void)
{
    const char *mods = getenv("OPENSSL_MODULES");
    int kem_in_default[HYBRID_KEM_ALG_COUNT];
    int sig_in_default[HYBRID_SIG_ALG_COUNT];
    int served = 0;
    OSSL_LIB_CTX *ctx;
    size_t i;

    printf("cede-to-default (table-driven over the whole inventory)\n");
    printf("================================================================\n");

    /* Phase 1 — cede OFF (coexistence): hybrid serves its whole inventory, and
     * we record which names the default provider also serves (the oracle). The
     * cede state is process-global, so this instance is fully torn down before
     * phase 2 loads a fresh one with ceding on. */
    if ((ctx = load(mods, 0)) == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *nm = hybrid_kem_table[i].hybrid_name;

        kem_in_default[i] = kem_resolves(ctx, nm, "provider=default");
        served += kem_in_default[i];
        OK(kem_resolves(ctx, nm, "provider=hybrid"),
           "KEM %s: provider=hybrid must resolve with cede off", nm);
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *nm = hybrid_sig_table[i].hybrid_name;

        sig_in_default[i] = sig_resolves(ctx, nm, "provider=default");
        served += sig_in_default[i];
        OK(sig_resolves(ctx, nm, "provider=hybrid"),
           "SIG %s: provider=hybrid must resolve with cede off", nm);
    }
    OSSL_LIB_CTX_free(ctx);

    /* Phase 2 — cede ON (default): hybrid serves a name IFF the default provider
     * does not (i.e. it withdraws exactly what phase 1 found default serving). */
    if ((ctx = load(mods, 1)) == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers (cede on)\n");
        return 1;
    }
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *nm = hybrid_kem_table[i].hybrid_name;

        OK(kem_resolves(ctx, nm, "provider=hybrid") == !kem_in_default[i],
           "KEM %s: with cede on, hybrid should %sresolve (default %s serve it)",
           nm, kem_in_default[i] ? "NOT " : "",
           kem_in_default[i] ? "does" : "does not");
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *nm = hybrid_sig_table[i].hybrid_name;

        OK(sig_resolves(ctx, nm, "provider=hybrid") == !sig_in_default[i],
           "SIG %s: with cede on, hybrid should %sresolve (default %s serve it)",
           nm, sig_in_default[i] ? "NOT " : "",
           sig_in_default[i] ? "does" : "does not");
    }
    OSSL_LIB_CTX_free(ctx);

    printf("\n  default serves %d of our identifiers -> %d ceded, %zu retained\n",
           served, served, (HYBRID_KEM_ALG_COUNT + HYBRID_SIG_ALG_COUNT) - served);
    printf("Results: %d/%d passed", passed, tests);
    if (failed)
        printf(" (%d FAILED)", failed);
    printf("\n");
    return failed == 0 ? 0 : 1;
}
