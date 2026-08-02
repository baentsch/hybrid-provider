/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provider-coexistence test (M8 drop-in contract; inverse of oqsprovider's
 * oqs_test_alg_overlap).
 *
 * oqsprovider's overlap test asserts it exposes NOTHING the default provider
 * already implements (it disables clashing algorithms). The hybrid provider
 * takes the opposite, deliberate stance for a true drop-in: it *re-advertises*
 * the same hybrid algorithm names as the default provider (the standardized MLX
 * KEM groups) and as oqsprovider (every OQS-legacy hybrid KEM/SIG), and relies
 * on property-query selection to pick the intended implementation. This is the
 * property M8 hinges on: once oqsprovider delegates its hybrid logic here, code
 * that fetches with a mandatory "provider=default", "provider=oqsprovider" or
 * "provider=hybrid" must all keep resolving to a live, correct implementation.
 * (The queries are mandatory, i.e. no "?" prefix: an optional "?provider=..."
 * clause is only a scoring preference and would fall back to another provider.)
 *
 * For every hybrid KEM and signature in the master tables this test asserts:
 *   - "?provider=hybrid" resolves to the hybrid provider;
 *   - where the default provider also implements the name (MLX KEMs on 3.5+),
 *     "?provider=default" independently resolves to default (coexistence, no
 *     clobber); where it does not (all hybrid sigs, OQS-legacy KEMs), default
 *     does not resolve it (no accidental default registration);
 *   - when oqsprovider is present, "?provider=oqsprovider" independently
 *     resolves to oqsprovider for every name it shares with us.
 *
 * Fetch-only: no keygen, so it needs no PQ base and covers the whole inventory
 * (Frodo/BIKE/HQC included) without oqsprovider. oqsprovider, when on the module
 * path, is loaded to additionally prove the hybrid<->oqs coexistence.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

static int tests, passed, failed;
#define OK(cond, ...) do { tests++; if (cond) { passed++; } \
    else { failed++; printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); \
           ERR_print_errors_fp(stdout); } } while (0)

/* Provider name backing a KEM fetch, or NULL. */
static const char *kem_prov(OSSL_LIB_CTX *ctx, const char *name, const char *q)
{
    EVP_KEM *k = EVP_KEM_fetch(ctx, name, q);
    const char *p = k ? OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(k)) : NULL;
    EVP_KEM_free(k);
    ERR_clear_error();
    return p;   /* provider name string is owned by the provider, stays valid */
}

static const char *sig_prov(OSSL_LIB_CTX *ctx, const char *name, const char *q)
{
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(ctx, name, q);
    const char *p = s ? OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(s))
                      : NULL;
    EVP_SIGNATURE_free(s);
    ERR_clear_error();
    return p;
}

static int name_is(const char *got, const char *want)
{
    return got != NULL && strcmp(got, want) == 0;
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    int have_oqs, default_has_pq, shared = 0, hybrid_only = 0;
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    have_oqs = OSSL_PROVIDER_load(ctx, "oqsprovider") != NULL;
    ERR_clear_error();

    /* Does the default provider ship PQ (ML-KEM) at all? (No on 3.4.) If so, the
     * standardized MLX groups must be the shared-with-default names below. */
    {
        EVP_KEM *k = EVP_KEM_fetch(ctx, "ML-KEM-768", "?provider=default");
        default_has_pq = (k != NULL);
        EVP_KEM_free(k);
        ERR_clear_error();
    }

    printf("hybrid <-> default/oqsprovider coexistence (M8 drop-in contract)\n");
    printf("================================================================\n");
    printf("  default PQ: %s   oqsprovider: %s\n\n",
           default_has_pq ? "yes" : "no (pre-3.5)",
           have_oqs ? "loaded" : "absent");

    /* --- KEMs --- */
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *nm = hybrid_kem_table[i].hybrid_name;
        const char *h = kem_prov(ctx, nm, "provider=hybrid");
        const char *d = kem_prov(ctx, nm, "provider=default");

        OK(name_is(h, "hybrid"), "KEM %s: ?provider=hybrid -> %s (want hybrid)",
           nm, h ? h : "(none)");
        if (d != NULL) {
            OK(name_is(d, "default"),
               "KEM %s: ?provider=default -> %s (want default)", nm, d);
            shared++;
        } else {
            hybrid_only++;
        }
        if (have_oqs) {
            const char *o = kem_prov(ctx, nm, "provider=oqsprovider");
            /* oqsprovider has the OQS-legacy/Frodo/BIKE/HQC names but NOT the
             * standardized MLX names; only assert when it resolves. */
            if (o != NULL)
                OK(name_is(o, "oqsprovider"),
                   "KEM %s: ?provider=oqsprovider -> %s", nm, o);
        }
    }

    /* --- signatures --- */
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *nm = hybrid_sig_table[i].hybrid_name;
        const char *h = sig_prov(ctx, nm, "provider=hybrid");
        const char *d = sig_prov(ctx, nm, "provider=default");

        OK(name_is(h, "hybrid"), "SIG %s: ?provider=hybrid -> %s (want hybrid)",
           nm, h ? h : "(none)");
        OK(d == NULL, "SIG %s: ?provider=default -> %s (want none; default has "
           "no hybrid sigs)", nm, d ? d : "(none)");
        if (have_oqs) {
            const char *o = sig_prov(ctx, nm, "provider=oqsprovider");
            OK(name_is(o, "oqsprovider"),
               "SIG %s: ?provider=oqsprovider -> %s (want oqsprovider)",
               nm, o ? o : "(none)");
        }
    }

    /* Sanity: if default ships PQ, the coexistence path must actually be
     * exercised (the MLX groups are shared) — not vacuously hybrid-only. */
    if (default_has_pq)
        OK(shared >= 3, "expected >=3 KEM names shared with default (MLX groups),"
           " got %d", shared);

    printf("\n  KEMs: %zu (%d shared with default, %d hybrid-only)  SIGs: %zu\n",
           (size_t)HYBRID_KEM_ALG_COUNT, shared, hybrid_only,
           (size_t)HYBRID_SIG_ALG_COUNT);
    printf("Results: %d/%d passed", passed, tests);
    if (failed)
        printf(" (%d FAILED)", failed);
    printf("\n");

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
