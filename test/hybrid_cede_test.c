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
 * list of names: for every hybrid KEM and signature it computes "does the default
 * provider serve this?" as the oracle and asserts that
 *
 *   cede OFF (interop mode):  provider=hybrid resolves it — always (coexistence);
 *   cede ON  (default):       provider=hybrid resolves it IFF the default
 *                             provider does NOT serve it (ceded otherwise).
 *
 * The oracle must mirror the provider's cede predicate exactly: the provider
 * withdraws a hybrid the default serves under ANY shared identifier — a direct
 * fetch by name, or a TLS group/sigalg advertised at the same code point, name
 * or (signatures) OID (see hybrid_probe_cede in hybrid_prov.c). A name-only
 * oracle is too narrow: OpenSSL master serves X25519+ML-KEM-512 as the TLS group
 * "MLKEM512X25519" at code point 0x11EA — the same wire group as our
 * x25519_mlkem512 (0x11EA), just a different spelling — so the provider rightly
 * cedes it by code point while a fetch of "x25519_mlkem512" against default
 * misses. So we match by code point / name / OID here too, exactly as the
 * provider does; nothing about the set is hard-coded. The lever is resolved per
 * provider init from getenv(), so the test flips the environment around each
 * load, each in its own library context.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
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

/* Flag every hybrid KEM the default provider advertises as a TLS group under the
 * same code point or name — the provider's group-cede predicate (arg: int flags
 * array over hybrid_kem_table). */
static int group_oracle_cb(const OSSL_PARAM params[], void *arg)
{
    int *flags = arg;
    const OSSL_PARAM *p;
    unsigned int id = 0;
    const char *nm = NULL;
    size_t i;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_ID)) != NULL)
        (void)OSSL_PARAM_get_uint(p, &id);
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME)) != NULL
            && p->data_type == OSSL_PARAM_UTF8_STRING)
        nm = p->data;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if ((id != 0 && (unsigned int)hybrid_kem_table[i].tls_codepoint == id)
                || (nm != NULL
                    && strcmp(nm, hybrid_kem_table[i].hybrid_name) == 0))
            flags[i] = 1;
    return 1;
}

#ifdef OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT
/* Flag every hybrid signature the default provider advertises as a TLS sigalg
 * under the same code point, name or OID — the provider's sigalg-cede predicate. */
static int sigalg_oracle_cb(const OSSL_PARAM params[], void *arg)
{
    int *flags = arg;
    const OSSL_PARAM *p;
    unsigned int cp = 0;
    const char *nm = NULL, *oid = NULL;
    size_t i;

    if ((p = OSSL_PARAM_locate_const(params,
            OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT)) != NULL)
        (void)OSSL_PARAM_get_uint(p, &cp);
    if ((p = OSSL_PARAM_locate_const(params,
            OSSL_CAPABILITY_TLS_SIGALG_NAME)) != NULL
            && p->data_type == OSSL_PARAM_UTF8_STRING)
        nm = p->data;
    if ((p = OSSL_PARAM_locate_const(params,
            OSSL_CAPABILITY_TLS_SIGALG_OID)) != NULL
            && p->data_type == OSSL_PARAM_UTF8_STRING)
        oid = p->data;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];

        if ((cp != 0 && (unsigned int)r->tls_codepoint == cp)
                || (nm != NULL && strcmp(nm, r->hybrid_name) == 0)
                || (oid != NULL && r->oid != NULL && strcmp(oid, r->oid) == 0))
            flags[i] = 1;
    }
    return 1;
}
#endif

/* Mark, via the default provider's advertised TLS capabilities, which of our
 * identifiers it serves by code point / name / OID (the fetch-by-name oracle
 * alone misses a group the default spells differently but shares a code point
 * with — see the file header). Flags are OR-ed into the per-row oracle below. */
static void probe_default_caps(OSSL_LIB_CTX *ctx, int *kem_flags, int *sig_flags)
{
    OSSL_PROVIDER *def = OSSL_PROVIDER_load(ctx, "default");

    if (def == NULL)
        return;
    (void)OSSL_PROVIDER_get_capabilities(def, "TLS-GROUP",
                                         group_oracle_cb, kem_flags);
#ifdef OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT
    (void)OSSL_PROVIDER_get_capabilities(def, "TLS-SIGALG",
                                         sigalg_oracle_cb, sig_flags);
#endif
    OSSL_PROVIDER_unload(def);
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
    int kem_cap[HYBRID_KEM_ALG_COUNT] = { 0 };
    int sig_cap[HYBRID_SIG_ALG_COUNT] = { 0 };
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
    probe_default_caps(ctx, kem_cap, sig_cap);
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *nm = hybrid_kem_table[i].hybrid_name;

        kem_in_default[i] = kem_resolves(ctx, nm, "provider=default") || kem_cap[i];
        served += kem_in_default[i];
        OK(kem_resolves(ctx, nm, "provider=hybrid"),
           "KEM %s: provider=hybrid must resolve with cede off", nm);
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *nm = hybrid_sig_table[i].hybrid_name;

        sig_in_default[i] = sig_resolves(ctx, nm, "provider=default") || sig_cap[i];
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
