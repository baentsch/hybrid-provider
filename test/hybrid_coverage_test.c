/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Coverage guard: every hybrid algorithm oqsprovider advertises MUST also be
 * served by the hybrid provider (i.e. present in HYBRID_KEM_LIST /
 * HYBRID_SIG_LIST).
 *
 * This is the inverse of hybrid_matrix_test. The matrix test iterates OUR
 * master tables and crosses each entry against oqsprovider, so it can only
 * check what we already list — a family missing from the tables is invisible
 * to it (exactly how the eFrodoKEM hybrids stayed absent from M6 until #25).
 * This test iterates OQSPROVIDER's advertised algorithms instead and fails if
 * any hybrid name is not in our tables, so a future oqsprovider hybrid family
 * that we forget to mirror breaks CI immediately.
 *
 * "Hybrid" is recognised structurally, the same way oqsprovider's own cede
 * lever (OQS_CEDE_HYBRIDS) classifies them: a name is a hybrid iff it carries a
 * classical <curve>_/<rsa>_ prefix or is one of the standardised MLX names. No
 * standalone PQ or classical algorithm carries such a prefix. If that cede set
 * ever changes, keep this list in sync.
 *
 * Skipped wholesale when oqsprovider is unavailable.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include "hybrid_prov.h"

#define NELEM(x) (sizeof(x) / sizeof((x)[0]))

/* Classical prefixes that mark an oqsprovider hybrid (KEM or signature). */
static const char *const hybrid_prefixes[] = {
    "p256_",  "p384_",  "p521_",   "x25519_",
    "x448_",  "bp256_", "bp384_",  "bp512_", "rsa3072_"};
/* Standardised MLX KEM names have no classical prefix but are hybrids. */
static const char *const hybrid_standard_names[] = {
    "X25519MLKEM768", "SecP256r1MLKEM768", "X448MLKEM1024",
    "SecP384r1MLKEM1024"};

static int is_hybrid_name(const char *name)
{
    size_t i;

    for (i = 0; i < NELEM(hybrid_prefixes); i++)
        if (strncmp(name, hybrid_prefixes[i], strlen(hybrid_prefixes[i])) == 0)
            return 1;
    for (i = 0; i < NELEM(hybrid_standard_names); i++)
        if (strcmp(name, hybrid_standard_names[i]) == 0)
            return 1;
    return 0;
}

static int in_kem_table(const char *name)
{
    size_t i;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if (strcmp(name, hybrid_kem_table[i].hybrid_name) == 0)
            return 1;
    return 0;
}

static int in_sig_table(const char *name)
{
    size_t i;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (strcmp(name, hybrid_sig_table[i].hybrid_name) == 0)
            return 1;
    return 0;
}

/* Per-operation state threaded through the enumeration callbacks. */
struct scan {
    const char *op;                 /* "KEM" or "SIG", for messages */
    int (*in_table)(const char *);  /* our-table membership predicate */
    int checked;                    /* oqsprovider hybrid names inspected */
    int missing;                    /* those absent from our table */
};

static int is_oqsprovider(const OSSL_PROVIDER *prov)
{
    return prov != NULL
           && strcmp(OSSL_PROVIDER_get0_name(prov), "oqsprovider") == 0;
}

static void name_cb(const char *name, void *arg)
{
    struct scan *s = arg;

    if (!is_hybrid_name(name))
        return;
    s->checked++;
    if (s->in_table(name)) {
        printf("  ok:      %-24s served by hybrid provider\n", name);
    } else {
        printf("  MISSING: %-24s advertised by oqsprovider, absent from "
               "HYBRID_%s_LIST\n",
               name, strcmp(s->op, "KEM") == 0 ? "KEM" : "SIG");
        s->missing++;
    }
}

static void kem_cb(EVP_KEM *kem, void *arg)
{
    if (is_oqsprovider(EVP_KEM_get0_provider(kem)))
        EVP_KEM_names_do_all(kem, name_cb, arg);
}

static void sig_cb(EVP_SIGNATURE *sig, void *arg)
{
    if (is_oqsprovider(EVP_SIGNATURE_get0_provider(sig)))
        EVP_SIGNATURE_names_do_all(sig, name_cb, arg);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    struct scan kem = {"KEM", in_kem_table, 0, 0};
    struct scan sig = {"SIG", in_sig_table, 0, 0};

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING coverage guard\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }

    printf("oqsprovider hybrid coverage guard\n");
    printf("=================================\n");
    EVP_KEM_do_all_provided(ctx, kem_cb, &kem);
    EVP_SIGNATURE_do_all_provided(ctx, sig_cb, &sig);

    printf("\nChecked %d KEM + %d SIG oqsprovider hybrid names; "
           "%d missing from our tables.\n",
           kem.checked, sig.checked, kem.missing + sig.missing);

    OSSL_LIB_CTX_free(ctx);
    return (kem.missing + sig.missing) == 0 ? 0 : 1;
}
