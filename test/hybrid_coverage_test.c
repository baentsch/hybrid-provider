/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Coverage guard: every hybrid algorithm an *origin* provider advertises MUST
 * also be served by the hybrid provider (i.e. present in HYBRID_KEM_LIST /
 * HYBRID_SIG_LIST). Two origins are scanned:
 *
 *   - oqsprovider: its hybrid KEMs and signatures (the classical+PQ families).
 *   - the OpenSSL default provider: its built-in MLX hybrid KEMs. This is the
 *     safety net for OpenSSL growing the standardized MLX family — it is exactly
 *     what would have caught curveSM2MLKEM768 (added in OpenSSL 4.0) earlier
 *     (issue #116).
 *
 * This is the inverse of hybrid_matrix_test. The matrix test iterates OUR
 * master tables and crosses each entry against oqsprovider, so it can only
 * check what we already list — a family missing from the tables is invisible
 * to it (exactly how the eFrodoKEM hybrids stayed absent from M6 until #25).
 * This test iterates an ORIGIN provider's advertised algorithms instead and
 * fails if any hybrid name is not in our tables, so a future upstream hybrid
 * family we forget to mirror breaks CI immediately.
 *
 * "Hybrid" is recognised structurally, so no name list needs hand-maintaining:
 *   - oqsprovider hybrids carry a classical <curve>_/<rsa>_ prefix (the same way
 *     oqsprovider's own OQS_CEDE_HYBRIDS lever classifies them); and
 *   - standardized MLX hybrids (X25519MLKEM768, …, curveSM2MLKEM768) have a name
 *     that embeds "MLKEM" but is not the bare ML-KEM primitive itself.
 * No standalone PQ or classical algorithm matches either rule.
 *
 * The oqsprovider scan is skipped wholesale when oqsprovider is unavailable; the
 * default-provider scan always runs.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include "hybrid_prov.h"

#define NELEM(x) (sizeof(x) / sizeof((x)[0]))

/* Classical prefixes that mark an oqsprovider hybrid (KEM or signature). */
static const char *const hybrid_prefixes[] = {
    "p256_",  "p384_",  "p521_",   "x25519_",
    "x448_",  "bp256_", "bp384_",  "bp512_", "rsa3072_"};

/* Case-insensitive substring test (needle assumed non-empty). */
static int contains_ci(const char *hay, const char *needle)
{
    size_t nlen = strlen(needle);

    for (; *hay != '\0'; hay++)
        if (OPENSSL_strncasecmp(hay, needle, nlen) == 0)
            return 1;
    return 0;
}

/* The bare ML-KEM primitive, in the spellings the default provider
 * ("ML-KEM-768") and oqsprovider ("mlkem768") use — NOT hybrids. */
static int is_bare_mlkem(const char *name)
{
    static const char *const bare[] = {
        "mlkem512",   "mlkem768",   "mlkem1024",
        "ml-kem-512", "ml-kem-768", "ml-kem-1024"};
    size_t i;

    for (i = 0; i < NELEM(bare); i++)
        if (OPENSSL_strcasecmp(name, bare[i]) == 0)
            return 1;
    return 0;
}

/* A standardized MLX hybrid: embeds "MLKEM" but is not the bare primitive. This
 * matches every default-provider MLX group (X25519MLKEM768, SecP256r1MLKEM768,
 * X448MLKEM1024, SecP384r1MLKEM1024 and, on OpenSSL 4.0+, curveSM2MLKEM768)
 * without a hand-maintained name list. */
static int is_mlx_hybrid_name(const char *name)
{
    return !is_bare_mlkem(name) && contains_ci(name, "MLKEM");
}

static int is_hybrid_name(const char *name)
{
    size_t i;

    for (i = 0; i < NELEM(hybrid_prefixes); i++)
        if (strncmp(name, hybrid_prefixes[i], strlen(hybrid_prefixes[i])) == 0)
            return 1;
    return is_mlx_hybrid_name(name);
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

/* Per-scan state threaded through the enumeration callbacks. */
struct scan {
    const char *op;                 /* "KEM" or "SIG", for messages */
    const char *src;                /* origin provider name, for messages */
    int (*in_table)(const char *);  /* our-table membership predicate */
    int (*is_hybrid)(const char *); /* which names this origin can offer */
    int checked;                    /* origin hybrid names inspected */
    int missing;                    /* those absent from our table */
};

static int prov_is(const OSSL_PROVIDER *prov, const char *name)
{
    return prov != NULL
           && strcmp(OSSL_PROVIDER_get0_name(prov), name) == 0;
}

static void name_cb(const char *name, void *arg)
{
    struct scan *s = arg;

    if (!s->is_hybrid(name))
        return;
    s->checked++;
    if (s->in_table(name)) {
        printf("  ok:      %-24s served by hybrid provider\n", name);
    } else {
        printf("  MISSING: %-24s advertised by %s, absent from HYBRID_%s_LIST\n",
               name, s->src, strcmp(s->op, "KEM") == 0 ? "KEM" : "SIG");
        s->missing++;
    }
}

static void oqs_kem_cb(EVP_KEM *kem, void *arg)
{
    if (prov_is(EVP_KEM_get0_provider(kem), "oqsprovider"))
        EVP_KEM_names_do_all(kem, name_cb, arg);
}

static void oqs_sig_cb(EVP_SIGNATURE *sig, void *arg)
{
    if (prov_is(EVP_SIGNATURE_get0_provider(sig), "oqsprovider"))
        EVP_SIGNATURE_names_do_all(sig, name_cb, arg);
}

static void dflt_kem_cb(EVP_KEM *kem, void *arg)
{
    if (prov_is(EVP_KEM_get0_provider(kem), "default"))
        EVP_KEM_names_do_all(kem, name_cb, arg);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    /* The default provider offers only MLX hybrids, never the oqs-prefixed
     * ones, so it is scanned with the narrower is_mlx_hybrid_name predicate. */
    struct scan dflt_kem = {"KEM", "default provider", in_kem_table,
                            is_mlx_hybrid_name, 0, 0};
    struct scan oqs_kem = {"KEM", "oqsprovider", in_kem_table,
                           is_hybrid_name, 0, 0};
    struct scan oqs_sig = {"SIG", "oqsprovider", in_sig_table,
                           is_hybrid_name, 0, 0};
    int missing;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }

    printf("default-provider MLX coverage guard\n");
    printf("===================================\n");
    EVP_KEM_do_all_provided(ctx, dflt_kem_cb, &dflt_kem);
    printf("Checked %d default-provider MLX hybrid names; %d missing.\n\n",
           dflt_kem.checked, dflt_kem.missing);

    missing = dflt_kem.missing;

    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING oqsprovider coverage guard\n");
    } else {
        printf("oqsprovider hybrid coverage guard\n");
        printf("=================================\n");
        EVP_KEM_do_all_provided(ctx, oqs_kem_cb, &oqs_kem);
        EVP_SIGNATURE_do_all_provided(ctx, oqs_sig_cb, &oqs_sig);
        printf("\nChecked %d KEM + %d SIG oqsprovider hybrid names; "
               "%d missing from our tables.\n",
               oqs_kem.checked, oqs_sig.checked,
               oqs_kem.missing + oqs_sig.missing);
        missing += oqs_kem.missing + oqs_sig.missing;
    }

    OSSL_LIB_CTX_free(ctx);
    return missing == 0 ? 0 : 1;
}
