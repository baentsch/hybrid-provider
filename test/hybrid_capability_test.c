/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLS-GROUP code-point parity test. Our hybrid KEM code points (the
 * tls_codepoint column of HYBRID_KEM_LIST) are hand-copied from their origins:
 * the IETF draft-ietf-tls-ecdhe-mlkem code points (implemented by the default
 * provider) for the MLX groups, and oqsprovider's for the OQS-legacy groups.
 *
 * This test keeps them from drifting: it enumerates the TLS-GROUP capabilities
 * actually advertised by the default provider and oqsprovider (their live,
 * authoritative code points) and asserts our table matches, for every group an
 * origin provider advertises. Groups nobody else advertises are skipped (nothing
 * to compare against). The hybrid provider is deliberately NOT consulted -- that
 * would just echo our own table.
 *
 * OIDs need no equivalent check: a wrong OID already breaks the cross-provider
 * key-file round-trips in hybrid_encode_test / hybrid_kem_encode_test.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "hybrid_prov.h"

#define MAXG 512
static struct { char name[80]; unsigned int id; } adv[MAXG];
static int nadv;

/* Capability callback: record each advertised (name -> code point), for both
 * TLS-GROUP and TLS-SIGALG entries (different param keys, disjoint names). */
static int collect(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *pn =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
    const OSSL_PARAM *pi =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_ID);
    const char *name = NULL;
    unsigned int id = 0;

    (void)arg;
    if (pn == NULL || pi == NULL) {          /* not a group -> try a sigalg */
        pn = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME);
        pi = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT);
    }
    if (pn != NULL && pi != NULL && nadv < MAXG
        && OSSL_PARAM_get_utf8_string_ptr(pn, &name)
        && OSSL_PARAM_get_uint(pi, &id)) {
        OPENSSL_strlcpy(adv[nadv].name, name, sizeof(adv[0].name));
        adv[nadv].id = id;
        nadv++;
    }
    return 1;
}

static int origin_id(const char *name, unsigned int *id)
{
    int i;

    for (i = 0; i < nadv; i++)
        if (strcmp(adv[i].name, name) == 0) {
            *id = adv[i].id;
            return 1;
        }
    return 0;
}

/* Count how many capabilities a provider advertises (arg is an int counter). */
static int count_cb(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    ++*(int *)arg;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    OSSL_PROVIDER *dflt, *oqs;
    size_t i;
    int tests = 0, passed = 0, failed = 0, skipped = 0;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    dflt = OSSL_PROVIDER_load(ctx, "default");
    oqs = OSSL_PROVIDER_load(ctx, "oqsprovider");
    if (dflt == NULL) {
        fprintf(stderr, "cannot load default provider\n");
        return 1;
    }

    /* Collect the authoritative code points from the origin providers:
     * TLS groups from default + oqsprovider, TLS sigalgs from oqsprovider. */
    OSSL_PROVIDER_get_capabilities(dflt, "TLS-GROUP", collect, NULL);
    if (oqs != NULL) {
        OSSL_PROVIDER_get_capabilities(oqs, "TLS-GROUP", collect, NULL);
        OSSL_PROVIDER_get_capabilities(oqs, "TLS-SIGALG", collect, NULL);
    }

    printf("TLS-GROUP code-point parity vs default/oqsprovider\n");
    printf("==================================================\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const HYBRID_KEM_INFO *info = &hybrid_kem_table[i];
        unsigned int oid_cp;

        if (info->tls_codepoint == 0)
            continue;                       /* KEM-only, no TLS group */
        if (!origin_id(info->hybrid_name, &oid_cp)) {
            printf("  %-24s 0x%04x  SKIP (no origin advertises it)\n",
                   info->hybrid_name, info->tls_codepoint);
            skipped++;
            continue;
        }
        tests++;
        if ((unsigned int)info->tls_codepoint == oid_cp) {
            printf("  %-24s 0x%04x  == origin  PASS\n",
                   info->hybrid_name, oid_cp);
            passed++;
        } else {
            printf("  %-24s 0x%04x  != origin 0x%04x  FAIL\n",
                   info->hybrid_name, info->tls_codepoint, oid_cp);
            failed++;
        }
    }

    printf("\nTLS-SIGALG code-point parity vs oqsprovider\n");
    printf("===========================================\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *info = &hybrid_sig_table[i];
        unsigned int oid_cp;

        if (info->tls_codepoint == 0)
            continue;
        if (!origin_id(info->hybrid_name, &oid_cp)) {
            printf("  %-24s 0x%04x  SKIP (no origin advertises it)\n",
                   info->hybrid_name, info->tls_codepoint);
            skipped++;
            continue;
        }
        tests++;
        if ((unsigned int)info->tls_codepoint == oid_cp) {
            printf("  %-24s 0x%04x  == origin  PASS\n",
                   info->hybrid_name, oid_cp);
            passed++;
        } else {
            printf("  %-24s 0x%04x  != origin 0x%04x  FAIL\n",
                   info->hybrid_name, info->tls_codepoint, oid_cp);
            failed++;
        }
    }
    /*
     * Self-check: the hybrid provider actually advertises the sigalgs. Use a
     * fresh libctx (default + hybrid only) so this doesn't perturb `adv`.
     *
     * This test is deliberately advertisement/code-point *parity* only — it
     * guards the tls_codepoint table values against drift from the live
     * default/oqsprovider capabilities. Real functional use of those code points
     * (a group actually negotiated / a sigalg actually used for CertificateVerify
     * over a completed TLS 1.3 handshake) is covered by hybrid_tls_test and
     * hybrid_cert_tls_test.
     */
    {
        OSSL_LIB_CTX *hctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *h;
        int n = 0;

        if (mods != NULL)
            OSSL_PROVIDER_set_default_search_path(hctx, mods);
        OSSL_PROVIDER_load(hctx, "default");
        h = OSSL_PROVIDER_load(hctx, "hybrid");
        if (h != NULL)
            OSSL_PROVIDER_get_capabilities(h, "TLS-SIGALG", count_cb, &n);
        /* At least the hybrid sigalgs; more when built with the composite
         * capability (HYBRID_COMPOSITE), which advertises its own combos too. */
        tests++;
        printf("\nhybrid provider advertises %d TLS-SIGALGs (expect >= %d) ... %s\n",
               n, (int)HYBRID_SIG_ALG_COUNT,
               n >= (int)HYBRID_SIG_ALG_COUNT ? "PASS" : "FAIL");
        if (n >= (int)HYBRID_SIG_ALG_COUNT)
            passed++;
        else
            failed++;
        OSSL_LIB_CTX_free(hctx);
    }

    printf("\nResults: %d/%d matched, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
