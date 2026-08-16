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
#include <openssl/opensslv.h>
#include "hybrid_prov.h"

/* TLS-SIGALG capability params are OpenSSL 3.2+; on 3.0/3.1 only TLS-GROUP
 * (hybrid KEM) parity is checked. Mirrors the guard in hybrid_caps.c. */
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
# define HYBRID_HAVE_TLS_SIGALG 1
#endif

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
#ifdef HYBRID_HAVE_TLS_SIGALG
    if (pn == NULL || pi == NULL) {          /* not a group -> try a sigalg */
        pn = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME);
        pi = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT);
    }
#endif
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

/*
 * A second collector that records (name -> code point) into a caller-supplied
 * set, so the hybrid provider's OWN advertisement can be enumerated
 * independently of the origin `adv[]` above. Handles both TLS-GROUP and
 * TLS-SIGALG entries (disjoint param keys / names).
 */
typedef struct { char name[80]; unsigned int id; } ADV;
typedef struct { ADV a[MAXG]; int n; } ADVSET;

static int collect_set(const OSSL_PARAM params[], void *arg)
{
    ADVSET *s = arg;
    const OSSL_PARAM *pn =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
    const OSSL_PARAM *pi =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_ID);
    const char *name = NULL;
    unsigned int id = 0;

#ifdef HYBRID_HAVE_TLS_SIGALG
    if (pn == NULL || pi == NULL) {          /* not a group -> try a sigalg */
        pn = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME);
        pi = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT);
    }
#endif
    if (pn != NULL && pi != NULL && s->n < MAXG
        && OSSL_PARAM_get_utf8_string_ptr(pn, &name)
        && OSSL_PARAM_get_uint(pi, &id)) {
        OPENSSL_strlcpy(s->a[s->n].name, name, sizeof(s->a[0].name));
        s->a[s->n].id = id;
        s->n++;
    }
    return 1;
}

static int set_find(const ADVSET *s, const char *name, unsigned int *id)
{
    int i;

    for (i = 0; i < s->n; i++)
        if (strcmp(s->a[i].name, name) == 0) {
            if (id != NULL)
                *id = s->a[i].id;
            return 1;
        }
    return 0;
}

/* Info-table code point for a hybrid group / sigalg by name. */
static int table_group_cp(const char *name, unsigned int *cp)
{
    size_t i;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if (strcmp(name, hybrid_kem_table[i].hybrid_name) == 0) {
            *cp = (unsigned int)hybrid_kem_table[i].tls_codepoint;
            return 1;
        }
    return 0;
}

#ifdef HYBRID_HAVE_TLS_SIGALG
static int table_sig_cp(const char *name, unsigned int *cp)
{
    size_t i;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (strcmp(name, hybrid_sig_table[i].hybrid_name) == 0) {
            *cp = (unsigned int)hybrid_sig_table[i].tls_codepoint;
            return 1;
        }
    return 0;
}
#endif

/* Enumerate the hybrid provider's own advertised groups/sigalgs in `ctx`. */
static void enum_hybrid(OSSL_LIB_CTX *ctx, ADVSET *groups, ADVSET *sigs)
{
    OSSL_PROVIDER *h;

    groups->n = 0;
    sigs->n = 0;
    if ((h = OSSL_PROVIDER_load(ctx, "hybrid")) == NULL)
        return;
    OSSL_PROVIDER_get_capabilities(h, "TLS-GROUP", collect_set, groups);
#ifdef HYBRID_HAVE_TLS_SIGALG
    OSSL_PROVIDER_get_capabilities(h, "TLS-SIGALG", collect_set, sigs);
#endif
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

#ifdef HYBRID_HAVE_TLS_SIGALG
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
#endif /* HYBRID_HAVE_TLS_SIGALG */

    /*
     * Code-point provenance (issue #45): prefer IANA-assigned points, keep every
     * still-provisional point in a provisional range. The MLX groups carry the
     * IANA draft-ietf-tls-ecdhe-mlkem values; every other advertised code point
     * is inherited-provisional and must sit in oqsprovider's experimental block
     * or the TLS private-use range (never IANA-managed space, where a real
     * assignment could overrun it — cf. issue #38). Pure table check.
     */
    printf("\nCode-point provenance (IANA-assigned MLX; else provisional range)\n");
    printf("=================================================================\n");
    {
        static const struct { const char *name; unsigned int iana; } MLX[] = {
            { "X25519MLKEM768",     0x11ecu },
            { "SecP256r1MLKEM768",  0x11ebu },
            { "SecP384r1MLKEM1024", 0x11edu },
        };
        size_t m;

        for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
            const HYBRID_KEM_INFO *info = &hybrid_kem_table[i];
            unsigned int cp = (unsigned int)info->tls_codepoint;
            unsigned int iana = 0;
            int is_mlx = 0, ok;

            if (cp == 0)
                continue;
            for (m = 0; m < sizeof(MLX) / sizeof(MLX[0]); m++)
                if (strcmp(info->hybrid_name, MLX[m].name) == 0) {
                    is_mlx = 1;
                    iana = MLX[m].iana;
                }
            ok = is_mlx ? (cp == iana) : hybrid_codepoint_is_provisional(cp);
            tests++;
            printf("  %-24s 0x%04x  %-14s %s\n", info->hybrid_name, cp,
                   is_mlx ? "IANA-assigned" : "provisional",
                   ok ? "PASS" : "FAIL");
            if (ok)
                passed++;
            else
                failed++;
        }
#ifdef HYBRID_HAVE_TLS_SIGALG
        for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
            const HYBRID_SIG_INFO *info = &hybrid_sig_table[i];
            unsigned int cp = (unsigned int)info->tls_codepoint;
            int ok;

            if (cp == 0)
                continue;
            ok = hybrid_codepoint_is_provisional(cp);
            tests++;
            printf("  %-24s 0x%04x  %-14s %s\n", info->hybrid_name, cp,
                   "provisional", ok ? "PASS" : "FAIL");
            if (ok)
                passed++;
            else
                failed++;
        }
#endif
    }

    /*
     * Advertisement hygiene (issue #45): the hybrid provider must advertise
     *   (a) only operable algorithms — both components fetchable in the libctx;
     *   (b) each under its own info-table code point (so marking one
     *       not-advertisable never shifts another's point); and
     *   (c) no more than the per-enumeration cap.
     * With default+oqsprovider loaded, every component resolves, so all
     * non-zero-code-point hybrids are advertised; with default only, the
     * oqsprovider-only families (Frodo/BIKE/HQC and the OQS signatures) must be
     * dropped while the ML-KEM/ML-DSA-backed ones (components in the default
     * provider on 3.5+) stay. Cede-to-default is off here (set by CMake), so the
     * only reason to drop is (in)operability.
     */
    printf("\nAdvertisement hygiene: identity, operability, bound\n");
    printf("===================================================\n");
    {
        OSSL_LIB_CTX *actx = OSSL_LIB_CTX_new();      /* default (+oqs) + hybrid */
        OSSL_LIB_CTX *dctx = OSSL_LIB_CTX_new();      /* default + hybrid only   */
        ADVSET ag, as, dg, ds;
        int i2, oqs_present;

        if (mods != NULL) {
            OSSL_PROVIDER_set_default_search_path(actx, mods);
            OSSL_PROVIDER_set_default_search_path(dctx, mods);
        }
        OSSL_PROVIDER_load(actx, "default");
        oqs_present = (OSSL_PROVIDER_load(actx, "oqsprovider") != NULL);
        OSSL_PROVIDER_load(dctx, "default");
        enum_hybrid(actx, &ag, &as);
        enum_hybrid(dctx, &dg, &ds);

        /* (b) identity: every advertised name maps to its table code point. */
        for (i2 = 0; i2 < ag.n; i2++) {
            unsigned int tcp = 0;
            int ok = table_group_cp(ag.a[i2].name, &tcp) && tcp == ag.a[i2].id;

            tests++;
            printf("  group %-22s 0x%04x == table  %s\n",
                   ag.a[i2].name, ag.a[i2].id, ok ? "PASS" : "FAIL");
            ok ? passed++ : failed++;
        }
#ifdef HYBRID_HAVE_TLS_SIGALG
        for (i2 = 0; i2 < as.n; i2++) {
            unsigned int tcp = 0;
            /* Composite sigalgs (built with HYBRID_COMPOSITE) are not in the
             * hybrid sig table; skip those and check the hybrid ones. */
            if (!table_sig_cp(as.a[i2].name, &tcp))
                continue;
            tests++;
            printf("  sigalg %-21s 0x%04x == table  %s\n", as.a[i2].name,
                   as.a[i2].id, tcp == as.a[i2].id ? "PASS" : "FAIL");
            tcp == as.a[i2].id ? passed++ : failed++;
        }
#endif

        /* (c) bound. */
        tests++;
        printf("  advertised groups %d <= cap %d ... %s\n", ag.n,
               HYBRID_MAX_TLS_GROUPS,
               ag.n <= HYBRID_MAX_TLS_GROUPS ? "PASS" : "FAIL");
        ag.n <= HYBRID_MAX_TLS_GROUPS ? passed++ : failed++;
#ifdef HYBRID_HAVE_TLS_SIGALG
        tests++;
        printf("  advertised sigalgs %d <= cap %d ... %s\n", as.n,
               HYBRID_MAX_TLS_SIGALGS,
               as.n <= HYBRID_MAX_TLS_SIGALGS ? "PASS" : "FAIL");
        as.n <= HYBRID_MAX_TLS_SIGALGS ? passed++ : failed++;
#endif

        /* (a) operability: an oqsprovider-only group must be dropped without
         * oqsprovider and present with it; an ML-KEM-backed one is always
         * present (its components are in the default provider on 3.5+). */
        tests++;
        printf("  Frodo group dropped when oqsprovider absent ... %s\n",
               !set_find(&dg, "p256_frodo640aes", NULL) ? "PASS" : "FAIL");
        !set_find(&dg, "p256_frodo640aes", NULL) ? passed++ : failed++;

        tests++;
        printf("  BIKE group dropped when oqsprovider absent ... %s\n",
               !set_find(&dg, "p256_bikel1", NULL) ? "PASS" : "FAIL");
        !set_find(&dg, "p256_bikel1", NULL) ? passed++ : failed++;

        if (set_find(&dg, "x25519_mlkem512", NULL) || dg.n > 0) {
            tests++;
            printf("  ML-KEM group advertised with default only ... %s\n",
                   set_find(&dg, "x25519_mlkem512", NULL) ? "PASS" : "FAIL");
            set_find(&dg, "x25519_mlkem512", NULL) ? passed++ : failed++;
        }

        if (oqs_present) {
            tests++;
            printf("  Frodo group advertised with oqsprovider ... %s\n",
                   set_find(&ag, "p256_frodo640aes", NULL) ? "PASS" : "FAIL");
            set_find(&ag, "p256_frodo640aes", NULL) ? passed++ : failed++;
        } else {
            printf("  [oqsprovider absent: with-oqs advertisement checks skipped]\n");
            skipped++;
        }

#ifdef HYBRID_HAVE_TLS_SIGALG
        /* Same for signatures: an OQS-only sig (Falcon) drops without
         * oqsprovider; an ML-DSA hybrid stays (ML-DSA is in default on 3.5+). */
        tests++;
        printf("  Falcon sigalg dropped when oqsprovider absent ... %s\n",
               !set_find(&ds, "p256_falcon512", NULL) ? "PASS" : "FAIL");
        !set_find(&ds, "p256_falcon512", NULL) ? passed++ : failed++;

        if (set_find(&ds, "p256_mldsa44", NULL) || ds.n > 0) {
            tests++;
            printf("  ML-DSA sigalg advertised with default only ... %s\n",
                   set_find(&ds, "p256_mldsa44", NULL) ? "PASS" : "FAIL");
            set_find(&ds, "p256_mldsa44", NULL) ? passed++ : failed++;
        }
#endif
        OSSL_LIB_CTX_free(dctx);
        OSSL_LIB_CTX_free(actx);
    }

    printf("\nResults: %d/%d matched, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
