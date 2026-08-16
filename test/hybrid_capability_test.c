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

/*
 * Capacity of a capture set. The hybrid provider advertises at most one entry
 * per master-list row; the origin providers (default + oqsprovider) advertise
 * their full group/sigalg inventories. This is generously above the combined
 * total any of them emits, and every collector below is overflow-guarded.
 */
#define MAX_ADV 512

/* Set to 1 by a collector if a name did not fit HYBRID_ALG_NAME_MAX; main
 * asserts this stays 0, so the buffer size is proven sufficient, not assumed. */
static int g_name_overflow;

/* Copy an advertised name into `dst`, flagging (not silently truncating) any
 * name that would not fit. OPENSSL_strlcpy returns the source length. */
static void copy_name(char *dst, const char *src)
{
    if (OPENSSL_strlcpy(dst, src, HYBRID_ALG_NAME_MAX) >= HYBRID_ALG_NAME_MAX)
        g_name_overflow = 1;
}

/* Whether an algorithm resolves in `ctx` — the same provider-agnostic path the
 * provider's own operability probe uses (EVP_PKEY_CTX_new_from_name +
 * keygen_init). Lets the test independently recompute operability. */
static int comp_fetchable(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    int ok = (c != NULL && EVP_PKEY_keygen_init(c) > 0);

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

static struct { char name[HYBRID_ALG_NAME_MAX]; unsigned int id; } adv[MAX_ADV];
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
    if (pn != NULL && pi != NULL && nadv < MAX_ADV
        && OSSL_PARAM_get_utf8_string_ptr(pn, &name)
        && OSSL_PARAM_get_uint(pi, &id)) {
        copy_name(adv[nadv].name, name);
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
typedef struct { char name[HYBRID_ALG_NAME_MAX]; unsigned int id; } ADV;
typedef struct { ADV a[MAX_ADV]; int n; } ADVSET;

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
    if (pn != NULL && pi != NULL && s->n < MAX_ADV
        && OSSL_PARAM_get_utf8_string_ptr(pn, &name)
        && OSSL_PARAM_get_uint(pi, &id)) {
        copy_name(s->a[s->n].name, name);
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

/* Guarded because it is only called from the TLS-SIGALG checks (also guarded);
 * without the guard it would be an unused-function error on OpenSSL < 3.2,
 * where TLS-SIGALG capabilities do not exist. */
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

/*
 * Cross-check advertisement against operability, algorithm-agnostically: for
 * every hybrid with a TLS code point, the provider must advertise it iff both
 * components resolve in `ctx` (cede-to-default is off here, so operability is
 * the only filter). The test recomputes operability independently via
 * comp_fetchable and compares to the provider's advertised set — it iterates the
 * master tables and names no specific algorithm. One PASS/FAIL per family;
 * mismatches are printed with the offending row for diagnosis.
 */
static void check_group_operability(OSSL_LIB_CTX *ctx, const ADVSET *set,
                                     const char *label, int *tests,
                                     int *passed, int *failed)
{
    size_t i;
    int mism = 0;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const HYBRID_KEM_INFO *info = &hybrid_kem_table[i];
        int op, ad;

        if (info->tls_codepoint == 0)
            continue;               /* no TLS group -> never advertised */
        op = comp_fetchable(ctx, info->alg1_name)
            && comp_fetchable(ctx, info->alg2_name);
        ad = set_find(set, info->hybrid_name, NULL);
        if (op != ad) {
            mism++;
            printf("    MISMATCH %-24s operable=%d advertised=%d\n",
                   info->hybrid_name, op, ad);
        }
    }
    (*tests)++;
    printf("  %s groups: advertised == operable ... %s\n",
           label, mism == 0 ? "PASS" : "FAIL");
    if (mism == 0)
        (*passed)++;
    else
        (*failed)++;
}

#ifdef HYBRID_HAVE_TLS_SIGALG
static int comp_group_fetchable_for_sig(OSSL_LIB_CTX *ctx,
                                        const HYBRID_SIG_INFO *info)
{
    return comp_fetchable(ctx, info->alg1_name)
        && comp_fetchable(ctx, info->alg2_name);
}

static void check_sig_operability(OSSL_LIB_CTX *ctx, const ADVSET *set,
                                   const char *label, int *tests,
                                   int *passed, int *failed)
{
    size_t i;
    int mism = 0;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *info = &hybrid_sig_table[i];
        int op, ad;

        if (info->tls_codepoint == 0)
            continue;
        op = comp_group_fetchable_for_sig(ctx, info);
        ad = set_find(set, info->hybrid_name, NULL);
        if (op != ad) {
            mism++;
            printf("    MISMATCH %-24s operable=%d advertised=%d\n",
                   info->hybrid_name, op, ad);
        }
    }
    (*tests)++;
    printf("  %s sigalgs: advertised == operable ... %s\n",
           label, mism == 0 ? "PASS" : "FAIL");
    if (mism == 0)
        (*passed)++;
    else
        (*failed)++;
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
     * Code-point provenance (issue #45): every non-zero code point must be
     * classifiable by VALUE — either the IANA-assigned ML-KEM-hybrid span
     * (draft-ietf-tls-ecdhe-mlkem) or a provisional range (oqsprovider's
     * experimental block / TLS private-use). Anything else means a value was
     * invented in IANA-managed space, where a real assignment could overrun it
     * (cf. issue #38). No algorithm names appear — the classifier is on the
     * integer value alone (see hybrid_codepoint_is_* in hybrid_prov.h).
     */
    printf("\nCode-point provenance (IANA-assigned span or provisional range)\n");
    printf("===============================================================\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        unsigned int cp = (unsigned int)hybrid_kem_table[i].tls_codepoint;
        int ok;

        if (cp == 0)
            continue;
        ok = hybrid_codepoint_is_iana_assigned(cp)
            || hybrid_codepoint_is_provisional(cp);
        tests++;
        printf("  %-24s 0x%04x  %-13s %s\n", hybrid_kem_table[i].hybrid_name, cp,
               hybrid_codepoint_is_iana_assigned(cp) ? "IANA-assigned"
                                                     : "provisional",
               ok ? "PASS" : "FAIL");
        if (ok)
            passed++;
        else
            failed++;
    }
#ifdef HYBRID_HAVE_TLS_SIGALG
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        unsigned int cp = (unsigned int)hybrid_sig_table[i].tls_codepoint;
        int ok;

        if (cp == 0)
            continue;
        ok = hybrid_codepoint_is_iana_assigned(cp)
            || hybrid_codepoint_is_provisional(cp);
        tests++;
        printf("  %-24s 0x%04x  %-13s %s\n", hybrid_sig_table[i].hybrid_name, cp,
               hybrid_codepoint_is_iana_assigned(cp) ? "IANA-assigned"
                                                     : "provisional",
               ok ? "PASS" : "FAIL");
        if (ok)
            passed++;
        else
            failed++;
    }
#endif

    /*
     * Advertisement hygiene (issue #45): the hybrid provider must advertise
     *   (a) only operable algorithms — both components fetchable in the libctx —
     *       cross-checked against an independent probe in TWO contexts (with and
     *       without oqsprovider) so the with/without-component split is exercised
     *       generically, not against a hand-picked algorithm;
     *   (b) each under its own info-table code point (so marking one
     *       not-advertisable never shifts another's point); and
     *   (c) no more than the per-enumeration cap (the master-list size).
     * Cede-to-default is off here (set by CMake), so operability is the only
     * reason a non-zero-code-point hybrid is dropped.
     */
    printf("\nAdvertisement hygiene: identity, operability, bound\n");
    printf("===================================================\n");
    {
        OSSL_LIB_CTX *actx = OSSL_LIB_CTX_new();      /* default (+oqs) + hybrid */
        OSSL_LIB_CTX *dctx = OSSL_LIB_CTX_new();      /* default + hybrid only   */
        ADVSET ag, as, dg, ds;
        int i2;

        if (mods != NULL) {
            OSSL_PROVIDER_set_default_search_path(actx, mods);
            OSSL_PROVIDER_set_default_search_path(dctx, mods);
        }
        OSSL_PROVIDER_load(actx, "default");
        OSSL_PROVIDER_load(actx, "oqsprovider");     /* may be absent; that's fine */
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
            if (ok)
                passed++;
            else
                failed++;
        }
#ifdef HYBRID_HAVE_TLS_SIGALG
        for (i2 = 0; i2 < as.n; i2++) {
            unsigned int tcp = 0;
            int ok;

            /* Composite sigalgs (built with HYBRID_COMPOSITE) are not in the
             * hybrid sig table; skip those and check the hybrid ones. */
            if (!table_sig_cp(as.a[i2].name, &tcp))
                continue;
            ok = (tcp == as.a[i2].id);
            tests++;
            printf("  sigalg %-21s 0x%04x == table  %s\n", as.a[i2].name,
                   as.a[i2].id, ok ? "PASS" : "FAIL");
            if (ok)
                passed++;
            else
                failed++;
        }
#endif

        /* (c) bound: the count never exceeds the master-list size. */
        tests++;
        printf("  advertised groups %d <= cap %d ... %s\n", ag.n,
               (int)HYBRID_MAX_TLS_GROUPS,
               ag.n <= (int)HYBRID_MAX_TLS_GROUPS ? "PASS" : "FAIL");
        if (ag.n <= (int)HYBRID_MAX_TLS_GROUPS)
            passed++;
        else
            failed++;
#ifdef HYBRID_HAVE_TLS_SIGALG
        {
            /* HYBRID_MAX_TLS_SIGALGS bounds the hybrid family only; the composite
             * family (built with HYBRID_COMPOSITE) is advertised into the same
             * TLS-SIGALG enumeration but is bounded by its own master list. So
             * count just the advertised sigalgs that belong to the hybrid table. */
            int n_hybrid = 0;
            unsigned int tcp;

            for (i2 = 0; i2 < as.n; i2++)
                if (table_sig_cp(as.a[i2].name, &tcp))
                    n_hybrid++;
            tests++;
            printf("  advertised hybrid sigalgs %d <= cap %d ... %s\n", n_hybrid,
                   (int)HYBRID_MAX_TLS_SIGALGS,
                   n_hybrid <= (int)HYBRID_MAX_TLS_SIGALGS ? "PASS" : "FAIL");
            if (n_hybrid <= (int)HYBRID_MAX_TLS_SIGALGS)
                passed++;
            else
                failed++;
        }
#endif

        /* (a) operability: advertisement == independently-probed operability, in
         * both contexts. Whether oqsprovider is present or not, the two must
         * agree for every row — no specific algorithm is assumed present. */
        check_group_operability(actx, &ag, "default+oqs", &tests, &passed, &failed);
        check_group_operability(dctx, &dg, "default-only", &tests, &passed, &failed);
#ifdef HYBRID_HAVE_TLS_SIGALG
        check_sig_operability(actx, &as, "default+oqs", &tests, &passed, &failed);
        check_sig_operability(dctx, &ds, "default-only", &tests, &passed, &failed);
#endif
        OSSL_LIB_CTX_free(dctx);
        OSSL_LIB_CTX_free(actx);
    }

    /* Buffer-safety: no advertised name was truncated into the capture buffers,
     * proving HYBRID_ALG_NAME_MAX is sufficient rather than assuming it. */
    tests++;
    printf("\nName buffers fit every advertised name (HYBRID_ALG_NAME_MAX=%d) ... %s\n",
           HYBRID_ALG_NAME_MAX, g_name_overflow == 0 ? "PASS" : "FAIL");
    if (g_name_overflow == 0)
        passed++;
    else
        failed++;

    printf("\nResults: %d/%d matched, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
