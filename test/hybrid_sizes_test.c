/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Component-size table verifier / generator.
 *
 * The provider carries the per-component sizes of every hybrid as compile-time
 * constants (hybrid_kem_sizes[] / hybrid_sig_sizes[] in hybrid_prov.h), copied
 * into each key at construction — so there is no runtime discovery, no size
 * cache and no lock (see the concurrency-model comment in hybrid_prov.c). Those
 * constants must stay in lock-step with what the live component algorithms
 * actually produce. This test is the tripwire:
 *
 *   verify (default): for every hybrid whose components resolve in this build's
 *     providers, re-derive the sizes from live keygens (exactly as the provider
 *     once did) and assert they equal the committed constants. Rows whose
 *     components are unavailable (e.g. the oqsprovider-only families when
 *     oqsprovider is not loaded) are skipped, not failed.
 *
 *   emit  (argv[1] == "emit"): print the constant tables as C initializers, for
 *     regenerating hybrid_prov.h after adding a hybrid.
 *
 * Uses only the public EVP API and the same discovery logic the provider used,
 * so a genuine size change (new parameter set, changed private-key encoding)
 * fails CI here instead of silently corrupting a key blob.
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

/* --- discovery (mirrors the pre-constants hybrid_keymgmt.c logic) --------- */

static EVP_PKEY *ckeygen(OSSL_LIB_CTX *lc, const char *alg, const char *grp)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(lc, alg, NULL);
    EVP_PKEY *pkey = NULL;

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;
    if (grp != NULL) {
        OSSL_PARAM p[2];
        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)grp, 0);
        p[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, p) <= 0)
            goto err;
    } else if (strcmp(alg, "RSA") == 0) {
        size_t bits = 3072;
        OSSL_PARAM p[2];
        p[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits);
        p[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, p) <= 0)
            goto err;
    }
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int disc_kem(OSSL_LIB_CTX *lc, const char *alg, const char *grp,
                    int is_kem, size_t *pub, size_t *prv, size_t *ss, size_t *ct)
{
    EVP_PKEY *tmp = ckeygen(lc, alg, grp), *eph = NULL;
    EVP_PKEY_CTX *c = NULL;
    int ret = 0;

    *pub = *prv = *ss = *ct = 0;
    if (tmp == NULL)
        return 0;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, pub) <= 0)
        goto end;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, prv) <= 0) {
        int bits = EVP_PKEY_get_bits(tmp);
        ERR_clear_error();
        if (bits <= 0)
            goto end;
        *prv = (size_t)(bits + 7) / 8;
    }
    if (is_kem) {
        c = EVP_PKEY_CTX_new_from_pkey(lc, tmp, NULL);
        if (c == NULL || EVP_PKEY_encapsulate_init(c, NULL) <= 0
            || EVP_PKEY_encapsulate(c, NULL, ct, NULL, ss) <= 0)
            goto end;
    } else {
        *ct = *pub;
        c = EVP_PKEY_CTX_new_from_pkey(lc, tmp, NULL);
        if (c == NULL || EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_keygen(c, &eph) <= 0)
            goto end;
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(lc, eph, NULL);
        if (c == NULL || EVP_PKEY_derive_init(c) <= 0
            || EVP_PKEY_derive_set_peer(c, tmp) <= 0
            || EVP_PKEY_derive(c, NULL, ss) <= 0)
            goto end;
    }
    ret = 1;
end:
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(eph);
    EVP_PKEY_free(tmp);
    return ret;
}

static int disc_sig(OSSL_LIB_CTX *lc, const char *alg, const char *grp,
                    size_t *pub, size_t *prv, size_t *sig)
{
    EVP_PKEY *tmp = ckeygen(lc, alg, grp);
    int n;

    *pub = *prv = *sig = 0;
    if (tmp == NULL)
        return 0;
    n = EVP_PKEY_get_size(tmp);
    *sig = n > 0 ? (size_t)n : 0;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, pub) <= 0) {
        int dlen = i2d_PublicKey(tmp, NULL);
        *pub = dlen > 0 ? (size_t)dlen : 0;
        ERR_clear_error();
    }
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0, prv) <= 0) {
        int bits = EVP_PKEY_get_bits(tmp);
        *prv = bits > 0 ? (size_t)(bits + 7) / 8 : 0;
        ERR_clear_error();
    }
    EVP_PKEY_free(tmp);
    return *sig != 0;
}

/* --- driver --------------------------------------------------------------- */

static int fails, checked, skipped;

static void cmp(const char *name, const char *field, size_t want, size_t got)
{
    if (want != got) {
        fails++;
        printf("  FAIL %s.%s: table=%zu live=%zu\n", name, field, want, got);
    }
}

static void verify(OSSL_LIB_CTX *lc)
{
    size_t i;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const HYBRID_KEM_INFO *r = &hybrid_kem_table[i];
        const HYBRID_SIZES *t = &hybrid_kem_sizes[i];
        size_t a1p, a1v, a1s, a1c, a2p, a2v, a2s, a2c;

        if (!disc_kem(lc, r->alg1_name, r->alg1_group, r->alg1_is_kem,
                      &a1p, &a1v, &a1s, &a1c)
                || !disc_kem(lc, r->alg2_name, r->alg2_group, r->alg2_is_kem,
                             &a2p, &a2v, &a2s, &a2c)) {
            skipped++;
            ERR_clear_error();
            continue;
        }
        checked++;
        cmp(r->hybrid_name, "a1_pub", t->a1_pub, a1p);
        cmp(r->hybrid_name, "a1_prv", t->a1_prv, a1v);
        cmp(r->hybrid_name, "a1_ss",  t->a1_ss,  a1s);
        cmp(r->hybrid_name, "a1_ct",  t->a1_ct,  a1c);
        cmp(r->hybrid_name, "a2_pub", t->a2_pub, a2p);
        cmp(r->hybrid_name, "a2_prv", t->a2_prv, a2v);
        cmp(r->hybrid_name, "a2_ss",  t->a2_ss,  a2s);
        cmp(r->hybrid_name, "a2_ct",  t->a2_ct,  a2c);
    }

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];
        const HYBRID_SIZES *t = &hybrid_sig_sizes[i];
        size_t a1p, a1v, a1g, a2p, a2v, a2g;

        if (!disc_sig(lc, r->alg1_name, r->alg1_group, &a1p, &a1v, &a1g)
                || !disc_sig(lc, r->alg2_name, NULL, &a2p, &a2v, &a2g)) {
            skipped++;
            ERR_clear_error();
            continue;
        }
        checked++;
        cmp(r->hybrid_name, "a1_pub", t->a1_pub, a1p);
        cmp(r->hybrid_name, "a1_prv", t->a1_prv, a1v);
        cmp(r->hybrid_name, "a2_pub", t->a2_pub, a2p);
        cmp(r->hybrid_name, "a2_prv", t->a2_prv, a2v);
        cmp(r->hybrid_name, "a1_sig", t->a1_sig, a1g);
        cmp(r->hybrid_name, "a2_sig", t->a2_sig, a2g);
    }
}

static void emit(OSSL_LIB_CTX *lc)
{
    size_t i;

    printf("static const HYBRID_SIZES hybrid_kem_sizes[HYBRID_KEM_ALG_COUNT] = {\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const HYBRID_KEM_INFO *r = &hybrid_kem_table[i];
        size_t a1p, a1v, a1s, a1c, a2p, a2v, a2s, a2c;

        if (!disc_kem(lc, r->alg1_name, r->alg1_group, r->alg1_is_kem, &a1p, &a1v, &a1s, &a1c)
                || !disc_kem(lc, r->alg2_name, r->alg2_group, r->alg2_is_kem, &a2p, &a2v, &a2s, &a2c)) {
            printf("    { 0 },  /* %-22s UNRESOLVED */\n", r->hybrid_name);
            continue;
        }
        printf("    { %zu,%zu,%zu,%zu, %zu,%zu,%zu,%zu, 0,0 },  /* %s */\n",
               a1p, a1v, a1s, a1c, a2p, a2v, a2s, a2c, r->hybrid_name);
    }
    printf("};\n\nstatic const HYBRID_SIZES hybrid_sig_sizes[HYBRID_SIG_ALG_COUNT] = {\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];
        size_t a1p, a1v, a1g, a2p, a2v, a2g;

        if (!disc_sig(lc, r->alg1_name, r->alg1_group, &a1p, &a1v, &a1g)
                || !disc_sig(lc, r->alg2_name, NULL, &a2p, &a2v, &a2g)) {
            printf("    { 0 },  /* %-22s UNRESOLVED */\n", r->hybrid_name);
            continue;
        }
        printf("    { %zu,%zu,0,0, %zu,%zu,0,0, %zu,%zu },  /* %s */\n",
               a1p, a1v, a2p, a2v, a1g, a2g, r->hybrid_name);
    }
    printf("};\n");
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *lc = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");

    if (lc == NULL)
        return 1;
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(lc, mods);
    OSSL_PROVIDER_load(lc, "default");
    OSSL_PROVIDER_load(lc, "oqsprovider");   /* best-effort: enables the oqs-only rows */
    ERR_clear_error();

    if (argc > 1 && strcmp(argv[1], "emit") == 0) {
        emit(lc);
        OSSL_LIB_CTX_free(lc);
        return 0;
    }

    printf("component-size table verification\n");
    printf("=================================\n");
    verify(lc);
    printf("checked %d hybrids, skipped %d (components unavailable), %d mismatches\n",
           checked, skipped, fails);
    OSSL_LIB_CTX_free(lc);
    return fails == 0 ? 0 : 1;
}
