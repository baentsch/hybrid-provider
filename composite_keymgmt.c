/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) key management (issue #6). Each composite key holds a PQ
 * component + a classical component as EVP_PKEYs; keygen generates both via the
 * public EVP API (PQ from {oqsprovider|default} by tier, classical from default).
 *
 * First slice: keygen + descriptor params only (enough for EVP sign/verify). The
 * empty mandatory-digest advertises the one-shot contract so DigestSign/CMS pick
 * the one-shot path — same convention as the hybrid family. Import/export and the
 * DER encoders/decoders (for serialization + Bouncy Castle interop) follow.
 */
#include "composite_prov.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

/* --- lifecycle --- */

static void *composite_key_new(void *provctx, const COMPOSITE_SIG_INFO *info)
{
    COMPOSITE_PROV_CTX *pc = provctx;
    COMPOSITE_KEY *k = OPENSSL_zalloc(sizeof(*k));

    if (k == NULL)
        return NULL;
    k->libctx = pc != NULL ? pc->libctx : NULL;
    k->info = info;
    /* Tier-based component sourcing (config-overridable later): standardized
     * ML-DSA from the default provider, experimental research sigs from
     * oqsprovider; classical always from default. */
    k->pq_propq = info->tier == COMPOSITE_TIER_EXPERIMENTAL
                      ? "provider=oqsprovider" : "provider=default";
    k->trad_propq = "provider=default";
    k->state = COMPOSITE_HAVE_NOKEYS;
    return k;
}

static void composite_key_free(void *vkey)
{
    COMPOSITE_KEY *k = vkey;

    if (k == NULL)
        return;
    EVP_PKEY_free(k->pq_key);
    EVP_PKEY_free(k->trad_key);
    OPENSSL_free(k);
}

static int composite_key_has(const void *vkey, int selection)
{
    const COMPOSITE_KEY *k = vkey;

    if (k == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return k->state >= COMPOSITE_HAVE_PRVKEY;
    if ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                      | OSSL_KEYMGMT_SELECT_KEYPAIR)) != 0)
        return k->state >= COMPOSITE_HAVE_PUBKEY;
    return 1;
}

/* --- get_params / gettable_params --- */

static const OSSL_PARAM *composite_gettable_params(void *provctx)
{
    static const OSSL_PARAM tbl[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
        OSSL_PARAM_END
    };
    return tbl;
}

static int composite_get_params(void *vkey, OSSL_PARAM params[])
{
    COMPOSITE_KEY *k = vkey;
    OSSL_PARAM *p;

    if (k == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        int mx = 0;

        if (k->pq_key != NULL)
            mx += EVP_PKEY_get_size(k->pq_key);
        if (k->trad_key != NULL)
            mx += EVP_PKEY_get_size(k->trad_key);
        if (!OSSL_PARAM_set_int(p, mx))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 128))
        return 0;
    /* One-shot signer: empty mandatory digest -> "UNDEF" (see hybrid family). */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;
    return 1;
}

/* --- keygen --- */

typedef struct {
    void *provctx;
    const COMPOSITE_SIG_INFO *info;
} COMPOSITE_GEN_CTX;

static EVP_PKEY *gen_trad(OSSL_LIB_CTX *libctx, const COMPOSITE_SIG_INFO *info)
{
    const char *p = "provider=default";

    if (strcmp(info->trad_alg, "EC") == 0)
        return EVP_PKEY_Q_keygen(libctx, p, "EC", info->trad_group);
    if (strcmp(info->trad_alg, "ED25519") == 0
            || strcmp(info->trad_alg, "ED448") == 0)
        return EVP_PKEY_Q_keygen(libctx, p, info->trad_alg);
    /* RSA / RSA-PSS: a plain 3072-bit RSA key; PSS applied at signing time. */
    return EVP_PKEY_Q_keygen(libctx, p, "RSA", (size_t)3072);
}

static void *composite_gen_init_info(void *provctx,
                                     const COMPOSITE_SIG_INFO *info)
{
    COMPOSITE_GEN_CTX *g = OPENSSL_zalloc(sizeof(*g));

    if (g != NULL) {
        g->provctx = provctx;
        g->info = info;
    }
    return g;
}

static void *composite_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    COMPOSITE_GEN_CTX *g = vgctx;
    COMPOSITE_KEY *k = composite_key_new(g->provctx, g->info);
    EVP_PKEY_CTX *pctx = NULL;

    if (k == NULL)
        return NULL;
    pctx = EVP_PKEY_CTX_new_from_name(k->libctx, g->info->pq_alg, k->pq_propq);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0
            || EVP_PKEY_keygen(pctx, &k->pq_key) <= 0)
        goto err;
    EVP_PKEY_CTX_free(pctx);
    if ((k->trad_key = gen_trad(k->libctx, g->info)) == NULL)
        goto err2;
    k->state = COMPOSITE_HAVE_PRVKEY;
    return k;
err:
    EVP_PKEY_CTX_free(pctx);
err2:
    composite_key_free(k);
    return NULL;
}

static void composite_gen_cleanup(void *vgctx)
{
    OPENSSL_free(vgctx);
}

static int composite_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM *composite_gen_settable_params(void *vgctx,
                                                       void *provctx)
{
    static const OSSL_PARAM tbl[] = { OSSL_PARAM_END };
    return tbl;
}

/*
 * Per-algorithm keymgmt instances — generated from the master list, each binding
 * its NEW/GEN_INIT to the matching info-table row (the hybrid family's pattern).
 */
#define DECLARE_COMPOSITE_KMGMT(cf, idx)                                       \
    static void *composite_##cf##_new(void *provctx)                          \
    {                                                                          \
        return composite_key_new(provctx, &composite_sig_table[idx]);         \
    }                                                                          \
    static void *composite_##cf##_gen_init(void *provctx, int selection,      \
                                           const OSSL_PARAM params[])          \
    {                                                                          \
        return composite_gen_init_info(provctx, &composite_sig_table[idx]);   \
    }                                                                          \
    const OSSL_DISPATCH composite_##cf##_kmgmt_functions[] = {                 \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))composite_##cf##_new },       \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))composite_key_free },        \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))composite_key_has },          \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                        \
          (void (*)(void))composite_get_params },                             \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                   \
          (void (*)(void))composite_gettable_params },                        \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,                                          \
          (void (*)(void))composite_##cf##_gen_init },                        \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))composite_gen },              \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                       \
          (void (*)(void))composite_gen_cleanup },                            \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                    \
          (void (*)(void))composite_gen_set_params },                         \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                               \
          (void (*)(void))composite_gen_settable_params },                    \
        { 0, NULL }                                                            \
    }

#define COMPOSITE_KMGMT_ROW(cf, ...) \
    DECLARE_COMPOSITE_KMGMT(cf, COMPOSITE_SIG_IDX_##cf);
COMPOSITE_SIG_LIST(COMPOSITE_KMGMT_ROW)
#undef COMPOSITE_KMGMT_ROW
