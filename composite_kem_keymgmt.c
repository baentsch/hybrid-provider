/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM key management — the KEM analogue of
 * composite_keymgmt.c. Each key holds an ML-KEM component + a classical
 * component as EVP_PKEYs; keygen generates both via the public EVP API, each half
 * sourced from whichever provider the config selects. The ML-KEM private key is
 * serialized as its 64-byte seed (draft-18 §4.2); the classical component is EC
 * (uncompressed point), X25519/X448 (raw octets) or RSA (for the RSA-OAEP combos).
 */
#include "composite_kem_prov.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <string.h>

static int trad_is_raw(const COMPOSITE_KEM_INFO *info)   /* X25519 / X448 */
{
    return strcmp(info->trad_alg, "X25519") == 0
        || strcmp(info->trad_alg, "X448") == 0;
}

static int trad_is_rsa(const COMPOSITE_KEM_INFO *info)
{
    return strcmp(info->trad_alg, "RSA-OAEP") == 0;
}

/* --- lifecycle --- */

static void *composite_kem_key_new(void *provctx, const COMPOSITE_KEM_INFO *info)
{
    HYBRID_PROV_CTX *pc = provctx;
    COMPOSITE_KEM_KEY *k = OPENSSL_zalloc(sizeof(*k));

    if (k == NULL)
        return NULL;
    k->libctx = pc != NULL ? pc->libctx : NULL;
    k->info = info;
    /* Config-driven component sourcing (shared with the hybrid family). Absent
     * config, both halves resolve from the default provider: the ML-KEM seed API
     * and the classical algorithms all live there on 3.5+. */
    k->pq_propq = pc != NULL && pc->pq_propq != NULL
                      ? pc->pq_propq : "provider=default";
    k->trad_propq = pc != NULL && pc->classic_propq != NULL
                        ? pc->classic_propq : "provider=default";
    k->state = COMPOSITE_KEM_HAVE_NOKEYS;
    return k;
}

static void composite_kem_key_free_(void *vkey)
{
    COMPOSITE_KEM_KEY *k = vkey;

    if (k == NULL)
        return;
    EVP_PKEY_free(k->pq_key);
    EVP_PKEY_free(k->trad_key);
    OPENSSL_free(k);
}

static int composite_kem_key_has(const void *vkey, int selection)
{
    const COMPOSITE_KEM_KEY *k = vkey;

    if (k == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return k->state >= COMPOSITE_KEM_HAVE_PRVKEY;
    if ((selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                      | OSSL_KEYMGMT_SELECT_KEYPAIR)) != 0)
        return k->state >= COMPOSITE_KEM_HAVE_PUBKEY;
    return 1;
}

/* --- get_params / gettable_params --- */

static const OSSL_PARAM *composite_kem_gettable_params(void *provctx)
{
    static const OSSL_PARAM tbl[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_END
    };
    return tbl;
}

static int composite_kem_get_params(void *vkey, OSSL_PARAM params[])
{
    COMPOSITE_KEM_KEY *k = vkey;
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
    if (p != NULL) {
        int bits = k->pq_key != NULL ? EVP_PKEY_get_bits(k->pq_key) : 0;

        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }
    /* Composite security is bounded by the weaker component — derive it. */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int spq = k->pq_key != NULL ? EVP_PKEY_get_security_bits(k->pq_key) : 0;
        int str = k->trad_key != NULL
                      ? EVP_PKEY_get_security_bits(k->trad_key) : 0;
        int sec = spq == 0 ? str : (str == 0 ? spq : (spq < str ? spq : str));

        if (!OSSL_PARAM_set_int(p, sec))
            return 0;
    }
    return 1;
}

/* --- keygen --- */

typedef struct {
    void *provctx;
    const COMPOSITE_KEM_INFO *info;
} COMPOSITE_KEM_GEN_CTX;

static EVP_PKEY *gen_trad(OSSL_LIB_CTX *libctx, const COMPOSITE_KEM_INFO *info,
                          const char *p)
{
    if (strcmp(info->trad_alg, "EC") == 0)
        return EVP_PKEY_Q_keygen(libctx, p, "EC", info->trad_group);
    if (trad_is_raw(info))
        return EVP_PKEY_Q_keygen(libctx, p, info->trad_alg);
    /* RSA-OAEP: a plain RSA key of the combo's modulus size; OAEP padding is
     * applied at encapsulation time (see composite_kem.c rsa_oaep_ctx). */
    return EVP_PKEY_Q_keygen(libctx, p, "RSA", (size_t)info->trad_rsa_bits);
}

static void *composite_kem_gen_init_info(void *provctx,
                                         const COMPOSITE_KEM_INFO *info)
{
    COMPOSITE_KEM_GEN_CTX *g = OPENSSL_zalloc(sizeof(*g));

    if (g != NULL) {
        g->provctx = provctx;
        g->info = info;
    }
    return g;
}

static void *composite_kem_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    COMPOSITE_KEM_GEN_CTX *g = vgctx;
    COMPOSITE_KEM_KEY *k = composite_kem_key_new(g->provctx, g->info);
    EVP_PKEY_CTX *pctx = NULL;

    if (k == NULL)
        return NULL;
    pctx = EVP_PKEY_CTX_new_from_name(k->libctx, g->info->pq_alg, k->pq_propq);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0
            || EVP_PKEY_keygen(pctx, &k->pq_key) <= 0)
        goto err;
    EVP_PKEY_CTX_free(pctx);
    if ((k->trad_key = gen_trad(k->libctx, g->info, k->trad_propq)) == NULL)
        goto err2;
    k->state = COMPOSITE_KEM_HAVE_PRVKEY;
    return k;
err:
    EVP_PKEY_CTX_free(pctx);
err2:
    composite_kem_key_free_(k);
    return NULL;
}

static void composite_kem_gen_cleanup(void *vgctx)
{
    OPENSSL_free(vgctx);
}

static int composite_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM *composite_kem_gen_settable_params(void *vgctx,
                                                           void *provctx)
{
    static const OSSL_PARAM tbl[] = { OSSL_PARAM_END };
    return tbl;
}

/* --- decoder support --- */

static void *composite_kem_key_load(const void *reference, size_t reference_sz)
{
    COMPOSITE_KEM_KEY *key = NULL;

    if (reference_sz == sizeof(key)) {
        key = *(COMPOSITE_KEM_KEY **)reference;
        *(COMPOSITE_KEM_KEY **)reference = NULL;   /* ownership transfers */
    }
    return key;
}

COMPOSITE_KEM_KEY *composite_kem_keymgmt_new_by_index(void *provctx, size_t idx)
{
    return composite_kem_key_new(provctx, &composite_kem_table[idx]);
}

void composite_kem_keymgmt_free(COMPOSITE_KEM_KEY *key)
{
    composite_kem_key_free_(key);
}

/* Rebuild one classical public component from its raw bytes. */
static EVP_PKEY *load_trad_pub(OSSL_LIB_CTX *libctx, const char *propq,
                               const COMPOSITE_KEM_INFO *info,
                               const unsigned char *pub, size_t len)
{
    if (strcmp(info->trad_alg, "EC") == 0) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
        EVP_PKEY *k = NULL;
        OSSL_PARAM p[3];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)info->trad_group, 0);
        p[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                 (void *)pub, len);
        p[2] = OSSL_PARAM_construct_end();
        if (c != NULL && EVP_PKEY_fromdata_init(c) > 0)
            EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, p);
        EVP_PKEY_CTX_free(c);
        return k;
    }
    if (trad_is_raw(info))
        return EVP_PKEY_new_raw_public_key_ex(libctx, info->trad_alg,
                                              propq, pub, len);
    /* RSA-OAEP: raw form is i2d_PublicKey (RSAPublicKey) DER. */
    {
        const unsigned char *pp = pub;

        return d2i_PublicKey(EVP_PKEY_RSA, NULL, &pp, (long)len);
    }
}

int composite_kem_key_load_pub(COMPOSITE_KEM_KEY *key,
                               const unsigned char *pqpub, size_t pqlen,
                               const unsigned char *tradpub, size_t tradlen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(key->libctx, key->info->pq_alg,
                                                 key->pq_propq);
    OSSL_PARAM p[2];
    int ok = 0;

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                             (void *)pqpub, pqlen);
    p[1] = OSSL_PARAM_construct_end();
    if (c != NULL && EVP_PKEY_fromdata_init(c) > 0
            && EVP_PKEY_fromdata(c, &key->pq_key, EVP_PKEY_PUBLIC_KEY, p) > 0
            && (key->trad_key = load_trad_pub(key->libctx, key->trad_propq,
                                              key->info, tradpub,
                                              tradlen)) != NULL) {
        key->state = COMPOSITE_KEM_HAVE_PUBKEY;
        ok = 1;
    }
    EVP_PKEY_CTX_free(c);
    return ok;
}

/* Rebuild one classical private component: raw for X25519/X448, DER otherwise. */
static EVP_PKEY *load_trad_priv(OSSL_LIB_CTX *libctx, const char *propq,
                                const COMPOSITE_KEM_INFO *info,
                                const unsigned char *priv, size_t len)
{
    if (trad_is_raw(info))
        return EVP_PKEY_new_raw_private_key_ex(libctx, info->trad_alg,
                                               propq, priv, len);
    {
        const unsigned char *pp = priv;

        return d2i_AutoPrivateKey_ex(NULL, &pp, (long)len, libctx, propq);
    }
}

int composite_kem_key_load_prv(COMPOSITE_KEM_KEY *key,
                               const unsigned char *pqpriv, size_t pqlen,
                               const unsigned char *tradpriv, size_t tradlen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(key->libctx, key->info->pq_alg,
                                                 key->pq_propq);
    /* Reconstruct the PQ component from the param named by the row: the ML-KEM
     * seed for standardized combos; a different seed param or the raw private key
     * for a future non-ML-KEM combo. No ML-KEM assumption. */
    OSSL_PARAM p[2];
    int ok = 0;

    p[0] = OSSL_PARAM_construct_octet_string(key->info->pq_priv_param,
                                             (void *)pqpriv, pqlen);
    p[1] = OSSL_PARAM_construct_end();
    if (c != NULL && EVP_PKEY_fromdata_init(c) > 0
            && EVP_PKEY_fromdata(c, &key->pq_key, EVP_PKEY_KEYPAIR, p) > 0
            && (key->trad_key = load_trad_priv(key->libctx, key->trad_propq,
                                               key->info, tradpriv,
                                               tradlen)) != NULL) {
        key->state = COMPOSITE_KEM_HAVE_PRVKEY;
        ok = 1;
    }
    EVP_PKEY_CTX_free(c);
    return ok;
}

/* --- match + import/export --- */

static int composite_kem_key_match(const void *va, const void *vb, int selection)
{
    const COMPOSITE_KEM_KEY *a = va, *b = vb;

    if (a->info != b->info)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1;
    if ((a->pq_key == NULL) != (b->pq_key == NULL))
        return 0;
    if (a->pq_key == NULL)
        return 1;
    return EVP_PKEY_eq(a->pq_key, b->pq_key) == 1
        && EVP_PKEY_eq(a->trad_key, b->trad_key) == 1;
}

/* Fixed PQ public / seed split lengths (component sizes are fixed per OID). */
static size_t discover_pq_pub_len(COMPOSITE_KEM_KEY *key)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(key->libctx, key->info->pq_alg,
                                                 key->pq_propq);
    EVP_PKEY *t = NULL;
    size_t n = 0;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &t) > 0)
        EVP_PKEY_get_octet_string_param(t, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &n);
    EVP_PKEY_free(t);
    EVP_PKEY_CTX_free(c);
    return n;
}

static size_t discover_pq_priv_len(COMPOSITE_KEM_KEY *key)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(key->libctx, key->info->pq_alg,
                                                 key->pq_propq);
    EVP_PKEY *t = NULL;
    size_t n = 0;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &t) > 0)
        EVP_PKEY_get_octet_string_param(t, key->info->pq_priv_param, NULL, 0, &n);
    EVP_PKEY_free(t);
    EVP_PKEY_CTX_free(c);
    return n;
}

static int import_pub_blob(COMPOSITE_KEM_KEY *key, const unsigned char *blob,
                           size_t len)
{
    size_t pqn = discover_pq_pub_len(key);

    return pqn != 0 && pqn < len
        && composite_kem_key_load_pub(key, blob, pqn, blob + pqn, len - pqn);
}

static int import_prv_blob(COMPOSITE_KEM_KEY *key, const unsigned char *blob,
                           size_t len)
{
    size_t pqn = discover_pq_priv_len(key);

    return pqn != 0 && pqn < len
        && composite_kem_key_load_prv(key, blob, pqn, blob + pqn, len - pqn);
}

static const OSSL_PARAM composite_kem_imexport_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *composite_kem_imexport_types_fn(int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0
        ? composite_kem_imexport_types : NULL;
}

static int composite_kem_import(void *vkey, int selection,
                                const OSSL_PARAM params[])
{
    COMPOSITE_KEM_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *data;
    size_t len;

    if (key == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (p = OSSL_PARAM_locate_const(params,
                                            OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        if (OSSL_PARAM_get_octet_string_ptr(p, &data, &len) != 1)
            return 0;
        return import_prv_blob(key, data, len);
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        if (OSSL_PARAM_get_octet_string_ptr(p, &data, &len) != 1)
            return 0;
        return import_pub_blob(key, data, len);
    }
    return 0;
}

static int composite_kem_export(void *vkey, int selection, OSSL_CALLBACK *cb,
                                void *cbarg)
{
    COMPOSITE_KEM_KEY *key = vkey;
    OSSL_PARAM_BLD *bld;
    OSSL_PARAM *params = NULL;
    unsigned char *pub = NULL, *prv = NULL;
    size_t publen = 0, prvlen = 0;
    int ret = 0;

    if (key == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0
            || key->state < COMPOSITE_KEM_HAVE_PUBKEY)
        return 0;
    if ((bld = OSSL_PARAM_BLD_new()) == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!composite_kem_encode_pub_blob(key, &pub, &publen)
                || !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                                     pub, publen))
            goto err;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && key->state >= COMPOSITE_KEM_HAVE_PRVKEY) {
        if (!composite_kem_encode_priv_blob(key, &prv, &prvlen)
                || !OSSL_PARAM_BLD_push_octet_string(bld,
                                                     OSSL_PKEY_PARAM_PRIV_KEY,
                                                     prv, prvlen))
            goto err;
    }
    if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
        goto err;
    ret = cb(params, cbarg);
err:
    if (params != NULL) {
        OSSL_PARAM *pp = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

        if (pp != NULL && pp->data != NULL)
            OPENSSL_cleanse(pp->data, pp->data_size);
    }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_clear_free(prv, prvlen);
    OPENSSL_free(pub);
    return ret;
}

/*
 * Per-algorithm keymgmt instances — generated from the master list, each binding
 * its NEW/GEN_INIT to the matching info-table row.
 */
#define DECLARE_COMPOSITE_KEM_KMGMT(cf, idx)                                   \
    static void *composite_##cf##_kem_new(void *provctx)                      \
    {                                                                          \
        return composite_kem_key_new(provctx, &composite_kem_table[idx]);     \
    }                                                                          \
    static void *composite_##cf##_kem_gen_init(void *provctx, int selection,  \
                                               const OSSL_PARAM params[])      \
    {                                                                          \
        return composite_kem_gen_init_info(provctx,                           \
                                           &composite_kem_table[idx]);        \
    }                                                                          \
    const OSSL_DISPATCH composite_##cf##_kem_kmgmt_functions[] = {             \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))composite_##cf##_kem_new },   \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))composite_kem_key_load },    \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))composite_kem_key_free_ },   \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))composite_kem_key_has },      \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))composite_kem_key_match },  \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))composite_kem_import },    \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                     \
          (void (*)(void))composite_kem_imexport_types_fn },                  \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))composite_kem_export },    \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                     \
          (void (*)(void))composite_kem_imexport_types_fn },                  \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                        \
          (void (*)(void))composite_kem_get_params },                         \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                   \
          (void (*)(void))composite_kem_gettable_params },                    \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,                                          \
          (void (*)(void))composite_##cf##_kem_gen_init },                    \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))composite_kem_gen },          \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                       \
          (void (*)(void))composite_kem_gen_cleanup },                        \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                    \
          (void (*)(void))composite_kem_gen_set_params },                     \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                               \
          (void (*)(void))composite_kem_gen_settable_params },                \
        { 0, NULL }                                                            \
    }

#define COMPOSITE_KEM_KMGMT_ROW(cf, ...) \
    DECLARE_COMPOSITE_KEM_KMGMT(cf, COMPOSITE_KEM_IDX_##cf);
COMPOSITE_KEM_LIST(COMPOSITE_KEM_KMGMT_ROW)
#undef COMPOSITE_KEM_KMGMT_ROW
