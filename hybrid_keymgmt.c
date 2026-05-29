/*
 * Copyright 2025 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"

/* --- Key lifecycle --- */

static void hybrid_key_free(void *vkey)
{
    HYBRID_KEY *key = vkey;

    if (key == NULL)
        return;
    OPENSSL_free(key->propq);
    EVP_PKEY_free(key->key1);
    EVP_PKEY_free(key->key2);
    OPENSSL_free(key);
}

static void *
hybrid_key_new(unsigned int variant, OSSL_LIB_CTX *libctx, char *propq)
{
    HYBRID_KEY *key;

    if (variant >= HYBRID_KEM_ALG_COUNT)
        return NULL;
    if ((key = OPENSSL_zalloc(sizeof(*key))) == NULL) {
        OPENSSL_free(propq);
        return NULL;
    }
    key->libctx = libctx;
    key->info = &hybrid_kem_table[variant];
    key->key1 = NULL;
    key->key2 = NULL;
    key->state = HYBRID_HAVE_NOKEYS;
    key->propq = propq;
    return key;
}

/* --- has / match / dup --- */

static int hybrid_kem_has(const void *vkey, int selection)
{
    const HYBRID_KEY *key = vkey;

    if (key == NULL)
        return 0;
    switch (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return hybrid_have_pubkey(key);
    default:
        return hybrid_have_prvkey(key);
    }
}

static int hybrid_kem_match(const void *vkey1, const void *vkey2, int selection)
{
    const HYBRID_KEY *key1 = vkey1;
    const HYBRID_KEY *key2 = vkey2;

    if (key1->info != key2->info)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 1;
    if (hybrid_have_pubkey(key1) != hybrid_have_pubkey(key2))
        return 0;
    if (!hybrid_have_pubkey(key1))
        return 1;
    return EVP_PKEY_eq(key1->key1, key2->key1)
        && EVP_PKEY_eq(key1->key2, key2->key2);
}

static void *hybrid_kem_dup(const void *vkey, int selection)
{
    const HYBRID_KEY *key = vkey;
    HYBRID_KEY *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    ret->libctx = key->libctx;
    ret->info = key->info;
    ret->state = HYBRID_HAVE_NOKEYS;
    ret->propq = NULL;

    if (key->propq != NULL
        && (ret->propq = OPENSSL_strdup(key->propq)) == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR) || key->key1 == NULL)
        return ret;

    ret->key1 = EVP_PKEY_dup(key->key1);
    ret->key2 = EVP_PKEY_dup(key->key2);
    if (ret->key1 != NULL && ret->key2 != NULL) {
        ret->state = key->state;
        return ret;
    }
    hybrid_key_free(ret);
    return NULL;
}

/* --- Import / Export --- */

static int
load_component(OSSL_LIB_CTX *libctx, const char *propq,
               const char *alg_name, const char *group_name,
               const char *param_name, int selection,
               const uint8_t *raw, size_t rawlen,
               EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM parr[3];
    int idx = 0;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;

    parr[idx++] = OSSL_PARAM_construct_octet_string(param_name,
                                                     (void *)raw, rawlen);
    if (group_name != NULL)
        parr[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, 0);
    parr[idx] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, out, selection, parr) > 0)
        ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int
load_keys(HYBRID_KEY *key,
          const uint8_t *pubenc, size_t publen,
          const uint8_t *prvenc, size_t prvlen)
{
    const HYBRID_KEM_INFO *info = key->info;
    int selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                  | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    const uint8_t *alg1_data, *alg2_data;
    size_t alg1_len, alg2_len;
    const char *pname;

    if (prvlen > 0) {
        pname = OSSL_PKEY_PARAM_PRIV_KEY;
        /* Slot ordering: if alg2_slot==0, alg2 data comes first */
        if (info->alg2_slot == 0) {
            alg2_data = prvenc;
            alg2_len = info->alg2_prvkey_bytes;
            alg1_data = prvenc + info->alg2_prvkey_bytes;
            alg1_len = info->alg1_prvkey_bytes;
        } else {
            alg1_data = prvenc;
            alg1_len = info->alg1_prvkey_bytes;
            alg2_data = prvenc + info->alg1_prvkey_bytes;
            alg2_len = info->alg2_prvkey_bytes;
        }
    } else if (publen > 0) {
        selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                  | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        pname = OSSL_PKEY_PARAM_PUB_KEY;
        if (info->alg2_slot == 0) {
            alg2_data = pubenc;
            alg2_len = info->alg2_pubkey_bytes;
            alg1_data = pubenc + info->alg2_pubkey_bytes;
            alg1_len = info->alg1_pubkey_bytes;
        } else {
            alg1_data = pubenc;
            alg1_len = info->alg1_pubkey_bytes;
            alg2_data = pubenc + info->alg1_pubkey_bytes;
            alg2_len = info->alg2_pubkey_bytes;
        }
    } else {
        return 0;
    }

    if (!load_component(key->libctx, key->propq,
                        info->alg1_name, info->alg1_group,
                        pname, selection,
                        alg1_data, alg1_len, &key->key1))
        goto err;
    if (!load_component(key->libctx, key->propq,
                        info->alg2_name, info->alg2_group,
                        pname, selection,
                        alg2_data, alg2_len, &key->key2))
        goto err;

    key->state = (prvlen > 0) ? HYBRID_HAVE_PRVKEY : HYBRID_HAVE_PUBKEY;
    return 1;

err:
    EVP_PKEY_free(key->key1);
    EVP_PKEY_free(key->key2);
    key->key1 = key->key2 = NULL;
    key->state = HYBRID_HAVE_NOKEYS;
    return 0;
}

static int hybrid_kem_import(void *vkey, int selection,
                             const OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    int include_private;

    if (key == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? 1 : 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p == NULL)
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL)
        OSSL_PARAM_get_octet_string_ptr(p, &pubenc, &publen);

    if (include_private) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL)
            OSSL_PARAM_get_octet_string_ptr(p, &prvenc, &prvlen);
    }

    if (publen == 0 && prvlen == 0)
        return 0;

    if (publen != 0 && publen != hybrid_kem_pubkey_bytes(key->info))
        return 0;
    if (prvlen != 0 && prvlen != hybrid_kem_prvkey_bytes(key->info))
        return 0;

    return load_keys(key, pubenc, publen, prvenc, prvlen);
}

/*
 * Extract concatenated public key bytes from both sub-keys.
 * Caller provides buffer of hybrid_kem_pubkey_bytes(info) size.
 */
static int
extract_pubkey(const HYBRID_KEY *key, uint8_t *buf, size_t buflen)
{
    const HYBRID_KEM_INFO *info = key->info;
    size_t off1, off2, len1, len2, out;

    if (buflen < hybrid_kem_pubkey_bytes(info))
        return 0;

    /* Determine slot offsets */
    if (info->alg2_slot == 0) {
        off2 = 0;  len2 = info->alg2_pubkey_bytes;
        off1 = len2; len1 = info->alg1_pubkey_bytes;
    } else {
        off1 = 0;  len1 = info->alg1_pubkey_bytes;
        off2 = len1; len2 = info->alg2_pubkey_bytes;
    }

    if (EVP_PKEY_get_octet_string_param(key->key1, OSSL_PKEY_PARAM_PUB_KEY,
            buf + off1, len1, &out) <= 0 || out != len1)
        return 0;
    if (EVP_PKEY_get_octet_string_param(key->key2, OSSL_PKEY_PARAM_PUB_KEY,
            buf + off2, len2, &out) <= 0 || out != len2)
        return 0;
    return 1;
}

/* Callback arg for EVP_PKEY_export — used for private key extraction */
typedef struct {
    uint8_t *buf;
    size_t off;
    size_t len;
    int found;
} EXPORT_PRV_ARG;

static int export_prv_cb(const OSSL_PARAM *params, void *varg)
{
    EXPORT_PRV_ARG *arg = varg;
    const OSSL_PARAM *p;
    const void *data;
    size_t len;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_get_octet_string_ptr(p, &data, &len) != 1)
        return 0;
    if (len != arg->len)
        return 0;

    memcpy(arg->buf + arg->off, data, len);
    arg->found = 1;
    return 1;
}

static int hybrid_kem_export(void *vkey, int selection,
                             OSSL_CALLBACK *param_cb, void *cbarg)
{
    HYBRID_KEY *key = vkey;
    const HYBRID_KEM_INFO *info;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    uint8_t *pubbuf = NULL, *prvbuf = NULL;
    size_t publen, prvlen;
    int ret = 0;

    if (key == NULL || !hybrid_have_pubkey(key))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    info = key->info;
    publen = hybrid_kem_pubkey_bytes(info);
    prvlen = hybrid_kem_prvkey_bytes(info);

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    /* Export public keys via direct param extraction */
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        pubbuf = OPENSSL_malloc(publen);
        if (pubbuf == NULL)
            goto err;
        if (!extract_pubkey(key, pubbuf, publen))
            goto err;
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                               pubbuf, publen))
            goto err;
    }

    /* Export private keys via EVP_PKEY_export callback */
    if (hybrid_have_prvkey(key)
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        EXPORT_PRV_ARG sub;
        int prv_sel = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

        prvbuf = OPENSSL_secure_zalloc(prvlen);
        if (prvbuf == NULL)
            goto err;

        sub.buf = prvbuf;
        sub.found = 0;
        if (info->alg2_slot == 0) {
            sub.off = info->alg2_prvkey_bytes;
            sub.len = info->alg1_prvkey_bytes;
        } else {
            sub.off = 0;
            sub.len = info->alg1_prvkey_bytes;
        }
        if (!EVP_PKEY_export(key->key1, prv_sel, export_prv_cb, &sub)
            || !sub.found)
            goto err;

        sub.found = 0;
        if (info->alg2_slot == 0) {
            sub.off = 0;
            sub.len = info->alg2_prvkey_bytes;
        } else {
            sub.off = info->alg1_prvkey_bytes;
            sub.len = info->alg2_prvkey_bytes;
        }
        if (!EVP_PKEY_export(key->key2, prv_sel, export_prv_cb, &sub)
            || !sub.found)
            goto err;

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                               prvbuf, prvlen))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_secure_clear_free(prvbuf, prvlen);
    OPENSSL_free(pubbuf);
    return ret;
}

static const OSSL_PARAM hybrid_imexport_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_kem_imexport_types(int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        return hybrid_imexport_types;
    return NULL;
}

/* --- get_params / gettable_params --- */

static const OSSL_PARAM hybrid_gettable[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_kem_gettable_params(void *provctx)
{
    return hybrid_gettable;
}

static int hybrid_kem_get_params(void *vkey, OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    const HYBRID_KEM_INFO *info;
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;
    info = key->info;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 128))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, hybrid_kem_ctext_bytes(info)))
        return 0;

    /* Return encoded public key if requested and available */
    if (hybrid_have_pubkey(key)) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p == NULL)
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            size_t publen = hybrid_kem_pubkey_bytes(info);

            p->return_size = publen;
            if (p->data != NULL) {
                if (p->data_size < publen)
                    return 0;
                if (!extract_pubkey(key, p->data, publen))
                    return 0;
            }
        }
    }

    return 1;
}

/* --- set_params / settable_params --- */

static const OSSL_PARAM hybrid_settable[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_kem_settable_params(void *provctx)
{
    return hybrid_settable;
}

static int hybrid_kem_set_params(void *vkey, const OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pubenc;
    size_t publen;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(key->propq);
        key->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &key->propq, 0))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p == NULL)
        return 1;

    if (hybrid_have_pubkey(key))
        return 0; /* no mutation */

    if (!OSSL_PARAM_get_octet_string_ptr(p, &pubenc, &publen))
        return 0;
    if (publen != hybrid_kem_pubkey_bytes(key->info))
        return 0;

    return load_keys(key, pubenc, publen, NULL, 0);
}

/* --- Key Generation --- */

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    int selection;
    unsigned int algo_idx;
} HYBRID_KEM_GEN_CTX;

static void *hybrid_kem_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    HYBRID_KEM_GEN_CTX *gctx = vgctx;
    HYBRID_KEY *key;
    char *propq;

    if (gctx == NULL)
        return NULL;

    propq = gctx->propq;
    gctx->propq = NULL;
    key = hybrid_key_new(gctx->algo_idx, gctx->libctx, propq);
    if (key == NULL)
        return NULL;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    key->key2 = EVP_PKEY_Q_keygen(key->libctx, key->propq,
                                   key->info->alg2_name);
    key->key1 = EVP_PKEY_Q_keygen(key->libctx, key->propq,
                                   key->info->alg1_name,
                                   key->info->alg1_group);

    if (key->key1 != NULL && key->key2 != NULL) {
        key->state = HYBRID_HAVE_PRVKEY;
        return key;
    }

    hybrid_key_free(key);
    return NULL;
}

static void hybrid_kem_gen_cleanup(void *vgctx)
{
    HYBRID_KEM_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static const OSSL_PARAM gen_settable[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static int hybrid_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    HYBRID_KEM_GEN_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(gctx->propq);
        gctx->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &gctx->propq, 0))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *hybrid_kem_gen_settable_params(void *vgctx,
                                                         void *provctx)
{
    return gen_settable;
}

/*
 * Macro to declare per-algorithm keymgmt_new and keymgmt_gen_init,
 * plus the dispatch table. Each variant index into hybrid_kem_table.
 */
#define DECLARE_HYBRID_KEM_KMGMT(name, variant)                              \
    static void *hybrid_##name##_new(void *provctx)                          \
    {                                                                        \
        HYBRID_PROV_CTX *ctx = provctx;                                      \
        OSSL_LIB_CTX *libctx = ctx ? ctx->libctx : NULL;                    \
        return hybrid_key_new(variant, libctx, NULL);                        \
    }                                                                        \
    static void *hybrid_##name##_gen_init(void *provctx, int selection,      \
                                          const OSSL_PARAM params[])         \
    {                                                                        \
        HYBRID_PROV_CTX *pctx = provctx;                                     \
        HYBRID_KEM_GEN_CTX *gctx;                                           \
        if (pctx == NULL || (selection & (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS \
                | OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) == 0)                    \
            return NULL;                                                     \
        gctx = OPENSSL_zalloc(sizeof(*gctx));                                \
        if (gctx == NULL) return NULL;                                       \
        gctx->algo_idx = variant;                                            \
        gctx->libctx = pctx->libctx;                                        \
        gctx->selection = selection;                                         \
        if (!hybrid_kem_gen_set_params(gctx, params)) {                      \
            hybrid_kem_gen_cleanup(gctx);                                    \
            return NULL;                                                     \
        }                                                                    \
        return gctx;                                                         \
    }                                                                        \
    const OSSL_DISPATCH hybrid_##name##_kmgmt_functions[] = {                \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hybrid_##name##_new },      \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hybrid_key_free },         \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hybrid_kem_has },           \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hybrid_kem_match },       \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))hybrid_kem_dup },           \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hybrid_kem_import },     \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                   \
          (void (*)(void))hybrid_kem_imexport_types },                       \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hybrid_kem_export },     \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                   \
          (void (*)(void))hybrid_kem_imexport_types },                       \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                     \
          (void (*)(void))hybrid_kem_get_params },                           \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                \
          (void (*)(void))hybrid_kem_gettable_params },                      \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                     \
          (void (*)(void))hybrid_kem_set_params },                           \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                \
          (void (*)(void))hybrid_kem_settable_params },                      \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,                                       \
          (void (*)(void))hybrid_##name##_gen_init },                        \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                 \
          (void (*)(void))hybrid_kem_gen_set_params },                       \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                            \
          (void (*)(void))hybrid_kem_gen_settable_params },                  \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))hybrid_kem_gen },           \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                    \
          (void (*)(void))hybrid_kem_gen_cleanup },                          \
        { 0, NULL }                                                          \
    }

DECLARE_HYBRID_KEM_KMGMT(x25519mlkem768, 0);
DECLARE_HYBRID_KEM_KMGMT(x448mlkem1024, 1);
DECLARE_HYBRID_KEM_KMGMT(secp256r1mlkem768, 2);
DECLARE_HYBRID_KEM_KMGMT(secp384r1mlkem1024, 3);
