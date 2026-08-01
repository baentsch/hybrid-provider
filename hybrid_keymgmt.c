/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/x509.h>

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

/*
 * Materialize a key from a decoder-provided reference (the decoder hands back a
 * pointer to a HYBRID_KEY it built; ownership transfers to the EVP_PKEY).
 */
static void *hybrid_key_load(const void *reference, size_t reference_sz)
{
    HYBRID_KEY *key = NULL;

    if (reference_sz == sizeof(key)) {
        key = *(HYBRID_KEY **)reference;
        *(HYBRID_KEY **)reference = NULL;   /* avoid a double free */
        return key;
    }
    return NULL;
}

static void *
hybrid_key_new(int is_kem, unsigned int variant,
               OSSL_LIB_CTX *libctx, char *propq)
{
    HYBRID_KEY *key;

    if (is_kem && variant >= HYBRID_KEM_ALG_COUNT)
        return NULL;
    if (!is_kem && variant >= HYBRID_SIG_ALG_COUNT)
        return NULL;
    if ((key = OPENSSL_zalloc(sizeof(*key))) == NULL) {
        OPENSSL_free(propq);
        return NULL;
    }
    key->libctx = libctx;
    key->is_kem = is_kem;
    key->info = is_kem ? (const void *)&hybrid_kem_table[variant]
                       : (const void *)&hybrid_sig_table[variant];
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
    ret->is_kem = key->is_kem;
    ret->info = key->info;
    ret->state = HYBRID_HAVE_NOKEYS;
    ret->propq = NULL;
    ret->pq_propq = key->pq_propq;
    ret->classic_propq = key->classic_propq;

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

/* --- Decoder support: build a public key from oqs blob components --- */

/* Free a hybrid key (public wrapper over the static free, for decoders). */
void hybrid_keymgmt_free(void *vkey)
{
    hybrid_key_free(vkey);
}

/* Create an empty hybrid key of the given family/variant (used by decoders). */
void *hybrid_keymgmt_new_by_variant(void *provctx, int is_kem,
                                    unsigned int variant)
{
    HYBRID_PROV_CTX *ctx = provctx;
    OSSL_LIB_CTX *lc = ctx ? HYBRID_COMPONENT_LIBCTX(ctx) : NULL;
    HYBRID_KEY *k = hybrid_key_new(is_kem, variant, lc, NULL);

    if (k != NULL && ctx != NULL) {
        k->pq_propq = ctx->pq_propq;
        k->classic_propq = ctx->classic_propq;
    }
    return k;
}

/* Load the classical + PQ public components from their raw byte ranges. */
int hybrid_key_load_pub_components(HYBRID_KEY *key,
                                  const unsigned char *classic, size_t clen,
                                  const unsigned char *pq, size_t plen)
{
    int sel = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
            | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    if (strcmp(HYBRID_KEY_ALG1_NAME(key), "RSA") == 0) {
        /* RSA public key is i2d_PublicKey (RSAPublicKey) DER, not an octet. */
        const unsigned char *p = classic;

        key->key1 = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, (long)clen);
        if (key->key1 == NULL)
            return 0;
    } else if (!load_component(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                        HYBRID_KEY_ALG1_NAME(key), HYBRID_KEY_ALG1_GROUP(key),
                        OSSL_PKEY_PARAM_PUB_KEY, sel, classic, clen,
                        &key->key1)) {
        return 0;
    }
    if (!load_component(key->libctx, HYBRID_KEY_PQ_PROPQ(key),
                        HYBRID_KEY_ALG2_NAME(key), NULL,
                        OSSL_PKEY_PARAM_PUB_KEY, sel, pq, plen, &key->key2))
        return 0;
    key->state = HYBRID_HAVE_PUBKEY;
    return 1;
}

/* Load the classical (DER) + PQ (raw) private components (decoders). */
int hybrid_key_load_prv_components(HYBRID_KEY *key,
                                  const unsigned char *cder, size_t cderlen,
                                  const unsigned char *pqv, size_t pqvlen)
{
    int sel = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
            | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    const char *a1 = HYBRID_KEY_ALG1_NAME(key);

    /* Raw-key classical types (X25519/X448) are stored raw, not DER. */
    if (strcmp(a1, "X25519") == 0 || strcmp(a1, "X448") == 0) {
        key->key1 = EVP_PKEY_new_raw_private_key_ex(key->libctx, a1,
                        HYBRID_KEY_CLASSIC_PROPQ(key), cder, cderlen);
    } else {
        const unsigned char *p = cder;

        key->key1 = d2i_AutoPrivateKey_ex(NULL, &p, (long)cderlen, key->libctx,
                                          HYBRID_KEY_CLASSIC_PROPQ(key));
    }
    if (key->key1 == NULL)
        return 0;
    if (!load_component(key->libctx, HYBRID_KEY_PQ_PROPQ(key),
                        HYBRID_KEY_ALG2_NAME(key), NULL,
                        OSSL_PKEY_PARAM_PRIV_KEY, sel, pqv, pqvlen, &key->key2)) {
        EVP_PKEY_free(key->key1);
        key->key1 = NULL;
        return 0;
    }
    key->state = HYBRID_HAVE_PRVKEY;
    return 1;
}

/* --- Runtime component-size discovery --- */

/* Forward declaration; defined in the Key Generation section below. */
static EVP_PKEY *
hybrid_component_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                        const char *alg_name, const char *group_name);

/*
 * Query the pub/priv/shared-secret/ciphertext sizes of one component algorithm
 * by generating a throwaway keypair (sizes are deterministic per algorithm and
 * EC group, so a fresh key yields the same sizes as the real component). For a
 * key-exchange component (is_kem==0) the "ciphertext" is the ephemeral public
 * key, so a1_ct == a1_pub, and the shared-secret length comes from a throwaway
 * ECDH derive.
 */
static int
discover_component_sizes(OSSL_LIB_CTX *libctx, const char *propq,
                         const char *alg_name, const char *group_name,
                         int is_kem, size_t *pub, size_t *prv,
                         size_t *ss, size_t *ct)
{
    EVP_PKEY *tmp = NULL, *eph = NULL;
    EVP_PKEY_CTX *c = NULL;
    int ret = 0;

    tmp = hybrid_component_keygen(libctx, propq, alg_name, group_name);
    if (tmp == NULL)
        return 0;

    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, pub) <= 0)
        goto end;
    /*
     * The private-key size: KEM components and raw curves (X25519/X448) expose
     * PRIV_KEY as an octet string. EC curves expose it as a BIGNUM, for which
     * the octet-string query fails; fall back to the field byte length so the
     * size reflects the fixed scalar width (not a particular key's stripped BN).
     */
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY,
                                        NULL, 0, prv) <= 0) {
        int bits = EVP_PKEY_get_bits(tmp);

        ERR_clear_error();
        if (bits <= 0)
            goto end;
        *prv = (size_t)(bits + 7) / 8;
    }

    if (is_kem) {
        c = EVP_PKEY_CTX_new_from_pkey(libctx, tmp, propq);
        if (c == NULL || EVP_PKEY_encapsulate_init(c, NULL) <= 0
            || EVP_PKEY_encapsulate(c, NULL, ct, NULL, ss) <= 0)
            goto end;
    } else {
        *ct = *pub;   /* ephemeral public key */
        c = EVP_PKEY_CTX_new_from_pkey(libctx, tmp, propq);
        if (c == NULL || EVP_PKEY_keygen_init(c) <= 0
            || EVP_PKEY_keygen(c, &eph) <= 0)
            goto end;
        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(libctx, eph, propq);
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

/*
 * Query the pub/priv/signature sizes of one signature component. pub/priv are
 * best-effort (used only by key export, deferred): RSA exposes neither as an
 * octet string, so they may be left 0. The signature size (EVP_PKEY_get_size)
 * is what sign/verify and the max-size query need.
 */
static int
discover_sig_component_sizes(OSSL_LIB_CTX *libctx, const char *propq,
                             const char *alg_name, const char *group_name,
                             size_t *pub, size_t *prv, size_t *sig)
{
    EVP_PKEY *tmp = hybrid_component_keygen(libctx, propq, alg_name, group_name);
    int n;

    if (tmp == NULL)
        return 0;
    n = EVP_PKEY_get_size(tmp);
    *sig = n > 0 ? (size_t)n : 0;

    *pub = 0;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, pub) <= 0) {
        *pub = 0;
        ERR_clear_error();
    }
    *prv = 0;
    if (EVP_PKEY_get_octet_string_param(tmp, OSSL_PKEY_PARAM_PRIV_KEY,
                                        NULL, 0, prv) <= 0) {
        int bits = EVP_PKEY_get_bits(tmp);

        *prv = bits > 0 ? (size_t)(bits + 7) / 8 : 0;
        ERR_clear_error();
    }
    EVP_PKEY_free(tmp);
    return *sig != 0;
}

int hybrid_ensure_sizes(HYBRID_KEY *key)
{
    if (key->sizes.valid)
        return 1;

    if (key->is_kem) {
        const HYBRID_KEM_INFO *info = (const HYBRID_KEM_INFO *)key->info;

        if (!discover_component_sizes(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                                      info->alg1_name, info->alg1_group,
                                      info->alg1_is_kem,
                                      &key->sizes.a1_pub, &key->sizes.a1_prv,
                                      &key->sizes.a1_ss, &key->sizes.a1_ct))
            return 0;
        if (!discover_component_sizes(key->libctx, HYBRID_KEY_PQ_PROPQ(key),
                                      info->alg2_name, info->alg2_group,
                                      info->alg2_is_kem,
                                      &key->sizes.a2_pub, &key->sizes.a2_prv,
                                      &key->sizes.a2_ss, &key->sizes.a2_ct))
            return 0;
    } else {
        const HYBRID_SIG_INFO *info = (const HYBRID_SIG_INFO *)key->info;

        if (!discover_sig_component_sizes(key->libctx,
                                          HYBRID_KEY_CLASSIC_PROPQ(key),
                                          info->alg1_name, info->alg1_group,
                                          &key->sizes.a1_pub, &key->sizes.a1_prv,
                                          &key->sizes.a1_sig))
            return 0;
        if (!discover_sig_component_sizes(key->libctx, HYBRID_KEY_PQ_PROPQ(key),
                                          info->alg2_name, NULL,
                                          &key->sizes.a2_pub, &key->sizes.a2_prv,
                                          &key->sizes.a2_sig))
            return 0;
    }
    key->sizes.valid = 1;
    return 1;
}

/*
 * Determine slot offsets for concatenated key material.
 * KEM keys use alg2_slot to control ordering; SIG keys always use alg1 first.
 */
static void
key_slot_offsets(const HYBRID_KEY *key, int is_pub,
                 size_t *off1, size_t *len1, size_t *off2, size_t *len2)
{
    size_t a1, a2;
    int alg2_first = 0;

    if (is_pub) {
        a1 = HYBRID_KEY_ALG1_PUBKEY_BYTES(key);
        a2 = HYBRID_KEY_ALG2_PUBKEY_BYTES(key);
    } else {
        a1 = HYBRID_KEY_ALG1_PRVKEY_BYTES(key);
        a2 = HYBRID_KEY_ALG2_PRVKEY_BYTES(key);
    }

    if (key->is_kem)
        alg2_first = (((const HYBRID_KEM_INFO *)key->info)->alg2_slot == 0);

    if (alg2_first) {
        *off2 = 0;  *len2 = a2;
        *off1 = a2; *len1 = a1;
    } else {
        *off1 = 0;  *len1 = a1;
        *off2 = a1; *len2 = a2;
    }
}

static int
load_keys(HYBRID_KEY *key,
          const uint8_t *pubenc, size_t publen,
          const uint8_t *prvenc, size_t prvlen)
{
    int selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                  | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    const uint8_t *alg1_data, *alg2_data;
    size_t off1, len1, off2, len2;
    const char *pname;

    if (prvlen > 0) {
        pname = OSSL_PKEY_PARAM_PRIV_KEY;
        key_slot_offsets(key, 0, &off1, &len1, &off2, &len2);
        alg1_data = prvenc + off1;
        alg2_data = prvenc + off2;
    } else if (publen > 0) {
        selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                  | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        pname = OSSL_PKEY_PARAM_PUB_KEY;
        key_slot_offsets(key, 1, &off1, &len1, &off2, &len2);
        alg1_data = pubenc + off1;
        alg2_data = pubenc + off2;
    } else {
        return 0;
    }

    if (!load_component(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                        HYBRID_KEY_ALG1_NAME(key),
                        HYBRID_KEY_ALG1_GROUP(key),
                        pname, selection,
                        alg1_data, len1, &key->key1))
        goto err;
    if (!load_component(key->libctx, HYBRID_KEY_PQ_PROPQ(key),
                        HYBRID_KEY_ALG2_NAME(key), NULL,
                        pname, selection,
                        alg2_data, len2, &key->key2))
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

static int hybrid_import(void *vkey, int selection,
                          const OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    int include_private;

    if (key == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;
    if (!hybrid_ensure_sizes(key))
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

    if (publen != 0 && publen != hybrid_key_pubkey_bytes(key))
        return 0;
    if (prvlen != 0 && prvlen != hybrid_key_prvkey_bytes(key))
        return 0;

    return load_keys(key, pubenc, publen, prvenc, prvlen);
}

/*
 * Extract concatenated public key bytes from both sub-keys.
 * Caller provides buffer of hybrid_key_pubkey_bytes(key) size.
 */
static int
extract_pubkey(const HYBRID_KEY *key, uint8_t *buf, size_t buflen)
{
    size_t off1, len1, off2, len2, out;

    if (buflen < hybrid_key_pubkey_bytes(key))
        return 0;

    key_slot_offsets(key, 1, &off1, &len1, &off2, &len2);

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

static int hybrid_export(void *vkey, int selection,
                          OSSL_CALLBACK *param_cb, void *cbarg)
{
    HYBRID_KEY *key = vkey;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    uint8_t *pubbuf = NULL, *prvbuf = NULL;
    size_t publen, prvlen;
    size_t off1, len1, off2, len2;
    int ret = 0;

    if (key == NULL || !hybrid_have_pubkey(key))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;
    if (!hybrid_ensure_sizes(key))
        return 0;

    publen = hybrid_key_pubkey_bytes(key);
    prvlen = hybrid_key_prvkey_bytes(key);

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

        key_slot_offsets(key, 0, &off1, &len1, &off2, &len2);

        sub.buf = prvbuf;
        sub.found = 0;
        sub.off = off1;
        sub.len = len1;
        if (!EVP_PKEY_export(key->key1, prv_sel, export_prv_cb, &sub)
            || !sub.found)
            goto err;

        sub.found = 0;
        sub.off = off2;
        sub.len = len2;
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
    /*
     * OSSL_PARAM_free() does not wipe payloads, so cleanse the private-key
     * copy the param builder made before releasing it.
     */
    if (params != NULL) {
        OSSL_PARAM *pp = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

        if (pp != NULL && pp->data != NULL)
            OPENSSL_cleanse(pp->data, pp->data_size);
    }
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

static int hybrid_get_params_fn(void *vkey, OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    OSSL_PARAM *p;
    size_t max_size;

    if (key == NULL)
        return 0;
    if (!hybrid_ensure_sizes(key))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 128))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        if (key->is_kem)
            max_size = hybrid_kem_ctext_bytes(key);
        else
            max_size = hybrid_sig_max_sig_bytes(key);
        if (!OSSL_PARAM_set_size_t(p, max_size))
            return 0;
    }

    /* Return encoded public key if requested and available */
    if (hybrid_have_pubkey(key)) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p == NULL)
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            size_t publen = hybrid_key_pubkey_bytes(key);

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

static int hybrid_set_params_fn(void *vkey, const OSSL_PARAM params[])
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
    if (!hybrid_ensure_sizes(key))
        return 0;
    if (publen != hybrid_key_pubkey_bytes(key))
        return 0;

    return load_keys(key, pubenc, publen, NULL, 0);
}

/* --- Key Generation --- */

/*
 * Generate a component key via the generic EVP keygen path.
 *
 * We deliberately avoid EVP_PKEY_Q_keygen(): that convenience helper only
 * accepts algorithm names from a hardcoded allowlist in libcrypto (RSA, EC,
 * the EdDSA/ECDH curves, SM2). ML-KEM/ML-DSA were not added to that list until
 * OpenSSL 3.5, so relying on it would both break on 3.4.x and contradict the
 * provider's goal of composing arbitrary sub-algorithms from any provider.
 * EVP_PKEY_CTX_new_from_name() resolves the algorithm purely by name and
 * property query, with no such restriction.
 */
static EVP_PKEY *
hybrid_component_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                        const char *alg_name, const char *group_name)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;

    if (group_name != NULL) {
        OSSL_PARAM parr[2];

        parr[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                   (char *)group_name, 0);
        parr[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, parr) <= 0)
            goto err;
    } else if (strcmp(alg_name, "RSA") == 0) {
        /* The only RSA classical component in the hybrid sigs is RSA-3072. */
        size_t bits = 3072;
        OSSL_PARAM parr[2];

        parr[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits);
        parr[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, parr) <= 0)
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

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const char *pq_propq;       /* borrowed from provctx */
    const char *classic_propq;  /* borrowed from provctx */
    int selection;
    int is_kem;
    unsigned int algo_idx;
} HYBRID_GEN_CTX;

static void *hybrid_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    HYBRID_GEN_CTX *gctx = vgctx;
    HYBRID_KEY *key;
    char *propq;

    if (gctx == NULL)
        return NULL;

    propq = gctx->propq;
    gctx->propq = NULL;
    key = hybrid_key_new(gctx->is_kem, gctx->algo_idx, gctx->libctx, propq);
    if (key == NULL)
        return NULL;
    key->pq_propq = gctx->pq_propq;
    key->classic_propq = gctx->classic_propq;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    key->key2 = hybrid_component_keygen(key->libctx, HYBRID_KEY_PQ_PROPQ(key),
                                        HYBRID_KEY_ALG2_NAME(key), NULL);
    key->key1 = hybrid_component_keygen(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                                        HYBRID_KEY_ALG1_NAME(key),
                                        HYBRID_KEY_ALG1_GROUP(key));

    if (key->key1 != NULL && key->key2 != NULL) {
        key->state = HYBRID_HAVE_PRVKEY;
        return key;
    }

    hybrid_key_free(key);
    return NULL;
}

static void hybrid_gen_cleanup(void *vgctx)
{
    HYBRID_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static const OSSL_PARAM gen_settable[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static int hybrid_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    HYBRID_GEN_CTX *gctx = vgctx;
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

static const OSSL_PARAM *hybrid_gen_settable_params(void *vgctx,
                                                      void *provctx)
{
    return gen_settable;
}

/*
 * Macro to declare per-algorithm keymgmt_new and keymgmt_gen_init,
 * plus the dispatch table. is_kem_val: 1=KEM, 0=SIG.
 */
#define DECLARE_HYBRID_KMGMT(name, is_kem_val, variant)                      \
    static void *hybrid_##name##_new(void *provctx)                          \
    {                                                                        \
        HYBRID_PROV_CTX *ctx = provctx;                                      \
        OSSL_LIB_CTX *libctx =                                               \
            ctx ? HYBRID_COMPONENT_LIBCTX(ctx) : NULL;                       \
        HYBRID_KEY *k = hybrid_key_new(is_kem_val, variant, libctx, NULL);   \
        if (k != NULL && ctx != NULL) {                                      \
            k->pq_propq = ctx->pq_propq;                                     \
            k->classic_propq = ctx->classic_propq;                          \
        }                                                                    \
        return k;                                                            \
    }                                                                        \
    static void *hybrid_##name##_gen_init(void *provctx, int selection,      \
                                          const OSSL_PARAM params[])         \
    {                                                                        \
        HYBRID_PROV_CTX *pctx = provctx;                                     \
        HYBRID_GEN_CTX *gctx;                                               \
        if (pctx == NULL || (selection & (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS \
                | OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) == 0)                    \
            return NULL;                                                     \
        gctx = OPENSSL_zalloc(sizeof(*gctx));                                \
        if (gctx == NULL) return NULL;                                       \
        gctx->is_kem = is_kem_val;                                          \
        gctx->algo_idx = variant;                                            \
        gctx->libctx = HYBRID_COMPONENT_LIBCTX(pctx);                       \
        gctx->pq_propq = pctx->pq_propq;                                     \
        gctx->classic_propq = pctx->classic_propq;                          \
        gctx->selection = selection;                                         \
        if (!hybrid_gen_set_params(gctx, params)) {                          \
            hybrid_gen_cleanup(gctx);                                        \
            return NULL;                                                     \
        }                                                                    \
        return gctx;                                                         \
    }                                                                        \
    const OSSL_DISPATCH hybrid_##name##_kmgmt_functions[] = {                \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hybrid_##name##_new },      \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))hybrid_key_load },         \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hybrid_key_free },         \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hybrid_kem_has },           \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hybrid_kem_match },       \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))hybrid_kem_dup },           \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hybrid_import },         \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                   \
          (void (*)(void))hybrid_kem_imexport_types },                       \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hybrid_export },         \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                   \
          (void (*)(void))hybrid_kem_imexport_types },                       \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                     \
          (void (*)(void))hybrid_get_params_fn },                            \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                \
          (void (*)(void))hybrid_kem_gettable_params },                      \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                     \
          (void (*)(void))hybrid_set_params_fn },                            \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                \
          (void (*)(void))hybrid_kem_settable_params },                      \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,                                       \
          (void (*)(void))hybrid_##name##_gen_init },                        \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                 \
          (void (*)(void))hybrid_gen_set_params },                           \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                            \
          (void (*)(void))hybrid_gen_settable_params },                      \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))hybrid_gen },               \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                    \
          (void (*)(void))hybrid_gen_cleanup },                              \
        { 0, NULL }                                                          \
    }

/* KEM keymgmt instances — generated from the master list in hybrid_prov.h.
 * Each row binds its keymgmt thunks to the matching info-table index. */
#define HYBRID_KEM_KMGMT_ROW(cf, ...) \
    DECLARE_HYBRID_KMGMT(cf, 1, HYBRID_KEM_IDX_##cf);
HYBRID_KEM_LIST(HYBRID_KEM_KMGMT_ROW)
#undef HYBRID_KEM_KMGMT_ROW

/* Signature keymgmt instances — generated from the master list. */
#define HYBRID_SIG_KMGMT_ROW(cf, ...) \
    DECLARE_HYBRID_KMGMT(cf, 0, HYBRID_SIG_IDX_##cf);
HYBRID_SIG_LIST(HYBRID_SIG_KMGMT_ROW)
#undef HYBRID_SIG_KMGMT_ROW
