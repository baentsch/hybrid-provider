/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    HYBRID_KEY *key;
    int op;
} HYBRID_KEM_CTX;

static void *hybrid_kem_newctx(void *provctx)
{
    HYBRID_KEM_CTX *ctx;
    HYBRID_PROV_CTX *pctx = provctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->libctx = pctx ? pctx->libctx : NULL;
    return ctx;
}

static void hybrid_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int
hybrid_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (!hybrid_have_pubkey(key))
        return 0;
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_ENCAPSULATE;
    return 1;
}

static int
hybrid_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (!hybrid_have_prvkey(key))
        return 0;
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_DECAPSULATE;
    return 1;
}

/*
 * Encapsulate for a key-exchange component (X25519/ECDH):
 * Generate ephemeral keypair, put public key into ctext, derive shared secret.
 */
static int
encap_keyexchange(OSSL_LIB_CTX *libctx, const char *propq,
                  EVP_PKEY *peer_pub,
                  uint8_t *ctext, size_t *ctlen,
                  uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *ephemeral = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    size_t publen, derlen;
    int ret = 0;

    /* Generate ephemeral key from the peer's key parameters */
    kctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer_pub, propq);
    if (kctx == NULL
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_keygen(kctx, &ephemeral) <= 0)
        goto end;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* Extract ephemeral public key as "ciphertext" */
    publen = *ctlen;
    if (EVP_PKEY_get_octet_string_param(ephemeral,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            ctext, publen, &publen) <= 0)
        goto end;
    if (publen != *ctlen)
        goto end;

    /* Derive shared secret: ephemeral private + peer public */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, ephemeral, propq);
    if (dctx == NULL
        || EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        goto end;

    derlen = *sslen;
    if (EVP_PKEY_derive(dctx, shsec, &derlen) <= 0)
        goto end;
    if (derlen != *sslen)
        goto end;

    ret = 1;
end:
    EVP_PKEY_free(ephemeral);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/*
 * Decapsulate for a key-exchange component:
 * Load peer public key from ctext, derive shared secret with our private key.
 */
static int
decap_keyexchange(OSSL_LIB_CTX *libctx, const char *propq,
                  EVP_PKEY *own_prv,
                  const uint8_t *ctext, size_t ctlen,
                  uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY *peer_pub = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    size_t derlen;
    int ret = 0;

    /* Reconstruct peer public key from ciphertext */
    peer_pub = EVP_PKEY_new();
    if (peer_pub == NULL
        || EVP_PKEY_copy_parameters(peer_pub, own_prv) <= 0
        || EVP_PKEY_set1_encoded_public_key(peer_pub, ctext, ctlen) <= 0)
        goto end;

    /* Derive shared secret: our private + peer public */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, own_prv, propq);
    if (dctx == NULL
        || EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        goto end;

    derlen = *sslen;
    if (EVP_PKEY_derive(dctx, shsec, &derlen) <= 0)
        goto end;
    if (derlen != *sslen)
        goto end;

    ret = 1;
end:
    EVP_PKEY_free(peer_pub);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/*
 * Encapsulate for a native KEM component (ML-KEM).
 */
static int
encap_kem(OSSL_LIB_CTX *libctx, const char *propq,
          EVP_PKEY *pub_key,
          uint8_t *ctext, size_t *ctlen,
          uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY_CTX *ctx;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub_key, propq);
    if (ctx == NULL
        || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, ctext, ctlen, shsec, sslen) <= 0)
        goto end;
    ret = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Decapsulate for a native KEM component (ML-KEM).
 */
static int
decap_kem(OSSL_LIB_CTX *libctx, const char *propq,
          EVP_PKEY *prv_key,
          const uint8_t *ctext, size_t ctlen,
          uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY_CTX *ctx;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, prv_key, propq);
    if (ctx == NULL
        || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, shsec, sslen, ctext, ctlen) <= 0)
        goto end;
    ret = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int hybrid_kem_encapsulate(void *vctx,
                                  unsigned char *ctext, size_t *clen,
                                  unsigned char *shsec, size_t *slen)
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_KEM_INFO *info = (const HYBRID_KEM_INFO *)key->info;
    size_t total_clen, total_slen;
    uint8_t *ct1, *ct2, *ss1, *ss2;
    size_t ct1len, ct2len, ss1len, ss2len;
    int ret = 0;

    if (!hybrid_have_pubkey(key))
        return 0;

    /*
     * For key-exchange alg1, "ciphertext" = ephemeral public key.
     * For native KEM alg2, ciphertext = KEM ciphertext.
     */
    if (!hybrid_kem_ensure_sizes(key))
        return 0;
    ct1len = key->sizes.a1_ct;
    ct2len = key->sizes.a2_ct;
    ss1len = key->sizes.a1_ss;
    ss2len = key->sizes.a2_ss;
    total_clen = ct1len + ct2len;
    total_slen = ss1len + ss2len;

    /* Size query */
    if (ctext == NULL) {
        if (clen != NULL) *clen = total_clen;
        if (slen != NULL) *slen = total_slen;
        return 1;
    }
    if (shsec == NULL || clen == NULL || slen == NULL)
        return 0;
    if (*clen < total_clen || *slen < total_slen)
        return 0;
    *clen = total_clen;
    *slen = total_slen;

    /*
     * Slot ordering:
     * If alg2_slot == 0: [alg2_ct | alg1_ct], [alg2_ss | alg1_ss]
     * If alg2_slot == 1: [alg1_ct | alg2_ct], [alg1_ss | alg2_ss]
     */
    if (info->alg2_slot == 0) {
        ct2 = ctext;
        ct1 = ctext + ct2len;
        ss2 = shsec;
        ss1 = shsec + ss2len;
    } else {
        ct1 = ctext;
        ct2 = ctext + ct1len;
        ss1 = shsec;
        ss2 = shsec + ss1len;
    }

    /* Encapsulate alg2 (PQ KEM) */
    if (info->alg2_is_kem) {
        if (!encap_kem(key->libctx, HYBRID_KEY_PQ_PROPQ(key), key->key2,
                       ct2, &ct2len, ss2, &ss2len))
            goto err;
    }

    /* Encapsulate alg1 (key-exchange or KEM) */
    if (info->alg1_is_kem) {
        if (!encap_kem(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key), key->key1,
                       ct1, &ct1len, ss1, &ss1len))
            goto err;
    } else {
        if (!encap_keyexchange(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                               key->key1, ct1, &ct1len, ss1, &ss1len))
            goto err;
    }

    return 1;

err:
    /* Don't leave a partial shared secret in the caller's buffer. */
    OPENSSL_cleanse(shsec, total_slen);
    return 0;
}

static int hybrid_kem_decapsulate(void *vctx,
                                  unsigned char *shsec, size_t *slen,
                                  const unsigned char *ctext, size_t clen)
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_KEM_INFO *info = (const HYBRID_KEM_INFO *)key->info;
    size_t total_clen, total_slen;
    const uint8_t *ct1, *ct2;
    uint8_t *ss1, *ss2;
    size_t ct1len, ct2len, ss1len, ss2len;

    if (!hybrid_have_prvkey(key))
        return 0;

    if (!hybrid_kem_ensure_sizes(key))
        return 0;
    ct1len = key->sizes.a1_ct;
    ct2len = key->sizes.a2_ct;
    ss1len = key->sizes.a1_ss;
    ss2len = key->sizes.a2_ss;
    total_clen = ct1len + ct2len;
    total_slen = ss1len + ss2len;

    /* Size query */
    if (shsec == NULL) {
        if (slen != NULL) *slen = total_slen;
        return 1;
    }
    if (slen == NULL)
        return 0;
    if (*slen < total_slen)
        return 0;
    if (clen != total_clen)
        return 0;
    *slen = total_slen;

    /* Slot ordering */
    if (info->alg2_slot == 0) {
        ct2 = ctext;
        ct1 = ctext + ct2len;
        ss2 = shsec;
        ss1 = shsec + ss2len;
    } else {
        ct1 = ctext;
        ct2 = ctext + ct1len;
        ss1 = shsec;
        ss2 = shsec + ss1len;
    }

    /* Decapsulate alg2 (PQ KEM) */
    if (info->alg2_is_kem) {
        if (!decap_kem(key->libctx, HYBRID_KEY_PQ_PROPQ(key), key->key2,
                       ct2, ct2len, ss2, &ss2len))
            goto err;
    }

    /* Decapsulate alg1 (key-exchange or KEM) */
    if (info->alg1_is_kem) {
        if (!decap_kem(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key), key->key1,
                       ct1, ct1len, ss1, &ss1len))
            goto err;
    } else {
        if (!decap_keyexchange(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                               key->key1, ct1, ct1len, ss1, &ss1len))
            goto err;
    }

    return 1;

err:
    /* Don't leave a partial shared secret in the caller's buffer. */
    OPENSSL_cleanse(shsec, total_slen);
    return 0;
}

static const OSSL_PARAM *hybrid_kem_settable_ctx_params(void *vctx,
                                                         void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };
    return params;
}

static int hybrid_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

const OSSL_DISPATCH hybrid_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))hybrid_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))hybrid_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))hybrid_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))hybrid_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))hybrid_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))hybrid_kem_decapsulate },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))hybrid_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))hybrid_kem_settable_ctx_params },
    { 0, NULL }
};
