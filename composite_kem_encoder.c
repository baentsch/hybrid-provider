/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM key encoders — the KEM analogue of
 * composite_encoder.c. Per draft-18 the composite public key is the raw
 * CONCATENATION mlkemPK || tradPK and the private key is mlkemSeed || tradSK (no
 * length prefix — component sizes are fixed per OID), carried under the single
 * composite OID:
 *   SPKI  = SEQUENCE { AlgorithmIdentifier{ compositeOID }, BIT STRING(mlkemPK||tradPK) }
 *   PKCS8 = the raw mlkemSeed||tradSK carried DIRECTLY as the privateKey OCTET
 *           STRING content under the composite OID (LAMPS single-wrap).
 */
#include "composite_kem_prov.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

/* A component's raw public key: the PUB_KEY octet (ML-KEM / EC point / X raw), or
 * i2d_PublicKey for RSA (which has no octet param). Caller frees *buf. */
static int component_pub(EVP_PKEY *pkey, unsigned char **buf, size_t *len)
{
    size_t n = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, &n) > 0 && n > 0) {
        if ((*buf = OPENSSL_malloc(n)) == NULL
                || EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                                   *buf, n, len) <= 0) {
            OPENSSL_free(*buf);
            *buf = NULL;
            return 0;
        }
        return 1;
    }
    ERR_clear_error();
    {
        unsigned char *der = NULL;
        int dlen = i2d_PublicKey(pkey, &der);

        if (dlen <= 0)
            return 0;
        *buf = der;
        *len = (size_t)dlen;
        return 1;
    }
}

int composite_kem_encode_pub_blob(COMPOSITE_KEM_KEY *key, unsigned char **out,
                                  size_t *outlen)
{
    unsigned char *pqbuf = NULL, *trbuf = NULL, *buf = NULL;
    size_t pqlen = 0, trlen = 0;
    int ret = 0;

    if (key->state < COMPOSITE_KEM_HAVE_PUBKEY)
        return 0;
    if (!component_pub(key->pq_key, &pqbuf, &pqlen)
            || !component_pub(key->trad_key, &trbuf, &trlen))
        goto end;
    if ((buf = OPENSSL_malloc(pqlen + trlen)) == NULL)
        goto end;
    memcpy(buf, pqbuf, pqlen);              /* ML-KEM first, then classical */
    memcpy(buf + pqlen, trbuf, trlen);
    *out = buf;
    *outlen = pqlen + trlen;
    buf = NULL;
    ret = 1;
end:
    OPENSSL_free(pqbuf);
    OPENSSL_free(trbuf);
    OPENSSL_free(buf);
    return ret;
}

/* X509_PUBKEY = AlgorithmIdentifier(compositeOID) + BIT STRING(pub blob). */
static X509_PUBKEY *key_to_x509_pubkey(COMPOSITE_KEM_KEY *key)
{
    X509_PUBKEY *xpk = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *blob = NULL;
    size_t bloblen = 0;

    if (key->info->oid == NULL
            || (oid = OBJ_txt2obj(key->info->oid, 1)) == NULL
            || !composite_kem_encode_pub_blob(key, &blob, &bloblen)
            || (xpk = X509_PUBKEY_new()) == NULL)
        goto err;
    if (!X509_PUBKEY_set0_param(xpk, oid, V_ASN1_UNDEF, NULL, blob,
                                (int)bloblen))
        goto err;
    return xpk;                            /* oid + blob owned by xpk */
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(blob);
    X509_PUBKEY_free(xpk);
    return NULL;
}

/* --- Encoder context --- */

typedef struct {
    OSSL_LIB_CTX *libctx;
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex;
} COMPOSITE_KEM_ENC_CTX;

static void *composite_kem_enc_newctx(void *provctx)
{
    HYBRID_PROV_CTX *pctx = provctx;
    COMPOSITE_KEM_ENC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL && pctx != NULL) {
        ctx->libctx = pctx->libctx;
        ctx->bio_write_ex = pctx->bio_write_ex;
    }
    return ctx;
}

static void composite_kem_enc_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int composite_kem_enc_does_selection_pub(void *provctx, int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int composite_kem_encode_spki(void *vctx, OSSL_CORE_BIO *cout,
                                     const void *key,
                                     const OSSL_PARAM key_abstract[],
                                     int selection,
                                     OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg,
                                     int pem)
{
    COMPOSITE_KEM_ENC_CTX *ctx = vctx;
    X509_PUBKEY *xpk = NULL;
    BIO *mem = NULL;
    char *data = NULL;
    long datalen;
    size_t written = 0;
    int ret = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0
            || ctx->bio_write_ex == NULL)
        return 0;
    if ((mem = BIO_new(BIO_s_mem())) == NULL
            || (xpk = key_to_x509_pubkey((COMPOSITE_KEM_KEY *)key)) == NULL)
        goto end;
    if ((pem ? PEM_write_bio_X509_PUBKEY(mem, xpk)
             : i2d_X509_PUBKEY_bio(mem, xpk)) <= 0)
        goto end;
    datalen = BIO_get_mem_data(mem, &data);
    if (datalen <= 0)
        goto end;
    ret = ctx->bio_write_ex(cout, data, (size_t)datalen, &written)
          && written == (size_t)datalen;
end:
    X509_PUBKEY_free(xpk);
    BIO_free(mem);
    return ret;
}

static int composite_kem_encode_spki_der(void *vctx, OSSL_CORE_BIO *cout,
                                         const void *key,
                                         const OSSL_PARAM key_abstract[],
                                         int selection,
                                         OSSL_PASSPHRASE_CALLBACK *cb,
                                         void *cbarg)
{
    return composite_kem_encode_spki(vctx, cout, key, key_abstract, selection,
                                     cb, cbarg, 0);
}

static int composite_kem_encode_spki_pem(void *vctx, OSSL_CORE_BIO *cout,
                                         const void *key,
                                         const OSSL_PARAM key_abstract[],
                                         int selection,
                                         OSSL_PASSPHRASE_CALLBACK *cb,
                                         void *cbarg)
{
    return composite_kem_encode_spki(vctx, cout, key, key_abstract, selection,
                                     cb, cbarg, 1);
}

const OSSL_DISPATCH composite_kem_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))composite_kem_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))composite_kem_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))composite_kem_enc_does_selection_pub },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))composite_kem_encode_spki_der },
    { 0, NULL }
};

const OSSL_DISPATCH composite_kem_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))composite_kem_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))composite_kem_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))composite_kem_enc_does_selection_pub },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))composite_kem_encode_spki_pem },
    { 0, NULL }
};

/* --- PKCS#8 (PrivateKeyInfo) encoders --- */

/* One classical private component: raw for raw-key types (X), else i2d DER. */
static int component_priv(EVP_PKEY *pkey, unsigned char **buf, size_t *len)
{
    size_t n = 0;
    unsigned char *der = NULL;
    int dlen;

    if (EVP_PKEY_get_raw_private_key(pkey, NULL, &n) > 0 && n > 0) {
        if ((*buf = OPENSSL_malloc(n)) == NULL
                || EVP_PKEY_get_raw_private_key(pkey, *buf, &n) <= 0) {
            OPENSSL_clear_free(*buf, n);
            *buf = NULL;
            return 0;
        }
        *len = n;
        return 1;
    }
    ERR_clear_error();
    if ((dlen = i2d_PrivateKey(pkey, &der)) <= 0)
        return 0;
    *buf = der;
    *len = (size_t)dlen;
    return 1;
}

/* PQ private material: the param named by the row (the ML-KEM seed for
 * standardized combos; a different seed param or the raw private key for a future
 * non-ML-KEM combo). No ML-KEM assumption. */
static int component_pq_priv(EVP_PKEY *pq, const COMPOSITE_KEM_INFO *info,
                             unsigned char **buf, size_t *len)
{
    const char *param = info->pq_priv_param;
    size_t n = 0;

    if (EVP_PKEY_get_octet_string_param(pq, param, NULL, 0, &n) <= 0 || n == 0)
        return 0;
    if ((*buf = OPENSSL_malloc(n)) == NULL
            || EVP_PKEY_get_octet_string_param(pq, param, *buf, n, len) <= 0) {
        OPENSSL_clear_free(*buf, n);
        *buf = NULL;
        return 0;
    }
    return 1;
}

int composite_kem_encode_priv_blob(COMPOSITE_KEM_KEY *key, unsigned char **out,
                                   size_t *outlen)
{
    unsigned char *pqbuf = NULL, *trbuf = NULL, *buf = NULL;
    size_t pqlen = 0, trlen = 0;
    int ret = 0;

    if (key->state < COMPOSITE_KEM_HAVE_PRVKEY)
        return 0;
    if (!component_pq_priv(key->pq_key, key->info, &pqbuf, &pqlen)
            || !component_priv(key->trad_key, &trbuf, &trlen))
        goto end;
    if ((buf = OPENSSL_malloc(pqlen + trlen)) == NULL)
        goto end;
    memcpy(buf, pqbuf, pqlen);
    memcpy(buf + pqlen, trbuf, trlen);
    *out = buf;
    *outlen = pqlen + trlen;
    buf = NULL;
    ret = 1;
end:
    OPENSSL_clear_free(pqbuf, pqlen);
    OPENSSL_clear_free(trbuf, trlen);
    OPENSSL_clear_free(buf, pqlen + trlen);
    return ret;
}

static PKCS8_PRIV_KEY_INFO *key_to_p8info(COMPOSITE_KEM_KEY *key)
{
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *blob = NULL;
    size_t bloblen = 0;

    if (key->info->oid == NULL
            || (oid = OBJ_txt2obj(key->info->oid, 1)) == NULL
            || !composite_kem_encode_priv_blob(key, &blob, &bloblen)
            || (p8 = PKCS8_PRIV_KEY_INFO_new()) == NULL)
        goto err;
    if (!PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, blob, (int)bloblen))
        goto err;
    return p8;
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_clear_free(blob, bloblen);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
}

static int composite_kem_enc_does_selection_priv(void *provctx, int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int composite_kem_encode_pkcs8(void *vctx, OSSL_CORE_BIO *cout,
                                      const void *key,
                                      const OSSL_PARAM key_abstract[],
                                      int selection,
                                      OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg,
                                      int pem)
{
    COMPOSITE_KEM_ENC_CTX *ctx = vctx;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    BIO *mem = NULL;
    char *data = NULL;
    long datalen;
    size_t written = 0;
    int ret = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0
            || ctx->bio_write_ex == NULL)
        return 0;
    if ((mem = BIO_new(BIO_s_mem())) == NULL
            || (p8 = key_to_p8info((COMPOSITE_KEM_KEY *)key)) == NULL)
        goto end;
    if ((pem ? PEM_write_bio_PKCS8_PRIV_KEY_INFO(mem, p8)
             : i2d_PKCS8_PRIV_KEY_INFO_bio(mem, p8)) <= 0)
        goto end;
    datalen = BIO_get_mem_data(mem, &data);
    if (datalen <= 0)
        goto end;
    ret = ctx->bio_write_ex(cout, data, (size_t)datalen, &written)
          && written == (size_t)datalen;
end:
    PKCS8_PRIV_KEY_INFO_free(p8);
    BIO_free(mem);
    return ret;
}

static int composite_kem_encode_pkcs8_der(void *vctx, OSSL_CORE_BIO *cout,
                                          const void *key,
                                          const OSSL_PARAM key_abstract[],
                                          int selection,
                                          OSSL_PASSPHRASE_CALLBACK *cb,
                                          void *cbarg)
{
    return composite_kem_encode_pkcs8(vctx, cout, key, key_abstract, selection,
                                      cb, cbarg, 0);
}

static int composite_kem_encode_pkcs8_pem(void *vctx, OSSL_CORE_BIO *cout,
                                          const void *key,
                                          const OSSL_PARAM key_abstract[],
                                          int selection,
                                          OSSL_PASSPHRASE_CALLBACK *cb,
                                          void *cbarg)
{
    return composite_kem_encode_pkcs8(vctx, cout, key, key_abstract, selection,
                                      cb, cbarg, 1);
}

const OSSL_DISPATCH composite_kem_pkcs8_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))composite_kem_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))composite_kem_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))composite_kem_enc_does_selection_priv },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))composite_kem_encode_pkcs8_der },
    { 0, NULL }
};

const OSSL_DISPATCH composite_kem_pkcs8_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))composite_kem_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))composite_kem_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))composite_kem_enc_does_selection_priv },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))composite_kem_encode_pkcs8_pem },
    { 0, NULL }
};

/* --- Human-readable text encoder (openssl pkey -text) --- */

static int composite_kem_text_block(BIO *mem, const char *label,
                                    const unsigned char *buf, size_t len)
{
    return BIO_printf(mem, "%s key material:\n", label) > 0
           && ASN1_buf_print(mem, buf, len, 4) > 0;
}

static int composite_kem_enc_does_selection_text(void *provctx, int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
}

static int composite_kem_encode_text(void *vctx, OSSL_CORE_BIO *cout,
                                     const void *key,
                                     const OSSL_PARAM key_abstract[],
                                     int selection,
                                     OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    COMPOSITE_KEM_ENC_CTX *ctx = vctx;
    COMPOSITE_KEM_KEY *ckey = (COMPOSITE_KEM_KEY *)key;
    const COMPOSITE_KEM_INFO *info = ckey->info;
    BIO *mem = NULL;
    unsigned char *pqbuf = NULL, *trbuf = NULL;
    size_t pqlen = 0, trlen = 0;
    const char *tname;
    int priv, ret = 0;
    char *data = NULL;
    long datalen;
    size_t written = 0;

    if (ctx->bio_write_ex == NULL)
        return 0;
    priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
           && ckey->state >= COMPOSITE_KEM_HAVE_PRVKEY;

    if (priv) {
        if (!component_pq_priv(ckey->pq_key, info, &pqbuf, &pqlen)
            || !component_priv(ckey->trad_key, &trbuf, &trlen))
            goto end;
    } else if (ckey->state < COMPOSITE_KEM_HAVE_PUBKEY
            || !component_pub(ckey->pq_key, &pqbuf, &pqlen)
            || !component_pub(ckey->trad_key, &trbuf, &trlen)) {
        goto end;
    }

    tname = info->trad_group != NULL ? info->trad_group : info->trad_alg;
    if ((mem = BIO_new(BIO_s_mem())) == NULL
        || BIO_printf(mem, "%s composite %s key:\n", info->name,
                      priv ? "private" : "public") <= 0
        || !composite_kem_text_block(mem, info->pq_alg, pqbuf, pqlen)
        || !composite_kem_text_block(mem, tname, trbuf, trlen))
        goto end;

    datalen = BIO_get_mem_data(mem, &data);
    if (datalen <= 0)
        goto end;
    ret = ctx->bio_write_ex(cout, data, (size_t)datalen, &written)
          && written == (size_t)datalen;
end:
    OPENSSL_clear_free(pqbuf, pqlen);
    OPENSSL_clear_free(trbuf, trlen);
    BIO_free(mem);
    return ret;
}

const OSSL_DISPATCH composite_kem_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))composite_kem_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))composite_kem_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))composite_kem_enc_does_selection_text },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))composite_kem_encode_text },
    { 0, NULL }
};
