/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM key decoder — the KEM analogue of composite_decoder.c.
 * DER SubjectPublicKeyInfo / PKCS#8 -> composite ML-KEM key: read the structure,
 * match the AlgorithmIdentifier OID against the composite-KEM table, split the raw
 * concat (mlkemPK||tradPK or mlkemSeed||tradSK — the ML-KEM part is fixed-size),
 * and rebuild both components. Uses the shared non-eager hybrid_spki_parse() (not
 * d2i_X509_PUBKEY, whose eager decode would recurse and crash) — same rule as the
 * hybrid and composite-sig decoders.
 */
#include "composite_kem_prov.h"
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <string.h>

typedef struct {
    HYBRID_PROV_CTX *provctx;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex;
} COMPOSITE_KEM_DEC_CTX;

static void *composite_kem_dec_newctx(void *provctx)
{
    HYBRID_PROV_CTX *pctx = provctx;
    COMPOSITE_KEM_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = pctx;
        ctx->bio_read_ex = pctx != NULL ? pctx->bio_read_ex : NULL;
    }
    return ctx;
}

static void composite_kem_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int composite_kem_dec_does_selection_pub(void *provctx, int selection)
{
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

#define COMPOSITE_KEM_MAX_KEY_DER  (1024 * 1024)
#define COMPOSITE_KEM_DEC_READ_CHUNK  4096
#define COMPOSITE_KEM_OID_TXT_MAX  128
static int read_all(COMPOSITE_KEM_DEC_CTX *ctx, OSSL_CORE_BIO *cin,
                    unsigned char **out, size_t *outlen)
{
    size_t cap = COMPOSITE_KEM_DEC_READ_CHUNK, len = 0, n = 0;
    unsigned char *buf = OPENSSL_malloc(cap), *tmp;

    if (buf == NULL || ctx->bio_read_ex == NULL) {
        OPENSSL_free(buf);
        return 0;
    }
    for (;;) {
        if (len == cap) {
            if (cap > COMPOSITE_KEM_MAX_KEY_DER) {
                OPENSSL_free(buf);
                return 0;
            }
            if ((tmp = OPENSSL_realloc(buf, cap * 2)) == NULL) {
                OPENSSL_free(buf);
                return 0;
            }
            buf = tmp;
            cap *= 2;
        }
        if (!ctx->bio_read_ex(cin, buf + len, cap - len, &n) || n == 0)
            break;
        len += n;
    }
    *out = buf;
    *outlen = len;
    return 1;
}

/* Table index whose OID matches, or -1. */
static int index_for_oid(const char *oid)
{
    size_t i;

    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        if (composite_kem_table[i].oid != NULL
                && strcmp(composite_kem_table[i].oid, oid) == 0)
            return (int)i;
    return -1;
}

/* Fixed ML-KEM public-key length for this combo, via a throwaway component key. */
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

/* Fixed PQ private split: the ML-KEM seed (64, standardized) or, for a future
 * non-ML-KEM combo, the component's raw private size. Mirrors the sig family. */
static size_t discover_pq_priv_len(COMPOSITE_KEM_KEY *key)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(key->libctx, key->info->pq_alg,
                                                 key->pq_propq);
    const char *param = key->info->pq_priv_seed ? OSSL_PKEY_PARAM_ML_KEM_SEED
                                                : OSSL_PKEY_PARAM_PRIV_KEY;
    EVP_PKEY *t = NULL;
    size_t n = 0;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &t) > 0)
        EVP_PKEY_get_octet_string_param(t, param, NULL, 0, &n);
    EVP_PKEY_free(t);
    EVP_PKEY_CTX_free(c);
    if (n == 0 && key->info->pq_priv_seed)
        n = COMPOSITE_KEM_MLKEM_SEED_BYTES;
    return n;
}

/* Hand the decoded key back as an object reference (keymgmt LOAD materializes). */
static int handback(COMPOSITE_KEM_KEY **key, int idx, OSSL_CALLBACK *data_cb,
                    void *cbarg)
{
    int object_type = OSSL_OBJECT_PKEY;
    const char *dtype = composite_kem_table[idx].name;
    OSSL_PARAM params[4];
    int r;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)dtype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  key, sizeof(*key));
    params[3] = OSSL_PARAM_construct_end();
    r = data_cb(params, cbarg);
    *key = NULL;
    return r;
}

static int composite_kem_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                                OSSL_CALLBACK *data_cb, void *data_cbarg,
                                OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_KEM_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    const unsigned char *pk = NULL;
    size_t derlen = 0, pqn;
    void *spki = NULL;
    const ASN1_OBJECT *alg_oid = NULL;
    int pklen = 0, idx, ret = 1;           /* default: not ours, continue chain */
    char oidbuf[COMPOSITE_KEM_OID_TXT_MAX];
    COMPOSITE_KEM_KEY *key = NULL;

    if (!read_all(ctx, cin, &der, &derlen) || derlen == 0)
        goto end;
    if ((spki = hybrid_spki_parse(der, derlen, &alg_oid, &pk, &pklen)) == NULL)
        goto end;
    if (alg_oid == NULL
            || OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg_oid, 1) <= 0)
        goto end;
    if ((idx = index_for_oid(oidbuf)) < 0)
        goto end;                          /* OID not ours; continue chain */

    key = composite_kem_keymgmt_new_by_index(ctx->provctx, (size_t)idx);
    if (key == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "composite-KEM decode: cannot instantiate %s", oidbuf);
        ret = 0;
        goto end;
    }
    pqn = discover_pq_pub_len(key);
    if (pqn == 0 || pqn >= (size_t)pklen) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "composite-KEM decode: malformed %s public key", oidbuf);
        ret = 0;
        goto end;
    }
    if (!composite_kem_key_load_pub(key, pk, pqn, pk + pqn,
                                    (size_t)pklen - pqn)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "composite-KEM decode: cannot load %s components", oidbuf);
        ret = 0;
        goto end;
    }
    ret = handback(&key, idx, data_cb, data_cbarg);
end:
    if (key != NULL)
        composite_kem_keymgmt_free(key);
    hybrid_spki_free(spki);
    OPENSSL_free(der);
    return ret;
}

const OSSL_DISPATCH composite_kem_spki_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))composite_kem_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))composite_kem_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))composite_kem_dec_does_selection_pub },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))composite_kem_decode },
    { 0, NULL }
};

/* --- PKCS#8 (PrivateKeyInfo) decoder --- */

static int composite_kem_dec_does_selection_priv(void *provctx, int selection)
{
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int composite_kem_decode_p8(void *vctx, OSSL_CORE_BIO *cin, int selection,
                                   OSSL_CALLBACK *data_cb, void *data_cbarg,
                                   OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_KEM_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    const unsigned char *p, *priv = NULL;
    size_t derlen = 0, pqn;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const ASN1_OBJECT *alg_oid = NULL;
    int privlen = 0, idx, ret = 1;
    char oidbuf[COMPOSITE_KEM_OID_TXT_MAX];
    COMPOSITE_KEM_KEY *key = NULL;

    if (!read_all(ctx, cin, &der, &derlen) || derlen == 0)
        goto end;
    p = der;
    if ((p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)derlen)) == NULL) {
        ERR_clear_error();
        goto end;
    }
    if (!PKCS8_pkey_get0(&alg_oid, &priv, &privlen, NULL, p8)
            || OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg_oid, 1) <= 0)
        goto end;
    if ((idx = index_for_oid(oidbuf)) < 0)
        goto end;

    key = composite_kem_keymgmt_new_by_index(ctx->provctx, (size_t)idx);
    if (key == NULL) {
        ret = 0;
        goto end;
    }
    pqn = discover_pq_priv_len(key);
    if (pqn == 0 || pqn >= (size_t)privlen) {
        ret = 0;
        goto end;
    }
    if (!composite_kem_key_load_prv(key, priv, pqn, priv + pqn,
                                    (size_t)privlen - pqn)) {
        ret = 0;
        goto end;
    }
    ret = handback(&key, idx, data_cb, data_cbarg);
end:
    if (key != NULL)
        composite_kem_keymgmt_free(key);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    return ret;
}

const OSSL_DISPATCH composite_kem_pkcs8_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))composite_kem_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))composite_kem_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))composite_kem_dec_does_selection_priv },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))composite_kem_decode_p8 },
    { 0, NULL }
};
