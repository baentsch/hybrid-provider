/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid key encoders (M2). First slice: SubjectPublicKeyInfo in DER and PEM,
 * byte-compatible with oqsprovider so the two interoperate on key files.
 *
 * SPKI = AlgorithmIdentifier(OID) + BIT STRING(pubblob), where
 *   pubblob = ENCODE_UINT32(classical_pub_len)
 *             || classical_pub || pq_pub          (alg2_slot == 1, classical first)
 *             || pq_pub || classical_pub          (alg2_slot == 0, PQ first)
 * The UINT32 always encodes the classical component length; the classical part
 * is the raw EC point / X25519 key. Signature hybrids are always classical-first.
 */

#include "hybrid_prov.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/encoder.h>

/* OID string for a key (signature hybrids carry it in their info table). */
static const char *hybrid_key_oid(const HYBRID_KEY *key)
{
    if (key->is_kem)
        return NULL;    /* KEM OIDs added in a later slice */
    return ((const HYBRID_SIG_INFO *)key->info)->oid;
}

/*
 * Build the oqsprovider public-key blob (UINT32 classical-length prefix +
 * ordered component public keys). Caller frees *out.
 */
int hybrid_encode_pub_blob(HYBRID_KEY *key, unsigned char **out, size_t *outlen)
{
    size_t a1, a2, total, got;
    unsigned char *buf, *classical, *pq;
    int pq_first;

    if (!hybrid_ensure_sizes(key) || !hybrid_have_pubkey(key))
        return 0;
    a1 = key->sizes.a1_pub;
    a2 = key->sizes.a2_pub;
    total = sizeof(uint32_t) + a1 + a2;

    if ((buf = OPENSSL_malloc(total)) == NULL)
        return 0;

    /* UINT32 big-endian classical public-key length */
    buf[0] = (unsigned char)(a1 >> 24);
    buf[1] = (unsigned char)(a1 >> 16);
    buf[2] = (unsigned char)(a1 >> 8);
    buf[3] = (unsigned char)(a1);

    /* Reverse-share KEMs (alg2_slot == 0) place the PQ share first. */
    pq_first = key->is_kem
            && ((const HYBRID_KEM_INFO *)key->info)->alg2_slot == 0;
    if (pq_first) {
        pq = buf + sizeof(uint32_t);
        classical = buf + sizeof(uint32_t) + a2;
    } else {
        classical = buf + sizeof(uint32_t);
        pq = buf + sizeof(uint32_t) + a1;
    }

    if (EVP_PKEY_get_octet_string_param(key->key1, OSSL_PKEY_PARAM_PUB_KEY,
                                        classical, a1, &got) <= 0 || got != a1
        || EVP_PKEY_get_octet_string_param(key->key2, OSSL_PKEY_PARAM_PUB_KEY,
                                           pq, a2, &got) <= 0 || got != a2) {
        OPENSSL_free(buf);
        return 0;
    }
    *out = buf;
    *outlen = total;
    return 1;
}

/* Build an X509_PUBKEY (AlgId(OID) + BIT STRING(blob)) for the key. */
static X509_PUBKEY *hybrid_key_to_x509_pubkey(HYBRID_KEY *key)
{
    X509_PUBKEY *xpk = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *blob = NULL;
    size_t bloblen = 0;
    const char *oidstr = hybrid_key_oid(key);

    if (oidstr == NULL
        || (oid = OBJ_txt2obj(oidstr, 1)) == NULL
        || !hybrid_encode_pub_blob(key, &blob, &bloblen)
        || (xpk = X509_PUBKEY_new()) == NULL)
        goto err;

    /* Transfers ownership of oid and blob to xpk. */
    if (!X509_PUBKEY_set0_param(xpk, oid, V_ASN1_UNDEF, NULL, blob,
                                (int)bloblen))
        goto err;
    return xpk;
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
} HYBRID_ENC_CTX;

static void *hybrid_enc_newctx(void *provctx)
{
    HYBRID_PROV_CTX *pctx = provctx;
    HYBRID_ENC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL && pctx != NULL) {
        ctx->libctx = pctx->libctx;
        ctx->bio_write_ex = pctx->bio_write_ex;
    }
    return ctx;
}

static void hybrid_enc_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int hybrid_enc_does_selection(void *provctx, int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int hybrid_encode_spki(void *vctx, OSSL_CORE_BIO *cout, const void *key,
                              const OSSL_PARAM key_abstract[], int selection,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg, int pem)
{
    HYBRID_ENC_CTX *ctx = vctx;
    HYBRID_KEY *hkey = (HYBRID_KEY *)key;
    X509_PUBKEY *xpk = NULL;
    BIO *mem = NULL;
    char *data = NULL;
    long datalen;
    size_t written = 0;
    int ret = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0
        || ctx->bio_write_ex == NULL)
        return 0;

    /*
     * Render into a plain memory BIO, then push the bytes to the core BIO via
     * the captured BIO_write_ex up-call (avoids needing a core-BIO method).
     */
    if ((mem = BIO_new(BIO_s_mem())) == NULL
        || (xpk = hybrid_key_to_x509_pubkey(hkey)) == NULL)
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

static int hybrid_encode_spki_der(void *vctx, OSSL_CORE_BIO *cout,
                                  const void *key,
                                  const OSSL_PARAM key_abstract[], int selection,
                                  OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return hybrid_encode_spki(vctx, cout, key, key_abstract, selection,
                              cb, cbarg, 0);
}

static int hybrid_encode_spki_pem(void *vctx, OSSL_CORE_BIO *cout,
                                  const void *key,
                                  const OSSL_PARAM key_abstract[], int selection,
                                  OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return hybrid_encode_spki(vctx, cout, key, key_abstract, selection,
                              cb, cbarg, 1);
}

const OSSL_DISPATCH hybrid_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))hybrid_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))hybrid_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))hybrid_enc_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))hybrid_encode_spki_der },
    { 0, NULL }
};

const OSSL_DISPATCH hybrid_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))hybrid_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))hybrid_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))hybrid_enc_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))hybrid_encode_spki_pem },
    { 0, NULL }
};
