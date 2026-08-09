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
#include "hybrid_asn1_compat.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/encoder.h>

/* OID string for a key; NULL when the algorithm has no assigned OID (most
 * hybrid KEMs) and is therefore not key-file encodable. */
static const char *hybrid_key_oid(const HYBRID_KEY *key)
{
    return key->is_kem ? ((const HYBRID_KEM_INFO *)key->info)->oid
                       : ((const HYBRID_SIG_INFO *)key->info)->oid;
}

/* Is this a reverse-share KEM (PQ component stored first)? */
static int hybrid_key_reverse(const HYBRID_KEY *key)
{
    return key->is_kem && ((const HYBRID_KEM_INFO *)key->info)->alg2_slot == 0;
}

/*
 * A classical component's private key in oqsprovider's on-wire form: the raw
 * private key for raw-key types (X25519/X448), or i2d_PrivateKey DER otherwise
 * (EC/RSA). Mirrors oqsprovider's raw_key_support branch. Caller frees *buf
 * with OPENSSL_clear_free.
 */
static int get_component_priv(EVP_PKEY *pkey, unsigned char **buf, size_t *len)
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

/*
 * Build the oqsprovider public-key blob (UINT32 classical-length prefix +
 * ordered component public keys). Caller frees *out.
 */
/*
 * Extract a component's public key in oqsprovider's on-wire form: the raw octet
 * (EC point / X25519 key), or i2d_PublicKey for RSA (no octet param). Caller
 * frees *buf with OPENSSL_free.
 */
static int get_component_pub(EVP_PKEY *pkey, unsigned char **buf, size_t *len)
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

int hybrid_encode_pub_blob(HYBRID_KEY *key, unsigned char **out, size_t *outlen)
{
    unsigned char *cbuf = NULL, *pqbuf = NULL, *buf = NULL;
    size_t clen = 0, pqlen = 0, total;
    int pq_first, ret = 0;

    if (!hybrid_have_pubkey(key))
        return 0;
    if (!get_component_pub(key->key1, &cbuf, &clen)
        || !get_component_pub(key->key2, &pqbuf, &pqlen))
        goto end;

    total = sizeof(uint32_t) + clen + pqlen;
    if ((buf = OPENSSL_malloc(total)) == NULL)
        goto end;

    /* UINT32 big-endian classical public-key length */
    buf[0] = (unsigned char)(clen >> 24);
    buf[1] = (unsigned char)(clen >> 16);
    buf[2] = (unsigned char)(clen >> 8);
    buf[3] = (unsigned char)(clen);

    /* Reverse-share KEMs (alg2_slot == 0) place the PQ share first. */
    pq_first = hybrid_key_reverse(key);
    if (pq_first) {
        memcpy(buf + sizeof(uint32_t), pqbuf, pqlen);
        memcpy(buf + sizeof(uint32_t) + pqlen, cbuf, clen);
    } else {
        memcpy(buf + sizeof(uint32_t), cbuf, clen);
        memcpy(buf + sizeof(uint32_t) + clen, pqbuf, pqlen);
    }
    *out = buf;
    *outlen = total;
    buf = NULL;
    ret = 1;
end:
    OPENSSL_free(cbuf);
    OPENSSL_free(pqbuf);
    OPENSSL_free(buf);
    return ret;
}

/*
 * Build the oqsprovider private-key blob:
 *   UINT32(classical_der_len) || classical_privkey_DER || pq_privkey || pq_pubkey
 * The classical private key is i2d_PrivateKey DER (EC/RSA); the PQ private and
 * (appended, matching oqsprovider's default) PQ public keys are raw. Classical
 * first for signature hybrids. Caller frees *out with OPENSSL_clear_free.
 */
int hybrid_encode_priv_blob(HYBRID_KEY *key, unsigned char **out, size_t *outlen)
{
    unsigned char *cbuf = NULL, *buf = NULL, *cdst, *pqdst;
    size_t clen = 0, a2v, a2p, total = 0, got;
    int ret = 0;

    if (!hybrid_ensure_sizes(key) || !hybrid_have_prvkey(key))
        return 0;
    a2v = key->sizes.a2_prv;
    a2p = key->sizes.a2_pub;

    if (!get_component_priv(key->key1, &cbuf, &clen))
        return 0;

    total = sizeof(uint32_t) + clen + a2v + a2p;
    if ((buf = OPENSSL_secure_malloc(total)) == NULL)
        goto err;

    /* UINT32 big-endian classical private-key length */
    buf[0] = (unsigned char)(clen >> 24);
    buf[1] = (unsigned char)(clen >> 16);
    buf[2] = (unsigned char)(clen >> 8);
    buf[3] = (unsigned char)(clen);

    /*
     * Reverse-share KEMs (alg2_slot == 0) store PQ private first, then
     * classical; others classical first. The PQ public key is always the
     * trailing block, at offset 4 + clen + a2v in both cases.
     */
    if (hybrid_key_reverse(key)) {
        pqdst = buf + sizeof(uint32_t);
        cdst  = buf + sizeof(uint32_t) + a2v;
    } else {
        cdst  = buf + sizeof(uint32_t);
        pqdst = buf + sizeof(uint32_t) + clen;
    }
    memcpy(cdst, cbuf, clen);
    if (EVP_PKEY_get_octet_string_param(key->key2, OSSL_PKEY_PARAM_PRIV_KEY,
            pqdst, a2v, &got) <= 0 || got != a2v
        || EVP_PKEY_get_octet_string_param(key->key2, OSSL_PKEY_PARAM_PUB_KEY,
            buf + sizeof(uint32_t) + clen + a2v, a2p, &got) <= 0 || got != a2p)
        goto err;

    *out = buf;
    *outlen = total;
    buf = NULL;
    ret = 1;
err:
    OPENSSL_clear_free(cbuf, clen);
    OPENSSL_secure_clear_free(buf, total);
    return ret;
}

/* Build a PKCS8_PRIV_KEY_INFO (AlgId(OID) + OCTET STRING(inner OCTET STRING)). */
static PKCS8_PRIV_KEY_INFO *hybrid_key_to_p8info(HYBRID_KEY *key)
{
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *blob = NULL, *inner = NULL;
    size_t bloblen = 0;
    int innerlen;
    const char *oidstr = hybrid_key_oid(key);

    if (oidstr == NULL || (oid = OBJ_txt2obj(oidstr, 1)) == NULL
        || !hybrid_encode_priv_blob(key, &blob, &bloblen)
        || (oct = ASN1_OCTET_STRING_new()) == NULL
        || !hybrid_asn1_octet_set(oct, blob, bloblen)
        || (innerlen = i2d_ASN1_OCTET_STRING(oct, &inner)) < 0
        || (p8 = PKCS8_PRIV_KEY_INFO_new()) == NULL)
        goto err;

    /* Transfers ownership of oid and inner to p8. */
    if (!PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, inner, innerlen))
        goto err;
    OPENSSL_secure_clear_free(blob, bloblen);
    ASN1_OCTET_STRING_free(oct);
    return p8;
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(inner);
    OPENSSL_secure_clear_free(blob, bloblen);
    ASN1_OCTET_STRING_free(oct);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
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

/* --- PKCS8 (PrivateKeyInfo) encoders --- */

static int hybrid_enc_does_selection_priv(void *provctx, int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int hybrid_encode_pkcs8(void *vctx, OSSL_CORE_BIO *cout, const void *key,
                               const OSSL_PARAM key_abstract[], int selection,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg, int pem)
{
    HYBRID_ENC_CTX *ctx = vctx;
    HYBRID_KEY *hkey = (HYBRID_KEY *)key;
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
        || (p8 = hybrid_key_to_p8info(hkey)) == NULL)
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

static int hybrid_encode_pkcs8_der(void *vctx, OSSL_CORE_BIO *cout,
                                   const void *key,
                                   const OSSL_PARAM key_abstract[],
                                   int selection,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return hybrid_encode_pkcs8(vctx, cout, key, key_abstract, selection,
                               cb, cbarg, 0);
}

static int hybrid_encode_pkcs8_pem(void *vctx, OSSL_CORE_BIO *cout,
                                   const void *key,
                                   const OSSL_PARAM key_abstract[],
                                   int selection,
                                   OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return hybrid_encode_pkcs8(vctx, cout, key, key_abstract, selection,
                               cb, cbarg, 1);
}

const OSSL_DISPATCH hybrid_pkcs8_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))hybrid_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))hybrid_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))hybrid_enc_does_selection_priv },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))hybrid_encode_pkcs8_der },
    { 0, NULL }
};

const OSSL_DISPATCH hybrid_pkcs8_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))hybrid_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))hybrid_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))hybrid_enc_does_selection_priv },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))hybrid_encode_pkcs8_pem },
    { 0, NULL }
};

/* --- Human-readable text encoder (openssl pkey -text), matching oqsprovider's
 * layout: a header line then a colon-hex dump of each component's material. --- */

static const char *hybrid_key_name(const HYBRID_KEY *key)
{
    return key->is_kem ? ((const HYBRID_KEM_INFO *)key->info)->hybrid_name
                       : ((const HYBRID_SIG_INFO *)key->info)->hybrid_name;
}

static int text_block(BIO *mem, const char *label,
                      const unsigned char *buf, size_t len)
{
    return BIO_printf(mem, "%s key material:\n", label) > 0
           && ASN1_buf_print(mem, buf, len, 4) > 0;
}

static int hybrid_enc_does_selection_text(void *provctx, int selection)
{
    /* Text is available for whatever key material is present. */
    return (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0;
}

static int hybrid_encode_text(void *vctx, OSSL_CORE_BIO *cout, const void *key,
                              const OSSL_PARAM key_abstract[], int selection,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    HYBRID_ENC_CTX *ctx = vctx;
    HYBRID_KEY *hkey = (HYBRID_KEY *)key;
    BIO *mem = NULL;
    unsigned char *cbuf = NULL, *pqbuf = NULL;
    size_t clen = 0, pqlen = 0, got = 0;
    const char *cname;
    int priv, ret = 0;
    char *data = NULL;
    long datalen;
    size_t written = 0;

    if (ctx->bio_write_ex == NULL || !hybrid_ensure_sizes(hkey))
        return 0;
    priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
           && hybrid_have_prvkey(hkey);

    /* Gather the classical + PQ component material (private or public). The
     * classical part is its on-wire form (EC/RSA DER, or raw X25519); the PQ
     * part is the raw octet. */
    if (priv) {
        pqlen = hkey->sizes.a2_prv;
        if (!get_component_priv(hkey->key1, &cbuf, &clen)
            || (pqbuf = OPENSSL_malloc(pqlen)) == NULL
            || EVP_PKEY_get_octet_string_param(hkey->key2,
                   OSSL_PKEY_PARAM_PRIV_KEY, pqbuf, pqlen, &got) <= 0
            || got != pqlen)
            goto end;
    } else {
        if (!hybrid_have_pubkey(hkey))
            goto end;
        pqlen = hkey->sizes.a2_pub;
        if (!get_component_pub(hkey->key1, &cbuf, &clen)
            || (pqbuf = OPENSSL_malloc(pqlen)) == NULL
            || EVP_PKEY_get_octet_string_param(hkey->key2,
                   OSSL_PKEY_PARAM_PUB_KEY, pqbuf, pqlen, &got) <= 0
            || got != pqlen)
            goto end;
    }

    cname = HYBRID_KEY_ALG1_GROUP(hkey);      /* "P-256"; NULL for RSA/X25519 */
    if (cname == NULL)
        cname = HYBRID_KEY_ALG1_NAME(hkey);
    if ((mem = BIO_new(BIO_s_mem())) == NULL
        || BIO_printf(mem, "%s hybrid %s key:\n", hybrid_key_name(hkey),
                      priv ? "private" : "public") <= 0
        || !text_block(mem, cname, cbuf, clen)
        || !text_block(mem, HYBRID_KEY_ALG2_NAME(hkey), pqbuf, pqlen))
        goto end;

    datalen = BIO_get_mem_data(mem, &data);
    if (datalen <= 0)
        goto end;
    ret = ctx->bio_write_ex(cout, data, (size_t)datalen, &written)
          && written == (size_t)datalen;
end:
    OPENSSL_clear_free(cbuf, clen);
    OPENSSL_clear_free(pqbuf, pqlen);
    BIO_free(mem);
    return ret;
}

const OSSL_DISPATCH hybrid_text_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))hybrid_enc_newctx },
    { OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))hybrid_enc_freectx },
    { OSSL_FUNC_ENCODER_DOES_SELECTION,
      (void (*)(void))hybrid_enc_does_selection_text },
    { OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))hybrid_encode_text },
    { 0, NULL }
};
