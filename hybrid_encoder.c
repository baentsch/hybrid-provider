/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid key encoders (M2). First slice: SubjectPublicKeyInfo in DER and PEM,
 * byte-compatible with oqsprovider so the two interoperate on key files.
 *
 * SPKI = AlgorithmIdentifier(OID) + BIT STRING(pubblob), where
 *   pubblob = ENCODE_UINT32(slot1_pub_len) || slot1_pub || slot2_pub
 * The UINT32 encodes the slot-1 component's public-key length. For KEMs slot 1 is
 * the classical share unless alg2_slot == 0 (reverse-share, PQ first). Signature
 * hybrids are classical-first by oqsprovider convention, except the provider-
 * private §3.4 rows that put a PQ or EC component in slot 1 (the private key is
 * serialized slot-symmetrically by component kind; see hybrid_encode_priv_blob).
 */

#include "hybrid_prov.h"
#include "hybrid_asn1_compat.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/encoder.h>

/* OID string for a key; NULL when the algorithm has no assigned OID (most
 * hybrid KEMs) and is therefore not key-file encodable. */
static const char *hybrid_key_oid(const HYBRID_KEY *key)
{
    return key->is_kem ? ((const HYBRID_KEM_INFO *)key->info)->oid
                       : ((const HYBRID_SIG_INFO *)key->info)->oid;
}

/* Write a UINT32 big-endian length prefix at p. */
static void enc_uint32_be(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v);
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
    if ((dlen = i2d_PrivateKey(pkey, &der)) > 0) {
        *buf = der;
        *len = (size_t)dlen;
        return 1;
    }
    /*
     * Some provider keytypes can keygen but ship no type-specific i2d encoder —
     * notably the default provider's curveSM2 ("No encoders were found"). For the
     * text dump (the only path that reaches this for such a NULL-OID hybrid; the
     * key-file encoders need an OID and are gated out), fall back to the raw
     * private scalar so the classical component still renders. For EC-family keys
     * the private key is a BIGNUM param (not an octet), so read it as one. Only
     * reached once both the raw-key and i2d encodings have failed, so EC/RSA/
     * X25519 output is unchanged.
     */
    ERR_clear_error();
    {
        BIGNUM *bn = NULL;
        int blen;

        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn) <= 0)
            return 0;
        blen = BN_num_bytes(bn);
        if (blen <= 0 || (*buf = OPENSSL_malloc((size_t)blen)) == NULL) {
            BN_clear_free(bn);
            return 0;
        }
        *len = (size_t)BN_bn2bin(bn, *buf);
        BN_clear_free(bn);
        return 1;
    }
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
    unsigned n = HYBRID_KEY_NCOMP(key), i, w;
    unsigned char *cpub[HYBRID_KEY_NCOMP(key)] = { 0 }, *buf = NULL;
    size_t cplen[HYBRID_KEY_NCOMP(key)] = { 0 }, total, off;
    int ret = 0;

    if (!hybrid_have_pubkey(key))
        return 0;

    /* Gather every component's public key, then lay them down in wire order
     * (the iterator places the PQ share first for reverse-share KEMs) behind a
     * UINT32 big-endian length of the classical (component ALG1) share — the
     * oqsprovider SPKI layout. */
    total = sizeof(uint32_t);
    for (i = 0; i < n; i++) {
        if (!get_component_pub(HYBRID_KEY_COMP(key, i), &cpub[i], &cplen[i]))
            goto end;
        total += cplen[i];
    }
    if ((buf = OPENSSL_malloc(total)) == NULL)
        goto end;
    enc_uint32_be(buf, (uint32_t)cplen[HYBRID_COMP_ALG1]);

    off = sizeof(uint32_t);
    for (w = 0; w < n; w++) {
        unsigned ci = hybrid_wire_to_comp(key, w);

        memcpy(buf + off, cpub[ci], cplen[ci]);
        off += cplen[ci];
    }
    *out = buf;
    *outlen = total;
    buf = NULL;
    ret = 1;
end:
    for (i = 0; i < n; i++)
        OPENSSL_free(cpub[i]);
    OPENSSL_free(buf);
    return ret;
}

/*
 * Serialize one component's private material in this provider's on-wire form,
 * dispatched by kind so a half renders the same way whichever slot it occupies:
 * a classical component via get_component_priv (i2d_PrivateKey DER for EC/RSA, or
 * raw for X25519/X448); a PQ component as raw private || raw public (the public
 * appended so a research keytype that cannot re-derive it still decodes to a
 * complete key). `prv`/`pub` are the fixed PQ component sizes.
 *
 * This is a transient scratch buffer holding private-key material, so it is a
 * regular-heap allocation wiped on free (OPENSSL_clear_free), not a secure-heap
 * one: the serialized private key unavoidably lands on the regular heap at the
 * ASN.1/PKCS#8 stage regardless (so securing the scratch is only partial), and
 * the fixed-size secure arena is a scarce resource that large PQ private keys
 * (e.g. UOV's ~405 KB uncompressed secret key) can exhaust, turning a
 * defence-in-depth nicety into an encode failure. Caller frees *buf with
 * OPENSSL_clear_free.
 */
static int encode_component_priv(EVP_PKEY *pkey, const char *alg,
                                 const char *group, size_t prv, size_t pub,
                                 unsigned char **buf, size_t *len)
{
    unsigned char *b;
    size_t got;

    if (hybrid_component_is_classical(alg, group))
        return get_component_priv(pkey, buf, len);

    if ((b = OPENSSL_malloc(prv + pub)) == NULL)
        return 0;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                        b, prv, &got) <= 0 || got != prv
        || EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                           b + prv, pub, &got) <= 0 || got != pub) {
        OPENSSL_clear_free(b, prv + pub);
        return 0;
    }
    *buf = b;
    *len = prv + pub;
    return 1;
}

/*
 * Slot-symmetric signature private blob:
 *   UINT32(len of component ALG1) || components in wire order
 * where each component is encode_component_priv() of its own kind. For the
 * classical-first rows this is byte-identical to the historical layout
 * (UINT32(classical_der_len) || classical_DER || pq_priv || pq_pub); a PQ-first
 * or EC-in-slot-2 row simply reverses which kind lands where (signatures never
 * reverse-share, so wire order == logical order here). Signatures only — KEMs
 * keep their trailing-PQ-public layout below. Regular-heap, wiped on free;
 * caller frees *out with OPENSSL_clear_free.
 */
static int encode_priv_blob_sig(HYBRID_KEY *key, unsigned char **out,
                                size_t *outlen)
{
    unsigned n = HYBRID_KEY_NCOMP(key), i, w;
    unsigned char *cb[HYBRID_KEY_NCOMP(key)] = { 0 }, *buf = NULL;
    size_t cl[HYBRID_KEY_NCOMP(key)] = { 0 }, total = 0, off;
    int ret = 0;

    total = sizeof(uint32_t);
    for (i = 0; i < n; i++) {
        if (!encode_component_priv(HYBRID_KEY_COMP(key, i),
                                   hybrid_key_comp_name(key, i),
                                   hybrid_key_comp_group(key, i),
                                   hybrid_key_comp_prv_bytes(key, i),
                                   hybrid_key_comp_pub_bytes(key, i),
                                   &cb[i], &cl[i]))
            goto err;
        total += cl[i];
    }
    if ((buf = OPENSSL_malloc(total)) == NULL)
        goto err;
    enc_uint32_be(buf, (uint32_t)cl[HYBRID_COMP_ALG1]);

    off = sizeof(uint32_t);
    for (w = 0; w < n; w++) {
        unsigned ci = hybrid_wire_to_comp(key, w);

        memcpy(buf + off, cb[ci], cl[ci]);
        off += cl[ci];
    }
    *out = buf;
    *outlen = total;
    buf = NULL;
    ret = 1;
err:
    /* Regular-heap private-key scratch, wiped on free. */
    for (i = 0; i < n; i++)
        OPENSSL_clear_free(cb[i], cl[i]);
    OPENSSL_clear_free(buf, total);
    return ret;
}

/*
 * Build the KEM private-key blob (signatures take the slot-symmetric path above
 * and return early). oqsprovider's KEM layout is NOT a plain per-component
 * concatenation: the PQ component's public key is always pinned to the trailing
 * block, whatever the share order —
 *   UINT32(classical_der_len) || <private parts, wire order> || pq_pubkey
 * where each private part is the classical DER (component ALG1) or the PQ raw
 * private key (component ALG2), ordered by the wire iterator (PQ private first
 * for reverse-share KEMs). That trailing-public rule is the one asymmetry a loop
 * cannot absorb; the private parts themselves are placed by the same wire-order
 * loop the public blob uses. Regular-heap, wiped on free (see
 * encode_component_priv for why not the secure heap); caller frees *out with
 * OPENSSL_clear_free.
 */
int hybrid_encode_priv_blob(HYBRID_KEY *key, unsigned char **out, size_t *outlen)
{
    unsigned n = HYBRID_KEY_NCOMP(key), w;
    unsigned char *cbuf = NULL, *buf = NULL;
    size_t clen = 0, pqv, pqp, total = 0, off, got;
    int ret = 0;

    if (!hybrid_have_prvkey(key))
        return 0;
    if (!key->is_kem)                  /* signatures: slot-symmetric by kind */
        return encode_priv_blob_sig(key, out, outlen);

    /* Classical (ALG1) private part, and PQ (ALG2) raw private/public sizes. */
    pqv = hybrid_key_comp_prv_bytes(key, HYBRID_COMP_ALG2);
    pqp = hybrid_key_comp_pub_bytes(key, HYBRID_COMP_ALG2);
    if (!get_component_priv(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1), &cbuf, &clen))
        return 0;

    total = sizeof(uint32_t) + clen + pqv + pqp;
    if ((buf = OPENSSL_malloc(total)) == NULL)
        goto err;
    enc_uint32_be(buf, (uint32_t)clen);

    off = sizeof(uint32_t);
    for (w = 0; w < n; w++) {
        unsigned ci = hybrid_wire_to_comp(key, w);

        if (ci == HYBRID_COMP_ALG1) {         /* classical share: DER (clen) */
            memcpy(buf + off, cbuf, clen);
            off += clen;
        } else {                              /* PQ share: raw private (pqv) */
            if (EVP_PKEY_get_octet_string_param(HYBRID_KEY_COMP(key, ci),
                    OSSL_PKEY_PARAM_PRIV_KEY, buf + off, pqv, &got) <= 0
                || got != pqv)
                goto err;
            off += pqv;
        }
    }
    /* PQ public key: the trailing block in every share order. */
    if (EVP_PKEY_get_octet_string_param(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2),
            OSSL_PKEY_PARAM_PUB_KEY, buf + off, pqp, &got) <= 0 || got != pqp)
        goto err;

    *out = buf;
    *outlen = total;
    buf = NULL;
    ret = 1;
err:
    OPENSSL_clear_free(cbuf, clen);
    OPENSSL_clear_free(buf, total);
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
    OPENSSL_clear_free(blob, bloblen);
    ASN1_OCTET_STRING_free(oct);
    return p8;
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(inner);
    OPENSSL_clear_free(blob, bloblen);
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
    unsigned char *slot1buf = NULL, *slot2buf = NULL;
    size_t slot1len = 0, slot2len = 0, got = 0;
    const char *slot1name, *slot2name;
    int priv, ret = 0;
    char *data = NULL;
    long datalen;
    size_t written = 0;

    if (ctx->bio_write_ex == NULL)
        return 0;
    priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
           && hybrid_have_prvkey(hkey);

    /*
     * Gather component 1 and component 2 material (private or public). Each half
     * is rendered by its own kind, not by assuming "slot 1 is classical": a
     * classical half (EC/RSA DER, raw X25519/X448, or a BN scalar) via
     * get_component_{priv,pub}; a PQ half as its fixed-size raw octet. This makes
     * the dump slot-symmetric, so a classical EC component in slot 2 (e.g.
     * mldsa65_p256, whose EC private key is a BN, not an octet) renders too.
     * The slotN* names are deliberately slot-neutral: either slot may hold the
     * classical or the PQ half.
     */
    if (!hybrid_have_pubkey(hkey))
        goto end;
    if (priv) {
        if (!get_component_priv(HYBRID_KEY_COMP(hkey, HYBRID_COMP_ALG1),
                                &slot1buf, &slot1len))
            goto end;
        if (hybrid_component_is_classical(
                    hybrid_key_comp_name(hkey, HYBRID_COMP_ALG2),
                    hybrid_key_comp_group(hkey, HYBRID_COMP_ALG2))) {
            if (!get_component_priv(HYBRID_KEY_COMP(hkey, HYBRID_COMP_ALG2),
                                    &slot2buf, &slot2len))
                goto end;
        } else {
            slot2len = hybrid_key_comp_prv_bytes(hkey, HYBRID_COMP_ALG2);
            if ((slot2buf = OPENSSL_malloc(slot2len)) == NULL
                || EVP_PKEY_get_octet_string_param(
                       HYBRID_KEY_COMP(hkey, HYBRID_COMP_ALG2),
                       OSSL_PKEY_PARAM_PRIV_KEY, slot2buf, slot2len, &got) <= 0
                || got != slot2len)
                goto end;
        }
    } else {
        if (!get_component_pub(HYBRID_KEY_COMP(hkey, HYBRID_COMP_ALG1),
                               &slot1buf, &slot1len))
            goto end;
        if (hybrid_component_is_classical(
                    hybrid_key_comp_name(hkey, HYBRID_COMP_ALG2),
                    hybrid_key_comp_group(hkey, HYBRID_COMP_ALG2))) {
            if (!get_component_pub(HYBRID_KEY_COMP(hkey, HYBRID_COMP_ALG2),
                                   &slot2buf, &slot2len))
                goto end;
        } else {
            slot2len = hybrid_key_comp_pub_bytes(hkey, HYBRID_COMP_ALG2);
            if ((slot2buf = OPENSSL_malloc(slot2len)) == NULL
                || EVP_PKEY_get_octet_string_param(
                       HYBRID_KEY_COMP(hkey, HYBRID_COMP_ALG2),
                       OSSL_PKEY_PARAM_PUB_KEY, slot2buf, slot2len, &got) <= 0
                || got != slot2len)
                goto end;
        }
    }

    /* Label each component with its curve ("P-256") if it has one, else its
     * algorithm name ("RSA", "MLDSA65", …) — symmetric across both slots. */
    slot1name = hybrid_key_comp_group(hkey, HYBRID_COMP_ALG1);
    if (slot1name == NULL)
        slot1name = hybrid_key_comp_name(hkey, HYBRID_COMP_ALG1);
    slot2name = hybrid_key_comp_group(hkey, HYBRID_COMP_ALG2);
    if (slot2name == NULL)
        slot2name = hybrid_key_comp_name(hkey, HYBRID_COMP_ALG2);
    if ((mem = BIO_new(BIO_s_mem())) == NULL
        || BIO_printf(mem, "%s hybrid %s key:\n", hybrid_key_name(hkey),
                      priv ? "private" : "public") <= 0
        || !text_block(mem, slot1name, slot1buf, slot1len)
        || !text_block(mem, slot2name, slot2buf, slot2len))
        goto end;

    datalen = BIO_get_mem_data(mem, &data);
    if (datalen <= 0)
        goto end;
    ret = ctx->bio_write_ex(cout, data, (size_t)datalen, &written)
          && written == (size_t)datalen;
end:
    OPENSSL_clear_free(slot1buf, slot1len);
    OPENSSL_clear_free(slot2buf, slot2len);
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
