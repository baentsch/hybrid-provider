/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid key decoder (M2): DER SubjectPublicKeyInfo -> hybrid public key,
 * the inverse of hybrid_encoder.c. Reads the SPKI, matches the AlgorithmId OID
 * against the signature table, and rebuilds the hybrid key from the oqs blob
 * (UINT32 classical-length prefix + ordered component public keys). This lets
 * the hybrid provider consume public keys written by oqsprovider (and itself).
 *
 * On the "public API" rule: all cryptographic operations are EVP-only. Key-file
 * (de)serialization additionally uses OpenSSL's public ASN.1/X.509 API —
 * d2i_/i2d_X509_PUBKEY, d2i_PKCS8_PRIV_KEY_INFO, d2i_ASN1_OCTET_STRING,
 * ASN1_STRING_get0_data/length, OBJ_obj2txt, PKCS8_pkey_get0. These are
 * documented, stable, external functions declared in the public <openssl/x509.h>
 * / <openssl/asn1.h>; the lowercase d2i_/i2d_ prefix is OpenSSL's standard
 * public ASN.1 naming convention, NOT an internal-symbol marker. There is no
 * EVP-only way to parse a SubjectPublicKeyInfo/PrivateKeyInfo by a custom OID
 * into raw component blobs; oqsprovider uses these same primitives. No internal
 * (crypto/…) headers are used.
 */

#include "hybrid_prov.h"
#include "hybrid_asn1_compat.h"
#include <openssl/x509.h>
#include <openssl/asn1t.h>
#include <openssl/core_object.h>

typedef struct {
    HYBRID_PROV_CTX *provctx;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex;
} HYBRID_DEC_CTX;

static void *hybrid_dec_newctx(void *provctx)
{
    HYBRID_PROV_CTX *pctx = provctx;
    HYBRID_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = pctx;
        ctx->bio_read_ex = pctx ? pctx->bio_read_ex : NULL;
    }
    return ctx;
}

static void hybrid_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int hybrid_dec_does_selection(void *provctx, int selection)
{
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

/*
 * Read the whole core BIO into a buffer. Terminates when the BIO reports EOF
 * (bio_read_ex returns 0, or a short/zero read) — key files are finite — or,
 * defensively, once the buffer would exceed HYBRID_MAX_KEY_DER, which also caps
 * memory use if the core ever hands us an unbounded stream.
 */
#define HYBRID_MAX_KEY_DER (1024 * 1024)    /* hybrid keys are a few KB at most */
static int read_all(HYBRID_DEC_CTX *ctx, OSSL_CORE_BIO *cin,
                    unsigned char **out, size_t *outlen)
{
    size_t cap = 4096, len = 0, n = 0;
    unsigned char *buf = OPENSSL_malloc(cap), *tmp;

    if (buf == NULL || ctx->bio_read_ex == NULL) {
        OPENSSL_free(buf);
        return 0;
    }
    for (;;) {
        if (len == cap) {
            if (cap > HYBRID_MAX_KEY_DER) {
                ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                               "hybrid decode: input exceeds %d bytes",
                               HYBRID_MAX_KEY_DER);
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

/*
 * Find the table variant whose OID matches, across both the signature and KEM
 * tables. Sets *is_kem accordingly. Returns -1 if no algorithm claims the OID
 * (NULL-OID rows are skipped: those algorithms are not key-file encodable).
 */
static int variant_for_oid(const char *oid, int *is_kem)
{
    size_t i;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (hybrid_sig_table[i].oid != NULL
            && strcmp(hybrid_sig_table[i].oid, oid) == 0) {
            *is_kem = 0;
            return (int)i;
        }
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if (hybrid_kem_table[i].oid != NULL
            && strcmp(hybrid_kem_table[i].oid, oid) == 0) {
            *is_kem = 1;
            return (int)i;
        }
    return -1;
}

/* Hand a decoded key back to the caller as an object reference. */
static int handback(HYBRID_KEY **key, int variant, int is_kem,
                    OSSL_CALLBACK *data_cb, void *cbarg)
{
    int object_type = OSSL_OBJECT_PKEY;
    const char *dtype = is_kem ? hybrid_kem_table[variant].hybrid_name
                               : hybrid_sig_table[variant].hybrid_name;
    OSSL_PARAM params[4];
    int r;

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)dtype, 0);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                  key, sizeof(*key));
    params[3] = OSSL_PARAM_construct_end();
    r = data_cb(params, cbarg);
    *key = NULL;   /* ownership passed to the caller's reference */
    return r;
}

/*
 * Local SubjectPublicKeyInfo template for the shared non-eager parser: SEQUENCE
 * { AlgorithmIdentifier, BIT STRING }, built from public ASN.1 types. See
 * hybrid_spki_parse() below and its declaration in hybrid_prov.h for why we
 * must not use d2i_X509_PUBKEY() (eager decode -> decoder recursion -> crash).
 */
typedef struct {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
} HYBRID_SPKI;

ASN1_SEQUENCE(HYBRID_SPKI) = {
    ASN1_SIMPLE(HYBRID_SPKI, algor, X509_ALGOR),
    ASN1_SIMPLE(HYBRID_SPKI, public_key, ASN1_BIT_STRING)
} static_ASN1_SEQUENCE_END(HYBRID_SPKI)

void *hybrid_spki_parse(const unsigned char *der, size_t derlen,
                        const ASN1_OBJECT **oid,
                        const unsigned char **pub, int *publen)
{
    const unsigned char *p = der;
    HYBRID_SPKI *spki = (HYBRID_SPKI *)ASN1_item_d2i(NULL, &p, (long)derlen,
                                                     ASN1_ITEM_rptr(HYBRID_SPKI));

    if (spki == NULL) {
        ERR_clear_error();               /* not a SPKI; caller lets others try */
        return NULL;
    }
    /*
     * ASN1_item_d2i is the only fallible call and is checked above. Both fields
     * are ASN1_SIMPLE (mandatory) in HYBRID_SPKI, and X509_ALGOR's algorithm is
     * likewise mandatory, so a successful decode guarantees spki->algor,
     * spki->public_key and the returned OID are non-NULL; X509_ALGOR_get0() and
     * the ASN1_STRING accessors are void/infallible on them. The soft outputs
     * (the OID and an empty/short public key) are still validated by every
     * caller (OID != NULL, length checks) as defence in depth.
     */
    X509_ALGOR_get0(oid, NULL, NULL, spki->algor);
    *pub = ASN1_STRING_get0_data(spki->public_key);
    {
        size_t plen = hybrid_asn1_string_length(spki->public_key);

        /* publen is int (shared signature); a public key that large is
         * impossible, but flag it so callers' length checks decline it. */
        *publen = plen > (size_t)INT_MAX ? -1 : (int)plen;
    }
    return spki;
}

void hybrid_spki_free(void *handle)
{
    ASN1_item_free((ASN1_VALUE *)handle, ASN1_ITEM_rptr(HYBRID_SPKI));
}

static int hybrid_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                         OSSL_CALLBACK *data_cb, void *data_cbarg,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    HYBRID_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    size_t derlen = 0;
    void *spki = NULL;
    const ASN1_OBJECT *alg_oid = NULL;
    const unsigned char *pk = NULL;
    const unsigned char *cpub, *pqpub;
    int pklen = 0, variant, is_kem = 0, ret = 1; /* default: not ours, continue */
    char oidbuf[128];
    HYBRID_KEY *key = NULL;
    uint32_t clen;
    size_t pqlen;

    if (!read_all(ctx, cin, &der, &derlen) || derlen == 0)
        goto end;

    if ((spki = hybrid_spki_parse(der, derlen, &alg_oid, &pk, &pklen)) == NULL)
        goto end;                        /* not a SPKI; let others try */
    if (alg_oid == NULL
        || OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg_oid, 1) <= 0)
        goto end;

    variant = variant_for_oid(oidbuf, &is_kem);
    if (variant < 0)
        goto end;                        /* OID not ours; continue chain */

    /* From here the OID is a hybrid one we own, so a failure is a real error for
     * this key rather than a "let another decoder try" decline: raise a message
     * so the user learns why an otherwise-recognized hybrid key did not load.
     * Blob: UINT32(classical_pub_len) then the two component public keys.
     * Signature hybrids and forward KEMs are classical-first; reverse-share
     * KEMs (alg2_slot == 0) put the PQ public key first. */
    clen = 0;
    if (pklen >= 4)
        clen = ((uint32_t)pk[0] << 24) | ((uint32_t)pk[1] << 16)
             | ((uint32_t)pk[2] << 8) | (uint32_t)pk[3];
    if (pklen < 4 || 4 + (size_t)clen > (size_t)pklen) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "hybrid decode: malformed %s public key", oidbuf);
        ret = 0;
        goto end;
    }
    pqlen = (size_t)pklen - 4 - clen;

    key = hybrid_keymgmt_new_by_variant(ctx->provctx, is_kem, (unsigned)variant);
    if (key == NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "hybrid decode: cannot instantiate %s", oidbuf);
        ret = 0;
        goto end;
    }
    if (is_kem && ((const HYBRID_KEM_INFO *)key->info)->alg2_slot == 0) {
        pqpub = pk + 4;
        cpub  = pk + 4 + pqlen;
    } else {
        cpub  = pk + 4;
        pqpub = pk + 4 + clen;
    }
    if (!hybrid_key_load_pub_components(key, cpub, clen, pqpub, pqlen)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "hybrid decode: cannot load %s components", oidbuf);
        ret = 0;
        goto end;
    }

    ret = handback(&key, variant, is_kem, data_cb, data_cbarg);

end:
    /* If we built a key but didn't hand it off, free it via the keymgmt. */
    if (key != NULL)
        hybrid_keymgmt_free(key);
    hybrid_spki_free(spki);
    OPENSSL_free(der);
    return ret;
}

static int hybrid_decode_p8(void *vctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *data_cb, void *data_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    HYBRID_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    const unsigned char *p, *inner;
    size_t derlen = 0, a2v;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    const ASN1_OBJECT *alg_oid = NULL;
    const unsigned char *octdata = NULL, *cder, *pqv, *pqpub = NULL;
    size_t octlen = 0, a2p;
    int innerlen = 0, variant, is_kem = 0, ret = 1;
    char oidbuf[128];
    HYBRID_KEY *key = NULL;
    uint32_t clen;

    if (!read_all(ctx, cin, &der, &derlen) || derlen == 0)
        goto end;
    p = der;
    if ((p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)derlen)) == NULL) {
        ERR_clear_error();
        goto end;
    }
    if (!PKCS8_pkey_get0(&alg_oid, &inner, &innerlen, NULL, p8)
        || OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg_oid, 1) <= 0)
        goto end;
    variant = variant_for_oid(oidbuf, &is_kem);
    if (variant < 0)
        goto end;

    /* Inner OCTET STRING wraps the raw blob. Use ASN1_STRING accessors: the
     * struct is opaque under OpenSSL 4.x, and hybrid_asn1_string_length() also
     * shields the 4.1 int->size_t deprecation (see hybrid_asn1_compat.h). */
    if ((oct = d2i_ASN1_OCTET_STRING(NULL, &inner, innerlen)) == NULL)
        goto end;
    octdata = ASN1_STRING_get0_data(oct);
    octlen = hybrid_asn1_string_length(oct);
    if (octlen < 4)
        goto end;
    clen = ((uint32_t)octdata[0] << 24) | ((uint32_t)octdata[1] << 16)
         | ((uint32_t)octdata[2] << 8) | (uint32_t)octdata[3];

    key = hybrid_keymgmt_new_by_variant(ctx->provctx, is_kem, (unsigned)variant);
    if (key == NULL || !hybrid_ensure_sizes(key)) {
        ret = 0;
        goto end;
    }
    a2v = key->sizes.a2_prv;
    a2p = key->sizes.a2_pub;
    if (sizeof(uint32_t) + (size_t)clen + a2v > octlen)
        goto end;
    /* Reverse-share KEMs store PQ private first, then classical. */
    if (is_kem && ((const HYBRID_KEM_INFO *)key->info)->alg2_slot == 0) {
        pqv  = octdata + 4;
        cder = octdata + 4 + a2v;
    } else {
        cder = octdata + 4;
        pqv  = octdata + 4 + clen;
    }
    /* Our blob also carries the PQ public key as a trailing block (offset
     * 4 + clen + a2v). Pass it through so the decoded key is complete — research
     * keytypes cannot re-derive it from private material, and a certificate needs
     * it. Blobs without the trailing block decode private-only (pqpub stays NULL). */
    if (a2p > 0 && sizeof(uint32_t) + (size_t)clen + a2v + a2p <= octlen)
        pqpub = octdata + 4 + (size_t)clen + a2v;
    if (!hybrid_key_load_prv_components(key, cder, clen, pqv, a2v,
                                        pqpub, pqpub != NULL ? a2p : 0)) {
        ret = 0;
        goto end;
    }
    ret = handback(&key, variant, is_kem, data_cb, data_cbarg);
end:
    if (key != NULL)
        hybrid_keymgmt_free(key);
    ASN1_OCTET_STRING_free(oct);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    return ret;
}

static int hybrid_dec_does_selection_priv(void *provctx, int selection)
{
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

const OSSL_DISPATCH hybrid_pkcs8_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))hybrid_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))hybrid_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))hybrid_dec_does_selection_priv },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))hybrid_decode_p8 },
    { 0, NULL }
};

const OSSL_DISPATCH hybrid_spki_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))hybrid_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))hybrid_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))hybrid_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))hybrid_decode },
    { 0, NULL }
};
