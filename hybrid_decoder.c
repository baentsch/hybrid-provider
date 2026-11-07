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

/* Read a UINT32 big-endian length prefix from p (p must have >= 4 bytes). The
 * decode-side mirror of the encoder's enc_uint32_be(). */
static uint32_t dec_uint32_be(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
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
    int pklen = 0, variant, is_kem = 0, ret = 1; /* default: not ours, continue */
    char oidbuf[128];
    HYBRID_KEY *key = NULL;
    /* Fixed-capacity (HYBRID_MAX_COMP) scratch; n (set once the key exists, below)
     * entries are used. key is NULL here, so n can only be read after it loads. */
    const unsigned char *compptr[HYBRID_MAX_COMP];
    size_t complen[HYBRID_MAX_COMP];
    unsigned n, w;
    uint32_t clen;
    size_t pqlen, off;

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
     * so the user learns why an otherwise-recognized hybrid key did not load. */
    clen = 0;
    if (pklen >= 4)
        clen = dec_uint32_be(pk);
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
    /* Split the blob into per-component byte ranges. The UINT32 prefix is
     * component ALG1's public-key length and the remainder is component ALG2 —
     * keyed to the slot, not the kind: for KEMs ALG1 is the classical share, but
     * for signatures ALG1 may itself be PQ (or both components PQ), so this is a
     * genuine ALG1-length prefix, not a classical-length one. The wire iterator
     * places each component at its on-wire offset (PQ share first for
     * reverse-share KEMs). */
    complen[HYBRID_COMP_ALG1] = clen;
    complen[HYBRID_COMP_ALG2] = pqlen;
    off = sizeof(uint32_t);
    n = HYBRID_KEY_NCOMP(key);
    for (w = 0; w < n; w++) {
        unsigned ci = hybrid_wire_to_comp(key, w);

        compptr[ci] = pk + off;
        off += complen[ci];
    }
    if (!hybrid_key_load_pub_components(key, compptr[HYBRID_COMP_ALG1], clen,
                                        compptr[HYBRID_COMP_ALG2], pqlen)) {
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
    size_t derlen = 0;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    const ASN1_OBJECT *alg_oid = NULL;
    const unsigned char *octdata = NULL, *cder = NULL, *pqv = NULL, *pqpub = NULL;
    size_t octlen = 0, pqvlen = 0, pqpublen = 0, off;
    int innerlen = 0, variant, is_kem = 0, ret = 1;
    char oidbuf[128];
    HYBRID_KEY *key = NULL;
    uint32_t clen;
    unsigned n, w, i, pqc = 0;
    int have_classical = 0, have_pq = 0;

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
    clen = dec_uint32_be(octdata);

    key = hybrid_keymgmt_new_by_variant(ctx->provctx, is_kem, (unsigned)variant);
    if (key == NULL) {
        ret = 0;
        goto end;
    }
    /* Common bound: the slot-1 block (length in the UINT32 prefix) must fit. */
    if (sizeof(uint32_t) + (size_t)clen > octlen)
        goto end;

    if (!is_kem) {
        /* Signatures: slot-symmetric. UINT32(len1) || slot1 || slot2 — each slot
         * reconstructed by its component's kind (classical DER / PQ priv||pub).
         * slot1 is the prefixed block, slot2 the remainder. */
        if (!hybrid_key_load_prv_components_sym(key, octdata + 4, clen,
                 octdata + 4 + clen, octlen - 4 - (size_t)clen)) {
            ret = 0;
            goto end;
        }
        ret = handback(&key, variant, is_kem, data_cb, data_cbarg);
        goto end;
    }

    /*
     * KEMs: oqsprovider's layout — UINT32(classical_der_len) || <private parts,
     * wire order> || pq_pubkey. Split the components by KIND, not slot (the
     * decode-side mirror of hybrid_encode_priv_blob): the classical share's
     * private DER has the prefixed length (clen); the PQ share's raw
     * private/public sizes come from its own size row.
     *
     * This wire format is a classical+PQ *pair*: the single classical-length
     * prefix and the single trailing PQ public mean it can carry exactly one of
     * each kind, so require that here. N-component and PQ-only (classical-less)
     * hybrid KEMs are implemented in the kind-agnostic concat combiner but are
     * NOT serializable in this format — they carry oid = NULL and never reach
     * this path. Generic per-component KEM key-file serialization is future
     * work, out of scope for #135/#131 (see design.md, "N-component
     * concatenation").
     */
    n = HYBRID_KEY_NCOMP(key);
    for (i = 0; i < n; i++) {
        if (hybrid_component_is_classical(hybrid_key_comp_name(key, i),
                                          hybrid_key_comp_group(key, i))) {
            if (have_classical)
                goto end;              /* a second classical: unrepresentable */
            have_classical = 1;
        } else {
            if (have_pq)
                goto end;              /* a second PQ: unrepresentable */
            pqc = i;
            have_pq = 1;
            pqvlen = hybrid_key_comp_prv_bytes(key, i);
            pqpublen = hybrid_key_comp_pub_bytes(key, i);
        }
    }
    if (!have_classical || !have_pq)
        goto end;
    /* The private parts (classical DER of length clen + PQ raw private) must fit
     * before the trailing PQ public block. */
    if (sizeof(uint32_t) + (size_t)clen + pqvlen > octlen)
        goto end;
    /* Place each private part at its wire offset — hybrid_wire_to_comp() owns
     * the order; the classical share is the prefixed DER (clen), the PQ share
     * (its index discovered above by kind) the raw private key. */
    off = sizeof(uint32_t);
    for (w = 0; w < n; w++) {
        unsigned ci = hybrid_wire_to_comp(key, w);

        if (ci == pqc) {
            pqv = octdata + off;
            off += pqvlen;
        } else {
            cder = octdata + off;
            off += (size_t)clen;
        }
    }
    /* Our blob also carries the PQ public key as the trailing block (at `off`).
     * Pass it through so the decoded key is complete — research keytypes cannot
     * re-derive it from private material, and a certificate needs it. Blobs
     * without the trailing block decode private-only (pqpub stays NULL). */
    if (pqpublen > 0 && off + pqpublen <= octlen)
        pqpub = octdata + off;
    else
        pqpublen = 0;
    if (!hybrid_key_load_prv_components(key, cder, clen, pqv, pqvlen,
                                        pqpub, pqpublen)) {
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
