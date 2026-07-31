/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid key decoder (M2): DER SubjectPublicKeyInfo -> hybrid public key,
 * the inverse of hybrid_encoder.c. Reads the SPKI, matches the AlgorithmId OID
 * against the signature table, and rebuilds the hybrid key from the oqs blob
 * (UINT32 classical-length prefix + ordered component public keys). This lets
 * the hybrid provider consume public keys written by oqsprovider (and itself).
 */

#include "hybrid_prov.h"
#include <openssl/x509.h>
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

/* Read the whole core BIO into a buffer. */
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

/* Find the signature-table index whose OID matches, or -1. */
static int sig_variant_for_oid(const char *oid)
{
    size_t i;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (strcmp(hybrid_sig_table[i].oid, oid) == 0)
            return (int)i;
    return -1;
}

static int hybrid_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                         OSSL_CALLBACK *data_cb, void *data_cbarg,
                         OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    HYBRID_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    const unsigned char *p;
    size_t derlen = 0;
    X509_PUBKEY *xpk = NULL;
    ASN1_OBJECT *alg_oid = NULL;
    const unsigned char *pk = NULL;
    int pklen = 0, variant, ret = 1;   /* default: "not ours", continue chain */
    char oidbuf[128];
    HYBRID_KEY *key = NULL;
    uint32_t clen;

    if (!read_all(ctx, cin, &der, &derlen) || derlen == 0)
        goto end;

    p = der;
    if ((xpk = d2i_X509_PUBKEY(NULL, &p, (long)derlen)) == NULL) {
        ERR_clear_error();               /* not a SPKI; let others try */
        goto end;
    }
    if (!X509_PUBKEY_get0_param(&alg_oid, &pk, &pklen, NULL, xpk)
        || OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg_oid, 1) <= 0)
        goto end;

    variant = sig_variant_for_oid(oidbuf);
    if (variant < 0)
        goto end;                        /* OID not ours; continue chain */

    /* Parse the oqs blob: UINT32(classical_len) || classical_pub || pq_pub
     * (signature hybrids are always classical-first). */
    if (pklen < 4)
        goto end;
    clen = ((uint32_t)pk[0] << 24) | ((uint32_t)pk[1] << 16)
         | ((uint32_t)pk[2] << 8) | (uint32_t)pk[3];
    if (4 + (size_t)clen > (size_t)pklen)
        goto end;

    key = hybrid_keymgmt_new_by_variant(ctx->provctx, 0, (unsigned)variant);
    if (key == NULL) {
        ret = 0;
        goto end;
    }
    if (!hybrid_key_load_pub_components(key, pk + 4, clen,
                                       pk + 4 + clen, pklen - 4 - clen)) {
        ret = 0;
        goto end;
    }

    {
        int object_type = OSSL_OBJECT_PKEY;
        const char *dtype = hybrid_sig_table[variant].hybrid_name;
        OSSL_PARAM params[4];

        params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
                                             &object_type);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_TYPE, (char *)dtype, 0);
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();
        ret = data_cb(params, data_cbarg);
        key = NULL;   /* ownership passed to the caller's reference */
    }

end:
    /* If we built a key but didn't hand it off, free it via the keymgmt. */
    if (key != NULL)
        hybrid_keymgmt_free(key);
    X509_PUBKEY_free(xpk);
    OPENSSL_free(der);
    return ret;
}

const OSSL_DISPATCH hybrid_spki_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))hybrid_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))hybrid_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))hybrid_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))hybrid_decode },
    { 0, NULL }
};
