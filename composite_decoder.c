/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) key decoder (issue #6): DER SubjectPublicKeyInfo -> composite
 * public key, the inverse of composite_encoder.c. Reads the SPKI, matches the
 * AlgorithmIdentifier OID against the composite table, splits the raw concat
 * pqPub || tradPub (PQ length discovered from the component algorithm — sizes are
 * fixed per OID), and rebuilds both components. Lets us consume composite public
 * keys we (or a real peer) wrote.
 *
 * Uses only OpenSSL's public ASN.1/X.509 API (d2i_X509_PUBKEY, OBJ_obj2txt,
 * X509_PUBKEY_get0_param) — no internal headers, same rule as the hybrid family.
 */
#include "composite_prov.h"
#include <openssl/core_object.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <string.h>

typedef struct {
    COMPOSITE_PROV_CTX *provctx;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex;
} COMPOSITE_DEC_CTX;

static void *composite_dec_newctx(void *provctx)
{
    COMPOSITE_PROV_CTX *pctx = provctx;
    COMPOSITE_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = pctx;
        ctx->bio_read_ex = pctx != NULL ? pctx->bio_read_ex : NULL;
    }
    return ctx;
}

static void composite_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int composite_dec_does_selection(void *provctx, int selection)
{
    return selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

#define COMPOSITE_MAX_KEY_DER  (1024 * 1024)   /* 1 MiB cap on decoder input */
#define COMPOSITE_DEC_READ_CHUNK  4096          /* initial read buffer; doubles */
#define COMPOSITE_OID_TXT_MAX  128              /* room for a dotted-decimal OID */
static int read_all(COMPOSITE_DEC_CTX *ctx, OSSL_CORE_BIO *cin,
                    unsigned char **out, size_t *outlen)
{
    size_t cap = COMPOSITE_DEC_READ_CHUNK, len = 0, n = 0;
    unsigned char *buf = OPENSSL_malloc(cap), *tmp;

    if (buf == NULL || ctx->bio_read_ex == NULL) {
        OPENSSL_free(buf);
        return 0;
    }
    for (;;) {
        if (len == cap) {
            if (cap > COMPOSITE_MAX_KEY_DER) {
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

/* Table index whose OID matches, or -1 (NULL-OID/experimental rows skipped). */
static int index_for_oid(const char *oid)
{
    size_t i;

    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        if (composite_sig_table[i].oid != NULL
                && strcmp(composite_sig_table[i].oid, oid) == 0)
            return (int)i;
    return -1;
}

/* Fixed PQ public-key length for this combo, via a throwaway component key. */
static size_t discover_pq_pub_len(COMPOSITE_KEY *key)
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

/* Hand the decoded key back as an object reference (keymgmt LOAD materializes). */
static int handback(COMPOSITE_KEY **key, int idx, OSSL_CALLBACK *data_cb,
                    void *cbarg)
{
    int object_type = OSSL_OBJECT_PKEY;
    const char *dtype = composite_sig_table[idx].name;
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

static int composite_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                            OSSL_CALLBACK *data_cb, void *data_cbarg,
                            OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_DEC_CTX *ctx = vctx;
    unsigned char *der = NULL;
    const unsigned char *p, *pk = NULL;
    size_t derlen = 0, pqn;
    X509_PUBKEY *xpk = NULL;
    ASN1_OBJECT *alg_oid = NULL;
    int pklen = 0, idx, ret = 1;           /* default: not ours, continue chain */
    char oidbuf[COMPOSITE_OID_TXT_MAX];
    COMPOSITE_KEY *key = NULL;

    if (!read_all(ctx, cin, &der, &derlen) || derlen == 0)
        goto end;
    p = der;
    if ((xpk = d2i_X509_PUBKEY(NULL, &p, (long)derlen)) == NULL) {
        ERR_clear_error();
        goto end;
    }
    if (!X509_PUBKEY_get0_param(&alg_oid, &pk, &pklen, NULL, xpk)
            || OBJ_obj2txt(oidbuf, sizeof(oidbuf), alg_oid, 1) <= 0)
        goto end;
    if ((idx = index_for_oid(oidbuf)) < 0)
        goto end;                          /* OID not ours; continue chain */

    key = composite_keymgmt_new_by_index(ctx->provctx, (size_t)idx);
    if (key == NULL) {
        ret = 0;
        goto end;
    }
    pqn = discover_pq_pub_len(key);
    if (pqn == 0 || pqn >= (size_t)pklen) { /* need both components present */
        ret = 0;
        goto end;
    }
    if (!composite_key_load_pub(key, pk, pqn, pk + pqn, (size_t)pklen - pqn)) {
        ret = 0;
        goto end;
    }
    ret = handback(&key, idx, data_cb, data_cbarg);
end:
    if (key != NULL)
        composite_keymgmt_free(key);
    X509_PUBKEY_free(xpk);
    OPENSSL_free(der);
    return ret;
}

const OSSL_DISPATCH composite_spki_der_decoder_functions[] = {
    { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))composite_dec_newctx },
    { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))composite_dec_freectx },
    { OSSL_FUNC_DECODER_DOES_SELECTION,
      (void (*)(void))composite_dec_does_selection },
    { OSSL_FUNC_DECODER_DECODE, (void (*)(void))composite_decode },
    { 0, NULL }
};
