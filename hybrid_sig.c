/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid signature dispatch — one-shot DigestSign/DigestVerify combining a
 * classical signature (ECDSA or RSA) with a PQ signature (ML-DSA/…), matching
 * oqsprovider's hybrid-sig wire format:
 *
 *   sig = ENCODE_UINT32(classical_len) || classical_sig || pq_sig
 *
 * The classical component signs a digest of the message — SHA-256/384/512 chosen
 * by the PQ component's NIST level (1 -> 256, 2/3 -> 384, 4/5 -> 512) — via
 * EVP_PKEY_sign (ECDSA DER, or RSA PKCS#1 v1.5). The PQ component signs the raw
 * message. Verify requires BOTH to pass.
 */

#include "hybrid_prov.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>

typedef struct {
    OSSL_LIB_CTX *libctx;
    HYBRID_KEY *key;
    int op;     /* EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY */
} HYBRID_SIG_CTX;

static void *hybrid_sig_newctx(void *provctx, const char *propq)
{
    HYBRID_SIG_CTX *ctx;
    HYBRID_PROV_CTX *pctx = provctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->libctx = pctx ? pctx->libctx : NULL;
    return ctx;
}

static void hybrid_sig_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static void *hybrid_sig_dupctx(void *vctx)
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_SIG_CTX *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    *ret = *ctx;
    return ret;
}

static int
hybrid_sig_digest_sign_init(void *vctx, const char *mdname,
                             void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (key == NULL || !hybrid_have_prvkey(key))
        return 0;
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_SIGN;
    return 1;
}

static int
hybrid_sig_digest_verify_init(void *vctx, const char *mdname,
                               void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (key == NULL || !hybrid_have_pubkey(key))
        return 0;
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_VERIFY;
    return 1;
}

/*
 * Digest the classical component signs, chosen by the PQ NIST level. Uses the
 * static (non-fetched) EVP_MD accessors — matching oqsprovider and avoiding an
 * EVP_MD_fetch per operation.
 */
static const EVP_MD *classical_md(int nist_level)
{
    switch (nist_level) {
    case 1:  return EVP_sha256();
    case 2:
    case 3:  return EVP_sha384();
    default: return EVP_sha512();
    }
}

/*
 * Classical sign/verify over a pre-computed digest via EVP_PKEY_sign/verify
 * (ECDSA DER, or RSA PKCS#1 v1.5). `is_rsa` selects PKCS#1 padding.
 * For signing, out/outlen receive the signature; for verify, sig/siglen are the
 * input. Returns 1 on success.
 */
static int classical_op(HYBRID_KEY *key, int sign, int is_rsa,
                        const EVP_MD *md,
                        const unsigned char *tbs, size_t tbslen,
                        unsigned char *sig, size_t *siglen, size_t sigmax)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int diglen = sizeof(dig);
    int ret = 0;

    if (!EVP_Digest(tbs, tbslen, dig, &diglen, md, NULL))
        return 0;

    pctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, key->key1,
                                      HYBRID_KEY_CLASSIC_PROPQ(key));
    if (pctx == NULL)
        goto end;
    if ((sign ? EVP_PKEY_sign_init(pctx) : EVP_PKEY_verify_init(pctx)) <= 0)
        goto end;
    if (is_rsa && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
        goto end;
    if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
        goto end;

    if (sign) {
        *siglen = sigmax;
        if (EVP_PKEY_sign(pctx, sig, siglen, dig, diglen) <= 0)
            goto end;
    } else {
        if (EVP_PKEY_verify(pctx, sig, *siglen, dig, diglen) <= 0)
            goto end;
    }
    ret = 1;
end:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/*
 * One-shot sign:
 *   sig = ENCODE_UINT32(classical_len) || classical_sig || pq_sig
 */
static int
hybrid_sig_digest_sign(void *vctx,
                        unsigned char *sig, size_t *siglen,
                        size_t sigsize,
                        const unsigned char *tbs, size_t tbslen)
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_SIG_INFO *info = (const HYBRID_SIG_INFO *)key->info;
    EVP_MD_CTX *mctx = NULL;
    size_t clen = 0, plen = 0, maxsig;
    int is_rsa = (strcmp(info->alg1_name, "RSA") == 0);
    int ret = 0;

    maxsig = hybrid_sig_max_sig_bytes(key);

    if (sig == NULL) {          /* size query */
        *siglen = maxsig;
        return 1;
    }
    if (sigsize < maxsig || !hybrid_have_prvkey(key))
        return 0;

    /* classical signature, written after the 4-byte length prefix */
    if (!classical_op(key, 1, is_rsa, classical_md(info->nist_level),
                      tbs, tbslen, sig + sizeof(uint32_t), &clen,
                      key->sizes.a1_sig))
        goto err;
    sig[0] = (unsigned char)(clen >> 24);
    sig[1] = (unsigned char)(clen >> 16);
    sig[2] = (unsigned char)(clen >> 8);
    sig[3] = (unsigned char)(clen);

    /* PQ signature over the raw message, appended after the classical sig */
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL
        || EVP_DigestSignInit_ex(mctx, NULL, NULL, key->libctx,
                                 HYBRID_KEY_PQ_PROPQ(key), key->key2, NULL) <= 0)
        goto err;
    plen = key->sizes.a2_sig;
    if (EVP_DigestSign(mctx, sig + sizeof(uint32_t) + clen, &plen,
                       tbs, tbslen) <= 0)
        goto err;

    *siglen = sizeof(uint32_t) + clen + plen;
    ret = 1;
err:
    EVP_MD_CTX_free(mctx);
    return ret;
}

/*
 * One-shot verify: split at the 4-byte classical length; both parts must pass.
 */
static int
hybrid_sig_digest_verify(void *vctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_SIG_INFO *info = (const HYBRID_SIG_INFO *)key->info;
    EVP_MD_CTX *mctx = NULL;
    size_t clen, plen;
    int is_rsa = (strcmp(info->alg1_name, "RSA") == 0);
    int ret = 0;

    if (!hybrid_have_pubkey(key))
        return 0;
    /* Bounds guards: the signature must hold the 4-byte classical-length prefix
     * before we read sig[0..3], and that length must fit within siglen before we
     * split off the classical and PQ parts (else a malformed signature would
     * cause an out-of-bounds read). */
    if (siglen < sizeof(uint32_t))
        return 0;
    clen = ((size_t)sig[0] << 24) | ((size_t)sig[1] << 16)
         | ((size_t)sig[2] << 8) | (size_t)sig[3];
    if (sizeof(uint32_t) + clen > siglen)
        return 0;
    plen = siglen - sizeof(uint32_t) - clen;

    /* verify classical over the digest */
    if (!classical_op(key, 0, is_rsa, classical_md(info->nist_level),
                      tbs, tbslen, (unsigned char *)sig + sizeof(uint32_t),
                      &clen, 0))
        goto err;

    /* verify PQ over the raw message */
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL
        || EVP_DigestVerifyInit_ex(mctx, NULL, NULL, key->libctx,
                                   HYBRID_KEY_PQ_PROPQ(key), key->key2,
                                   NULL) <= 0)
        goto err;
    if (EVP_DigestVerify(mctx, sig + sizeof(uint32_t) + clen, plen,
                         tbs, tbslen) <= 0)
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(mctx);
    return ret;
}

static const OSSL_PARAM *hybrid_sig_settable_ctx_params(void *vctx,
                                                          void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };
    return params;
}

static int hybrid_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM *hybrid_sig_gettable_ctx_params(void *vctx,
                                                          void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

/*
 * Provide the X.509 AlgorithmIdentifier (DER) for the hybrid signature so that
 * X509_sign()/X509_verify() and the TLS CertificateVerify message can label the
 * signature. It is SEQUENCE { OID } with absent parameters — the hybrid OID from
 * the info table, matching oqsprovider.
 */
static int hybrid_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);

    if (p != NULL) {
        const HYBRID_SIG_INFO *info;
        X509_ALGOR *alg = NULL;
        ASN1_OBJECT *oid = NULL;
        unsigned char *der = NULL;
        int derlen, ok = 0;

        if (ctx == NULL || ctx->key == NULL)
            return 0;
        info = (const HYBRID_SIG_INFO *)ctx->key->info;
        if (info->oid == NULL || (oid = OBJ_txt2obj(info->oid, 1)) == NULL
                || (alg = X509_ALGOR_new()) == NULL
                || !X509_ALGOR_set0(alg, oid, V_ASN1_UNDEF, NULL))
            goto end;
        oid = NULL;             /* ownership transferred to alg */
        if ((derlen = i2d_X509_ALGOR(alg, &der)) <= 0
                || !OSSL_PARAM_set_octet_string(p, der, (size_t)derlen))
            goto end;
        ok = 1;
    end:
        OPENSSL_free(der);
        ASN1_OBJECT_free(oid);
        X509_ALGOR_free(alg);
        if (!ok)
            return 0;
    }
    return 1;
}

const OSSL_DISPATCH hybrid_sig_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX,
      (void (*)(void))hybrid_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX,
      (void (*)(void))hybrid_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX,
      (void (*)(void))hybrid_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))hybrid_sig_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))hybrid_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))hybrid_sig_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))hybrid_sig_digest_verify },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))hybrid_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))hybrid_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))hybrid_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))hybrid_sig_gettable_ctx_params },
    { 0, NULL }
};
