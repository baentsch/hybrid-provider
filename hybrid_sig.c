/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid signature dispatch — one-shot DigestSign/DigestVerify
 * combining a classical signature (EdDSA or ECDSA) with a PQ
 * signature (ML-DSA).
 *
 * Wire format: sig = alg1_sig || alg2_sig
 * For ECDSA (variable-length DER), alg1_sig is zero-padded to max size.
 */

#include "hybrid_prov.h"

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
 * One-shot DigestSign: sign tbs with both sub-keys, concatenate.
 * sig = alg1_sig (zero-padded to max) || alg2_sig
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
    size_t total_siglen = info->alg1_sig_bytes + info->alg2_sig_bytes;
    EVP_MD_CTX *mctx1 = NULL, *mctx2 = NULL;
    size_t sig1len, sig2len;
    int ret = 0;

    /* Size query */
    if (sig == NULL) {
        *siglen = total_siglen;
        return 1;
    }
    if (sigsize < total_siglen)
        return 0;

    if (!hybrid_have_prvkey(key))
        return 0;

    /* Zero the output so variable-length alg1 sigs are zero-padded */
    memset(sig, 0, total_siglen);

    /* Sign with alg1 (classical) */
    mctx1 = EVP_MD_CTX_new();
    if (mctx1 == NULL)
        goto err;
    if (EVP_DigestSignInit_ex(mctx1, NULL, NULL, key->libctx,
                               key->propq, key->key1, NULL) <= 0)
        goto err;
    sig1len = info->alg1_sig_bytes;
    if (EVP_DigestSign(mctx1, sig, &sig1len, tbs, tbslen) <= 0)
        goto err;
    /* sig1len may be < alg1_sig_bytes for ECDSA; that's fine, rest is zeroed */

    /* Sign with alg2 (PQ) */
    mctx2 = EVP_MD_CTX_new();
    if (mctx2 == NULL)
        goto err;
    if (EVP_DigestSignInit_ex(mctx2, NULL, NULL, key->libctx,
                               key->propq, key->key2, NULL) <= 0)
        goto err;
    sig2len = info->alg2_sig_bytes;
    if (EVP_DigestSign(mctx2, sig + info->alg1_sig_bytes,
                        &sig2len, tbs, tbslen) <= 0)
        goto err;

    *siglen = total_siglen;
    ret = 1;

err:
    EVP_MD_CTX_free(mctx1);
    EVP_MD_CTX_free(mctx2);
    return ret;
}

/*
 * One-shot DigestVerify: split signature, verify both sub-keys.
 * Both must pass for the hybrid verify to succeed.
 */
static int
hybrid_sig_digest_verify(void *vctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_SIG_INFO *info = (const HYBRID_SIG_INFO *)key->info;
    size_t total_siglen = info->alg1_sig_bytes + info->alg2_sig_bytes;
    EVP_MD_CTX *mctx1 = NULL, *mctx2 = NULL;
    const unsigned char *sig1, *sig2;
    size_t sig1len, sig2len;
    int ret = 0;

    if (siglen != total_siglen)
        return 0;
    if (!hybrid_have_pubkey(key))
        return 0;

    sig1 = sig;
    sig1len = info->alg1_sig_bytes;
    sig2 = sig + info->alg1_sig_bytes;
    sig2len = info->alg2_sig_bytes;

    /*
     * For ECDSA, the actual DER signature may be shorter than the max.
     * Find the real length from the DER encoding: tag(0x30) + length.
     * EdDSA signatures are fixed-length, so this is safe for them too
     * (they won't match 0x30 tag pattern in a meaningful way, but their
     * sig1len already equals the exact size).
     */
    if (sig1len > 2 && sig1[0] == 0x30) {
        /* DER sequence: parse length */
        if (sig1[1] < 0x80) {
            sig1len = 2 + sig1[1];
        } else if (sig1[1] == 0x81 && sig1len > 3) {
            sig1len = 3 + sig1[2];
        }
    }

    /* Verify alg1 (classical) */
    mctx1 = EVP_MD_CTX_new();
    if (mctx1 == NULL)
        goto err;
    if (EVP_DigestVerifyInit_ex(mctx1, NULL, NULL, key->libctx,
                                 key->propq, key->key1, NULL) <= 0)
        goto err;
    if (EVP_DigestVerify(mctx1, sig1, sig1len, tbs, tbslen) <= 0)
        goto err;

    /* Verify alg2 (PQ) */
    mctx2 = EVP_MD_CTX_new();
    if (mctx2 == NULL)
        goto err;
    if (EVP_DigestVerifyInit_ex(mctx2, NULL, NULL, key->libctx,
                                 key->propq, key->key2, NULL) <= 0)
        goto err;
    if (EVP_DigestVerify(mctx2, sig2, sig2len, tbs, tbslen) <= 0)
        goto err;

    ret = 1;

err:
    EVP_MD_CTX_free(mctx1);
    EVP_MD_CTX_free(mctx2);
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
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };
    return params;
}

static int hybrid_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
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
