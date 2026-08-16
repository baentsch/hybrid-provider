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
#include <openssl/proverr.h>

/*
 * The operation context carries no libctx of its own: the component sign/verify
 * below source their library context and property queries from the key
 * (key->libctx / HYBRID_KEY_*_PROPQ), captured from the provider's component
 * context at key construction (see hybrid_keymgmt.c, HYBRID_COMPONENT_LIBCTX).
 * One unambiguous source for the component context; never the global default.
 */
typedef struct {
    HYBRID_KEY *key;
    int op;     /* EVP_PKEY_OP_SIGN or EVP_PKEY_OP_VERIFY */
    /*
     * Optional per-operation signature context string (issue #46). Applied ONLY
     * to the PQ component, which is the half that supports it (ML-DSA and the
     * other PQ signatures take a context string). The classical component
     * (ECDSA/RSA over a digest) has no such concept, so it is always driven
     * without it — forwarding a context string there would force a spurious
     * failure. Owned here; freed in freectx, deep-copied in dupctx.
     */
    unsigned char *ctxstr;
    size_t ctxstrlen;
    /*
     * Streaming message-signature buffer (item 14). The hybrid signature is
     * inherently one-shot (the PQ half signs the raw message; the classical half
     * digests then signs), but OpenSSL's CMS content-signing path — `openssl cms
     * -sign -noattr` — drives the message-signature API (sign_message_init +
     * update* + final) rather than digest-sign. We satisfy it by accumulating the
     * update() bytes here and running the one-shot over the whole buffer in
     * final(). Owned here; freed in freectx, deep-copied in dupctx.
     */
    unsigned char *msg;
    size_t msglen;
    /*
     * The signature to check, for the streaming verify-message path. Per the
     * provider API, verify_message_final() takes only the ctx — the signature
     * is supplied out-of-band via the OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param
     * (set through set_ctx_params). Owned here; freed in freectx, copied in dup.
     */
    unsigned char *sigbuf;
    size_t sigbuflen;
} HYBRID_SIG_CTX;

static void *hybrid_sig_newctx(void *provctx, const char *propq)
{
    return OPENSSL_zalloc(sizeof(HYBRID_SIG_CTX));
}

static void hybrid_sig_freectx(void *vctx)
{
    HYBRID_SIG_CTX *ctx = vctx;

    if (ctx != NULL) {
        OPENSSL_free(ctx->ctxstr);
        OPENSSL_free(ctx->msg);
        OPENSSL_free(ctx->sigbuf);
    }
    OPENSSL_free(ctx);
}

static void *hybrid_sig_dupctx(void *vctx)
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_SIG_CTX *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    *ret = *ctx;
    /* Deep-copy the owned buffers so each ctx frees its own copy. Null the
     * aliases first so a partial-copy error path frees only what it allocated. */
    ret->ctxstr = NULL;
    ret->msg = NULL;
    ret->sigbuf = NULL;
    if (ctx->ctxstr != NULL
            && (ret->ctxstr = OPENSSL_memdup(ctx->ctxstr, ctx->ctxstrlen)) == NULL)
        goto err;
    if (ctx->msg != NULL
            && (ret->msg = OPENSSL_memdup(ctx->msg, ctx->msglen)) == NULL)
        goto err;
    if (ctx->sigbuf != NULL
            && (ret->sigbuf = OPENSSL_memdup(ctx->sigbuf, ctx->sigbuflen)) == NULL)
        goto err;
    return ret;
err:
    hybrid_sig_freectx(ret);
    return NULL;
}

/*
 * Apply the settable ctx-params (issue #46). Currently just the signature
 * context string, which init and set_ctx_params both route through here so a
 * caller may supply it either in the *_init params or via a later
 * EVP_PKEY_CTX_set_params. An empty/absent value clears any stored string.
 */
static int hybrid_sig_apply_params(HYBRID_SIG_CTX *ctx,
                                    const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *buf = NULL;
        size_t len = 0;

        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "signature context-string must be an octet string");
            return 0;
        }
        if (!OSSL_PARAM_get_octet_string(p, &buf, 0, &len)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "cannot read the signature context-string parameter");
            return 0;
        }
        OPENSSL_free(ctx->ctxstr);
        ctx->ctxstr = buf;
        ctx->ctxstrlen = len;
    }
    /*
     * The signature to check for the streaming verify-message path (item 14):
     * verify_message_final() takes only the ctx, so libcrypto delivers the
     * signature here as an octet string before calling it.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
    if (p != NULL) {
        void *buf = NULL;
        size_t len = 0;

        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "signature parameter must be an octet string");
            return 0;
        }
        if (!OSSL_PARAM_get_octet_string(p, &buf, 0, &len)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "cannot read the signature parameter");
            return 0;
        }
        OPENSSL_free(ctx->sigbuf);
        ctx->sigbuf = buf;
        ctx->sigbuflen = len;
    }
    return 1;
}

static int
hybrid_sig_digest_sign_init(void *vctx, const char *mdname,
                             void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (key == NULL || !hybrid_have_prvkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY,
                       "hybrid signing requires a private key");
        return 0;
    }
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_SIGN;
    return hybrid_sig_apply_params(ctx, params);
}

static int
hybrid_sig_digest_verify_init(void *vctx, const char *mdname,
                               void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (key == NULL || !hybrid_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
                       "hybrid verification requires a public key");
        return 0;
    }
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_VERIFY;
    return hybrid_sig_apply_params(ctx, params);
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
 * Build the OSSL_PARAM array handed to the PQ component's DigestSign/Verify init
 * (issue #46). Returns the array (into the caller-provided storage) when a
 * context string is set, or NULL when none is — so the PQ component runs with
 * its default (empty) context, preserving the oqsprovider-compatible wire format.
 * The classical component never receives these params.
 */
static OSSL_PARAM *pq_ctx_params(HYBRID_SIG_CTX *ctx, OSSL_PARAM store[2])
{
    if (ctx->ctxstr == NULL)
        return NULL;
    store[0] = OSSL_PARAM_construct_octet_string(
                   OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                   ctx->ctxstr, ctx->ctxstrlen);
    store[1] = OSSL_PARAM_construct_end();
    return store;
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
    OSSL_PARAM pqp_store[2], *pqp;
    size_t clen = 0, plen = 0, maxsig;
    int is_rsa = (strcmp(info->alg1_name, "RSA") == 0);
    int ret = 0;

    maxsig = hybrid_sig_max_sig_bytes(key);

    if (sig == NULL) {          /* size query */
        *siglen = maxsig;
        return 1;
    }
    if (!hybrid_have_prvkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY,
                       "hybrid signing requires a private key");
        return 0;
    }
    if (sigsize < maxsig) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "hybrid signature buffer %zu < required %zu",
                       sigsize, maxsig);
        return 0;
    }

    /* classical signature, written after the 4-byte length prefix */
    if (!classical_op(key, 1, is_rsa, classical_md(info->nist_level),
                      tbs, tbslen, sig + sizeof(uint32_t), &clen,
                      key->sizes->a1_sig)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid classical component signing failed");
        goto err;
    }
    sig[0] = (unsigned char)(clen >> 24);
    sig[1] = (unsigned char)(clen >> 16);
    sig[2] = (unsigned char)(clen >> 8);
    sig[3] = (unsigned char)(clen);

    /* PQ signature over the raw message, appended after the classical sig.
     * The context string (if any) is applied here, to the PQ half only. */
    pqp = pq_ctx_params(ctx, pqp_store);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL
        || EVP_DigestSignInit_ex(mctx, NULL, NULL, key->libctx,
                                 HYBRID_KEY_PQ_PROPQ(key), key->key2, pqp) <= 0) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid PQ component sign init failed");
        goto err;
    }
    plen = key->sizes->a2_sig;
    if (EVP_DigestSign(mctx, sig + sizeof(uint32_t) + clen, &plen,
                       tbs, tbslen) <= 0) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid PQ component signing failed");
        goto err;
    }

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
    OSSL_PARAM pqp_store[2], *pqp;
    size_t clen, plen;
    int is_rsa = (strcmp(info->alg1_name, "RSA") == 0);
    int ret = 0;

    if (!hybrid_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
                       "hybrid verification requires a public key");
        return 0;
    }
    /* Bounds guards: the signature must hold the 4-byte classical-length prefix
     * before we read sig[0..3], and that length must fit within siglen before we
     * split off the classical and PQ parts (else a malformed signature would
     * cause an out-of-bounds read). */
    if (siglen < sizeof(uint32_t)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                       "hybrid signature %zu too short for the length prefix",
                       siglen);
        return 0;
    }
    clen = ((size_t)sig[0] << 24) | ((size_t)sig[1] << 16)
         | ((size_t)sig[2] << 8) | (size_t)sig[3];
    if (sizeof(uint32_t) + clen > siglen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                       "hybrid classical length %zu inconsistent with "
                       "signature length %zu", clen, siglen);
        return 0;
    }
    plen = siglen - sizeof(uint32_t) - clen;

    /* verify classical over the digest */
    if (!classical_op(key, 0, is_rsa, classical_md(info->nist_level),
                      tbs, tbslen, (unsigned char *)sig + sizeof(uint32_t),
                      &clen, 0)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid classical component verification failed");
        goto err;
    }

    /* verify PQ over the raw message; context string (if any) applied to the
     * PQ half only, matching the sign side. */
    pqp = pq_ctx_params(ctx, pqp_store);
    mctx = EVP_MD_CTX_new();
    if (mctx == NULL
        || EVP_DigestVerifyInit_ex(mctx, NULL, NULL, key->libctx,
                                   HYBRID_KEY_PQ_PROPQ(key), key->key2,
                                   pqp) <= 0) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid PQ component verify init failed");
        goto err;
    }
    if (EVP_DigestVerify(mctx, sig + sizeof(uint32_t) + clen, plen,
                         tbs, tbslen) <= 0) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid PQ component verification failed");
        goto err;
    }

    ret = 1;
err:
    EVP_MD_CTX_free(mctx);
    return ret;
}

/*
 * Message-signature API (item 14). Unlike digest-sign, these entry points sign
 * the *message* itself — which is exactly what the hybrid does — and are what
 * OpenSSL's CMS content-signing path (`cms -sign -noattr`) and other message-mode
 * callers drive for no-digest algorithms. sign/verify are one-shot; the streaming
 * update/final variants buffer the message and defer to the one-shot in final.
 */
static int
hybrid_sig_sign_message_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;

    OPENSSL_free(ctx->msg);             /* reset any prior streamed message */
    ctx->msg = NULL;
    ctx->msglen = 0;
    return hybrid_sig_digest_sign_init(vctx, NULL, vkey, params);
}

static int
hybrid_sig_reset_verify_stream(HYBRID_SIG_CTX *ctx)
{
    OPENSSL_free(ctx->msg);
    ctx->msg = NULL;
    ctx->msglen = 0;
    OPENSSL_free(ctx->sigbuf);
    ctx->sigbuf = NULL;
    ctx->sigbuflen = 0;
    return 1;
}

static int
hybrid_sig_verify_message_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;

    hybrid_sig_reset_verify_stream(ctx);
    return hybrid_sig_digest_verify_init(vctx, NULL, vkey, params);
}

/* Accumulate a message fragment for the streaming message-signature path. */
static int
hybrid_sig_signverify_message_update(void *vctx, const unsigned char *data,
                                     size_t datalen)
{
    HYBRID_SIG_CTX *ctx = vctx;
    unsigned char *grown;

    if (datalen == 0)
        return 1;
    if ((grown = OPENSSL_realloc(ctx->msg, ctx->msglen + datalen)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ctx->msg = grown;
    memcpy(ctx->msg + ctx->msglen, data, datalen);
    ctx->msglen += datalen;
    return 1;
}

/* Finish a streaming sign: one-shot over the accumulated message. */
static int
hybrid_sig_sign_message_final(void *vctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize)
{
    HYBRID_SIG_CTX *ctx = vctx;

    return hybrid_sig_digest_sign(vctx, sig, siglen, sigsize,
                                  ctx->msg, ctx->msglen);
}

/*
 * Finish a streaming verify: one-shot over the accumulated message against the
 * signature previously delivered via OSSL_SIGNATURE_PARAM_SIGNATURE.
 */
static int
hybrid_sig_verify_message_final(void *vctx)
{
    HYBRID_SIG_CTX *ctx = vctx;

    if (ctx->sigbuf == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "no signature set for the streaming verify (expected the "
                       "OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param)");
        return 0;
    }
    return hybrid_sig_digest_verify(vctx, ctx->sigbuf, ctx->sigbuflen,
                                    ctx->msg, ctx->msglen);
}

static const OSSL_PARAM *hybrid_sig_settable_ctx_params(void *vctx,
                                                          void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int hybrid_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return hybrid_sig_apply_params(vctx, params);
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
    /* Message-signature API (item 14): one-shot + streaming. sign/verify reuse
     * the digest-sign one-shot, which already signs the raw message. */
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
      (void (*)(void))hybrid_sig_sign_message_init },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
      (void (*)(void))hybrid_sig_signverify_message_update },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
      (void (*)(void))hybrid_sig_sign_message_final },
    { OSSL_FUNC_SIGNATURE_SIGN,
      (void (*)(void))hybrid_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
      (void (*)(void))hybrid_sig_verify_message_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
      (void (*)(void))hybrid_sig_signverify_message_update },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
      (void (*)(void))hybrid_sig_verify_message_final },
    { OSSL_FUNC_SIGNATURE_VERIFY,
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
