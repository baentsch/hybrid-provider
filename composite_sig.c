/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) signature combiner — the cryptographic core of the composite
 * family (issue #6), kept independent of the provider plumbing so it can be unit-
 * tested directly with EVP-generated component keys (test/composite_sig_test.c).
 *
 * draft-ietf-lamps-pq-composite-sigs-19 (verify verbatim before interop):
 *   M'      = PREFIX || label || len(ctx) || ctx || PH(M)      (ctx empty here)
 *   pqSig   = PQ.Sign(pqSK, M', context = label)               (ML-DSA one-shot)
 *   tradSig = Trad.Sign(tradSK, M')  — with trad_md (EC/RSA-PSS) or pure (Ed)
 *   sig     = pqSig || tradSig       (raw concat)
 * Verify splits at the fixed ML-DSA signature length (EVP_PKEY_get_size(pq)).
 *
 * SCOPE / caveats (self-consistent, not yet interop-verified):
 *  - The domain-separator content in `label` (ASCII vs OID DER) and the ML-DSA
 *    context value are a best-effort draft-19 reading; both sign and verify use
 *    the same values, so round-trip passes regardless — interop fidelity against
 *    Bouncy Castle / OpenSSL-native composite still needs confirming.
 *  - The concat split assumes a FIXED-length PQ signature (verify splits at
 *    EVP_PKEY_get_size(pq)). Every experimental-tier PQ component is chosen to be
 *    fixed-length for this reason: MAYO/CROSS/UOV/SNOVA/MQOM2 already are, and
 *    Falcon is included only via its *padded* variants (constant-size sig). A
 *    genuinely variable-length PQ sig (plain Falcon) would need a length prefix —
 *    a follow-up if such a combo is ever added.
 */
#include "composite_prov.h"
#include "hybrid_msg_accum.h"
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <string.h>
#include <stdint.h>

/*
 * The message-signature API (sign_message_init/update/final, verify_message_*,
 * and the OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param) landed in OpenSSL 3.4. Guard
 * on the presence of the dispatch define rather than a version test, so the block
 * compiles out cleanly on the composite experimental floor (3.2/3.3) where the
 * API does not exist. CMS does not need it: it signs composites by digest-sign
 * (signed attributes) or external prehash (-noattr), both 3.0 entry points.
 * Mirrors hybrid_sig.c's HYBRID_HAVE_MSG_SIG.
 */
#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
# define COMPOSITE_HAVE_MSG_SIG 1
#endif

/* ph = PH(M): the composite's fixed prehash (SHAKE256 at 64 bytes). */
static int composite_prehash(const COMPOSITE_SIG_INFO *info,
                             OSSL_LIB_CTX *libctx,
                             const unsigned char *msg, size_t msglen,
                             unsigned char *ph, size_t *phlen)
{
    /* Provider-neutral message prehash: fetched from the provider's libctx with
     * default properties. It deliberately does NOT take a component propquery —
     * those steer the PQ/classical signature providers (e.g. oqsprovider), which
     * need not supply this digest. */
    EVP_MD *md = EVP_MD_fetch(libctx, info->prehash, NULL);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    int ret = 0;

    if (md == NULL || mc == NULL
            || EVP_DigestInit_ex2(mc, md, NULL) <= 0
            || EVP_DigestUpdate(mc, msg, msglen) <= 0)
        goto end;
    if ((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
        *phlen = COMPOSITE_XOF_PH_BYTES;
        ret = EVP_DigestFinalXOF(mc, ph, *phlen) > 0;
    } else {
        unsigned int l = 0;

        ret = EVP_DigestFinal_ex(mc, ph, &l) > 0;
        *phlen = l;
    }
end:
    EVP_MD_CTX_free(mc);
    EVP_MD_free(md);
    return ret;
}

/* Byte length of PH(M) for this combo (0 if the digest is unavailable). */
static size_t composite_ph_len(const COMPOSITE_SIG_INFO *info,
                               OSSL_LIB_CTX *libctx)
{
    EVP_MD *md = EVP_MD_fetch(libctx, info->prehash, NULL);
    size_t n = 0;

    if (md != NULL)
        n = (EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0
                ? COMPOSITE_XOF_PH_BYTES : (size_t)EVP_MD_get_size(md);
    EVP_MD_free(md);
    return n;
}

/* M' = PREFIX || label || len(ctx) || ctx || ph, with ph = PH(M) already. */
static int composite_mprime_from_ph(const COMPOSITE_SIG_INFO *info,
                                    const unsigned char *ph, size_t phlen,
                                    const unsigned char *ctx, size_t ctxlen,
                                    unsigned char **out, size_t *outlen)
{
    static const char prefix[] = COMPOSITE_SIG_PREFIX; /* trailing NUL unused */
    size_t plen = sizeof(prefix) - 1, llen = strlen(info->label);
    unsigned char *buf;

    if (ctxlen > COMPOSITE_SIG_CTX_MAX || (ctxlen > 0 && ctx == NULL)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "composite context string longer than %d bytes",
                       COMPOSITE_SIG_CTX_MAX);
        return 0;
    }
    *outlen = plen + llen + 1 + ctxlen + phlen;
    if ((buf = OPENSSL_malloc(*outlen)) == NULL)
        return 0;
    memcpy(buf, prefix, plen);
    memcpy(buf + plen, info->label, llen);
    buf[plen + llen] = (unsigned char)ctxlen;     /* len(ctx), one octet */
    if (ctxlen > 0)
        memcpy(buf + plen + llen + 1, ctx, ctxlen);
    memcpy(buf + plen + llen + 1 + ctxlen, ph, phlen);
    *out = buf;
    return 1;
}

/* M' = PREFIX || label || len(ctx) || ctx || PH(M). */
int composite_build_mprime(const COMPOSITE_SIG_INFO *info,
                           OSSL_LIB_CTX *libctx,
                           const unsigned char *msg, size_t msglen,
                           const unsigned char *ctx, size_t ctxlen,
                           unsigned char **out, size_t *outlen)
{
    unsigned char ph[EVP_MAX_MD_SIZE];
    size_t phlen = 0;

    if (ctxlen > COMPOSITE_SIG_CTX_MAX)     /* refuse before hashing anything */
        return composite_mprime_from_ph(info, NULL, 0, ctx, ctxlen, out,
                                        outlen);
    return composite_prehash(info, libctx, msg, msglen, ph, &phlen)
           && composite_mprime_from_ph(info, ph, phlen, ctx, ctxlen, out,
                                       outlen);
}

/*
 * M' from the caller's input: the message itself, or (prehashed) ph = PH(M)
 * computed outside -- draft-19 "External Pre-hashing", compliant as it yields
 * the same output. A ph must be exactly PH's length.
 */
static int composite_mprime(const COMPOSITE_SIG_INFO *info,
                            OSSL_LIB_CTX *libctx, int prehashed,
                            const unsigned char *in, size_t inlen,
                            const unsigned char *ctx, size_t ctxlen,
                            unsigned char **out, size_t *outlen)
{
    size_t want;

    if (!prehashed)
        return composite_build_mprime(info, libctx, in, inlen, ctx, ctxlen,
                                      out, outlen);
    want = composite_ph_len(info, libctx);
    if (want == 0 || inlen != want) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH,
                       "%s prehash must be %zu bytes of %s, got %zu",
                       info->name, want, info->prehash, inlen);
        return 0;
    }
    return composite_mprime_from_ph(info, in, inlen, ctx, ctxlen, out, outlen);
}

/*
 * PQ component: one-shot over M'. draft-19 passes the Label to ML-DSA as its
 * own context string (mldsa_ctx = Label), so the standardized (ML-DSA) tier
 * sets it -- after init, where a component must honour or refuse it, and a
 * refusal fails closed. The experimental tier's components (Falcon, MAYO, ...)
 * have no context-string input; the Label still reaches them inside M'.
 */
static int pq_op(int sign, const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq,
                 OSSL_LIB_CTX *libctx, const char *propq,
                 const unsigned char *mp, size_t mplen,
                 unsigned char **osig, size_t *olen,
                 const unsigned char *isig, size_t ilen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    OSSL_PARAM sp[2];
    unsigned char *s = NULL;
    size_t l = 0;
    int ret = 0;

    sp[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                              (void *)info->label,
                                              strlen(info->label));
    sp[1] = OSSL_PARAM_construct_end();
    if (m == NULL)
        goto end;
    if ((sign ? EVP_DigestSignInit_ex(m, NULL, NULL, libctx, propq, pq, NULL)
              : EVP_DigestVerifyInit_ex(m, NULL, NULL, libctx, propq, pq,
                                        NULL)) <= 0)
        goto end;
    if (info->tier == COMPOSITE_TIER_STANDARD
            && EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(m), sp) <= 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "%s: PQ component %s refused the Label as its context "
                       "string", info->name, info->pq_alg);
        goto end;
    }
    if (sign) {
        if (EVP_DigestSign(m, NULL, &l, mp, mplen) <= 0
                || (s = OPENSSL_malloc(l)) == NULL
                || EVP_DigestSign(m, s, &l, mp, mplen) <= 0)
            goto end;
        *osig = s; *olen = l; s = NULL;
    } else if (EVP_DigestVerify(m, isig, ilen, mp, mplen) != 1) {
        goto end;
    }
    ret = 1;
end:
    OPENSSL_free(s);
    EVP_MD_CTX_free(m);
    return ret;
}

/* Classical component: sign/verify M' with trad_md (EC/RSA-PSS) or pure (Ed). */
static int trad_op(int sign, const COMPOSITE_SIG_INFO *info, EVP_PKEY *trad,
                   OSSL_LIB_CTX *libctx, const char *propq,
                   const unsigned char *mp, size_t mplen,
                   unsigned char **osig, size_t *olen,
                   const unsigned char *isig, size_t ilen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    int is_pss = (strcmp(info->trad_alg, "RSA-PSS") == 0);
    unsigned char *s = NULL;
    size_t l = 0;
    int ret = 0;

    if (m == NULL)
        goto end;
    if (sign) {
        if (EVP_DigestSignInit_ex(m, &pctx, info->trad_md, libctx, propq,
                                  trad, NULL) <= 0)
            goto end;
    } else {
        if (EVP_DigestVerifyInit_ex(m, &pctx, info->trad_md, libctx, propq,
                                    trad, NULL) <= 0)
            goto end;
    }
    if (is_pss) {
        /* draft Table 2: MGF1 == message hash, salt == hash length. */
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
                                                    RSA_PSS_SALTLEN_DIGEST) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, info->trad_md,
                                                     NULL) <= 0)
            goto end;
    }
    if (sign) {
        if (EVP_DigestSign(m, NULL, &l, mp, mplen) <= 0
                || (s = OPENSSL_malloc(l)) == NULL
                || EVP_DigestSign(m, s, &l, mp, mplen) <= 0)
            goto end;
        *osig = s; *olen = l; s = NULL;
    } else {
        if (EVP_DigestVerify(m, isig, ilen, mp, mplen) != 1)
            goto end;
    }
    ret = 1;
end:
    OPENSSL_free(s);
    EVP_MD_CTX_free(m);
    return ret;
}

static int composite_sign_ex(int prehashed,
                   const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                   OSSL_LIB_CTX *libctx, const char *alg2_propq,
                   const char *trad_propq, const unsigned char *msg,
                   size_t msglen, const unsigned char *ctx, size_t ctxlen,
                   unsigned char **sig, size_t *siglen)
{
    unsigned char *mp = NULL, *pqsig = NULL, *tradsig = NULL;
    size_t mplen = 0, pqlen = 0, tradlen = 0;
    int ret = 0;

    if (!composite_mprime(info, libctx, prehashed, msg, msglen, ctx, ctxlen,
                          &mp, &mplen)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "composite sign: message prehash (M') failed");
        goto end;
    }
    if (!pq_op(1, info, pq, libctx, alg2_propq, mp, mplen,
               &pqsig, &pqlen, NULL, 0)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "composite sign: PQ component signing failed");
        goto end;
    }
    if (!trad_op(1, info, trad, libctx, trad_propq, mp, mplen,
                 &tradsig, &tradlen, NULL, 0)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "composite sign: classical component signing failed");
        goto end;
    }

    *siglen = pqlen + tradlen;
    if ((*sig = OPENSSL_malloc(*siglen)) == NULL)
        goto end;
    memcpy(*sig, pqsig, pqlen);
    memcpy(*sig + pqlen, tradsig, tradlen);
    ret = 1;
end:
    OPENSSL_free(mp);
    OPENSSL_free(pqsig);
    OPENSSL_free(tradsig);
    return ret;
}

static int composite_verify_ex(int prehashed,
                   const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                     OSSL_LIB_CTX *libctx, const char *alg2_propq,
                     const char *trad_propq, const unsigned char *msg,
                     size_t msglen, const unsigned char *ctx, size_t ctxlen,
                     const unsigned char *sig, size_t siglen)
{
    unsigned char *mp = NULL;
    size_t mplen = 0;
    int pqfixed = EVP_PKEY_get_size(pq);   /* fixed ML-DSA/MAYO signature length */
    int ret = 0;

    /*
     * Length sanity check BEFORE splitting the concatenated signature at the
     * fixed PQ-signature length (issue #46). A truncated or otherwise
     * wrong-length signature would leave no bytes (or a negative count) for the
     * classical component; reject it with a defined error rather than passing a
     * bogus pointer/length pair to the classical verify.
     */
    if (pqfixed <= 0 || (size_t)pqfixed >= siglen) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "composite verify: signature length %zu too short for "
                       "the %d-byte PQ component", siglen, pqfixed);
        return 0;                          /* need room for both components */
    }
    if (!composite_mprime(info, libctx, prehashed, msg, msglen, ctx, ctxlen,
                          &mp, &mplen)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "composite verify: message prehash (M') failed");
        goto end;
    }
    if (!pq_op(0, info, pq, libctx, alg2_propq, mp, mplen,
               NULL, NULL, sig, (size_t)pqfixed)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "composite verify: PQ component verification failed");
        goto end;
    }
    if (!trad_op(0, info, trad, libctx, trad_propq, mp, mplen,
                 NULL, NULL, sig + pqfixed, siglen - (size_t)pqfixed)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "composite verify: classical component verification "
                       "failed");
        goto end;
    }
    ret = 1;
end:
    OPENSSL_free(mp);
    return ret;
}

int composite_sign(const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                   OSSL_LIB_CTX *libctx, const char *alg2_propq,
                   const char *trad_propq, const unsigned char *msg,
                   size_t msglen, const unsigned char *ctx, size_t ctxlen,
                   unsigned char **sig, size_t *siglen)
{
    return composite_sign_ex(0, info, pq, trad, libctx, alg2_propq, trad_propq,
                             msg, msglen, ctx, ctxlen, sig, siglen);
}

int composite_verify(const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq,
                     EVP_PKEY *trad, OSSL_LIB_CTX *libctx,
                     const char *alg2_propq,
                     const char *trad_propq, const unsigned char *msg,
                     size_t msglen, const unsigned char *ctx, size_t ctxlen,
                     const unsigned char *sig, size_t siglen)
{
    return composite_verify_ex(0, info, pq, trad, libctx, alg2_propq,
                               trad_propq, msg, msglen, ctx, ctxlen, sig,
                               siglen);
}

/* --- Provider signature dispatch (wraps the combiner over a COMPOSITE_KEY) --- */

typedef struct {
    COMPOSITE_KEY *key;
    /*
     * Streaming buffers for the message-signature API (issue #109) and for
     * streaming digest-sign (CMS signed attributes). Mechanics shared with
     * hybrid_sig.c via HYBRID_MSG_ACCUM (issue #121); the combiner builds M'
     * over the accumulated message in final(). Freed in freectx, deep-copied
     * in dupctx.
     */
    HYBRID_MSG_ACCUM stream;
    /* Caller context string, bound into M' (inline: a struct copy dups it). */
    unsigned char ctxstr[COMPOSITE_SIG_CTX_MAX];
    size_t ctxstrlen;
    /* Set by sign_init/verify_init: sign()/verify() then take ph = PH(M), as
     * EVP_PKEY_sign() hands a digest (CMS -noattr signs that way). The
     * message inits clear it: there sign()/verify() take the message. */
    int prehashed;
} COMPOSITE_SIGCTX;

static void *composite_sig_newctx(void *provctx, const char *propq)
{
    return OPENSSL_zalloc(sizeof(COMPOSITE_SIGCTX));
}

static void composite_sig_freectx(void *vctx)
{
    COMPOSITE_SIGCTX *c = vctx;

    if (c != NULL)
        hybrid_msg_accum_reset(&c->stream);
    OPENSSL_free(c);
}

static void *composite_sig_dupctx(void *vctx)
{
    COMPOSITE_SIGCTX *src = vctx;
    COMPOSITE_SIGCTX *c = OPENSSL_zalloc(sizeof(*c));

    if (c == NULL)
        return NULL;
    *c = *src;
    /* Deep-copy the owned buffers so each ctx frees its own copy. Drop the
     * aliases first so a partial-copy error path frees only what it allocated. */
    hybrid_msg_accum_init(&c->stream);
    if (!hybrid_msg_accum_dup(&c->stream, &src->stream))
        goto err;
    return c;
err:
    composite_sig_freectx(c);
    return NULL;
}

/*
 * Apply the settable ctx params: the context string (3.2+ name), and for the
 * streaming verify-message path (3.4+) the signature to check, which
 * verify_message_final() cannot take as an argument. Shared by the inits and
 * set_ctx_params.
 */
static int composite_sig_check_digest(const COMPOSITE_KEY *k,
                                      const char *mdname);

static int composite_sig_apply_params(COMPOSITE_SIGCTX *c,
                                      const OSSL_PARAM params[])
{
    const OSSL_PARAM *pd = params == NULL ? NULL
        : OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);

    /* EVP_SignFinal_ex names the digest it hashed with: it must be PH. */
    if (pd != NULL) {
        const char *mdname = NULL;

        if (!OSSL_PARAM_get_utf8_string_ptr(pd, &mdname) || c->key == NULL
                || !composite_sig_check_digest(c->key, mdname))
            return 0;
    }
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
    const OSSL_PARAM *p;
    void *buf = c->ctxstr;
    size_t len = 0;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "composite context-string must be an octet string");
            return 0;
        }
        /* draft-19 Sign/Verify step 1: len(ctx) > 255 MUST be an error. */
        if (p->data_size > COMPOSITE_SIG_CTX_MAX) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "composite context-string of %zu bytes exceeds "
                           "the maximum of %d", p->data_size,
                           COMPOSITE_SIG_CTX_MAX);
            return 0;
        }
        if (!OSSL_PARAM_get_octet_string(p, &buf, sizeof(c->ctxstr), &len)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                           "cannot read the composite context string");
            return 0;
        }
        c->ctxstrlen = len;
    }
#endif
#ifdef COMPOSITE_HAVE_MSG_SIG
    return hybrid_msg_accum_set_sig_param(&c->stream, params);
#else
    (void)c;
    (void)params;
    return 1;
#endif
}

/* CMS composite sigs (draft-ietf-lamps-cms-composite-sigs-05 3.3, Table 1):
 * the SignerInfo digestAlgorithm MUST be the composite's own prehash, and the
 * CMS layer hands it to us as mdname. Accept none, or exactly PH; refuse any
 * other digest instead of signing a message the verifier would mis-hash. */
static int composite_sig_check_digest(const COMPOSITE_KEY *k,
                                      const char *mdname)
{
    EVP_MD *md;
    int ok;

    if (mdname == NULL || mdname[0] == '\0')
        return 1;
    md = EVP_MD_fetch(k->libctx, mdname, NULL);
    ok = md != NULL && EVP_MD_is_a(md, k->info->prehash);
    EVP_MD_free(md);
    if (!ok)
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                       "%s requires digest %s, got %s", k->info->name,
                       k->info->prehash, mdname);
    return ok;
}

static int composite_sig_sign_init(void *vctx, const char *mdname, void *vkey,
                                   const OSSL_PARAM params[])
{
    COMPOSITE_SIGCTX *c = vctx;
    COMPOSITE_KEY *k = vkey;

    if (k == NULL || k->state < COMPOSITE_HAVE_PRVKEY) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY,
                       "composite signing requires a private key");
        return 0;
    }
    if (!composite_sig_check_digest(k, mdname))
        return 0;
    c->key = k;
    c->prehashed = 0;
    hybrid_msg_accum_reset(&c->stream);
    return composite_sig_apply_params(c, params);
}

static int composite_sig_verify_init(void *vctx, const char *mdname, void *vkey,
                                     const OSSL_PARAM params[])
{
    COMPOSITE_SIGCTX *c = vctx;
    COMPOSITE_KEY *k = vkey;

    if (k == NULL || k->state < COMPOSITE_HAVE_PUBKEY) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
                       "composite verification requires a public key");
        return 0;
    }
    if (!composite_sig_check_digest(k, mdname))
        return 0;
    c->key = k;
    c->prehashed = 0;
    hybrid_msg_accum_reset(&c->stream);
    return composite_sig_apply_params(c, params);
}

static int composite_sig_do_sign(void *vctx, int prehashed, unsigned char *sig,
                                 size_t *siglen, size_t sigsize,
                                     const unsigned char *tbs, size_t tbslen)
{
    COMPOSITE_SIGCTX *c = vctx;
    COMPOSITE_KEY *k = c->key;
    unsigned char *tmp = NULL;
    size_t tlen = 0;
    int ret = 0;

    if (sig == NULL) {          /* size query: upper bound (fixed PQ + max trad) */
        *siglen = (size_t)EVP_PKEY_get_size(k->pq_key)
                + (size_t)EVP_PKEY_get_size(k->trad_key);
        return 1;
    }
    if (!composite_sign_ex(prehashed, k->info, k->pq_key, k->trad_key,
                           k->libctx, k->alg2_propq, k->trad_propq, tbs, tbslen,
                           c->ctxstr, c->ctxstrlen, &tmp, &tlen))
        return 0;                            /* composite_sign already raised */
    if (tlen <= sigsize) {
        memcpy(sig, tmp, tlen);
        *siglen = tlen;
        ret = 1;
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                       "composite signature buffer %zu < required %zu",
                       sigsize, tlen);
    }
    OPENSSL_free(tmp);
    return ret;
}

static int composite_sig_digest_sign(void *vctx, unsigned char *sig,
                                     size_t *siglen, size_t sigsize,
                                     const unsigned char *tbs, size_t tbslen)
{
    return composite_sig_do_sign(vctx, 0, sig, siglen, sigsize, tbs, tbslen);
}

/* EVP_PKEY_sign(): ph after sign_init, the message after sign_message_init. */
static int composite_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    COMPOSITE_SIGCTX *c = vctx;

    return composite_sig_do_sign(vctx, c->prehashed, sig, siglen, sigsize,
                                 tbs, tbslen);
}

static int composite_sig_digest_verify(void *vctx, const unsigned char *sig,
                                       size_t siglen, const unsigned char *tbs,
                                       size_t tbslen)
{
    COMPOSITE_SIGCTX *c = vctx;
    COMPOSITE_KEY *k = c->key;

    return composite_verify_ex(0, k->info, k->pq_key, k->trad_key, k->libctx,
                               k->alg2_propq, k->trad_propq, tbs, tbslen,
                               c->ctxstr, c->ctxstrlen, sig, siglen);
}

/* EVP_PKEY_verify(): ph after verify_init, the message after message init. */
static int composite_sig_verify(void *vctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen)
{
    COMPOSITE_SIGCTX *c = vctx;
    COMPOSITE_KEY *k = c->key;

    return composite_verify_ex(c->prehashed, k->info, k->pq_key, k->trad_key,
                               k->libctx, k->alg2_propq, k->trad_propq, tbs,
                               tbslen, c->ctxstr, c->ctxstrlen, sig, siglen);
}

/* Raw sign/verify init (EVP_PKEY_sign_init): the input is ph = PH(M). */
static int composite_sig_sign_init(void *vctx, const char *mdname, void *vkey,
                                   const OSSL_PARAM params[]);
static int composite_sig_verify_init(void *vctx, const char *mdname, void *vkey,
                                     const OSSL_PARAM params[]);

static int composite_sig_raw_sign_init(void *vctx, void *vkey,
                                       const OSSL_PARAM params[])
{
    if (!composite_sig_sign_init(vctx, NULL, vkey, params))
        return 0;
    ((COMPOSITE_SIGCTX *)vctx)->prehashed = 1;
    return 1;
}

static int composite_sig_raw_verify_init(void *vctx, void *vkey,
                                         const OSSL_PARAM params[])
{
    if (!composite_sig_verify_init(vctx, NULL, vkey, params))
        return 0;
    ((COMPOSITE_SIGCTX *)vctx)->prehashed = 1;
    return 1;
}

/*
 * Streaming digest-sign/verify: what libcrypto drives once an mdname is set
 * (CMS signedAttrs, cms-composite-sigs-05 sec. 3.3). The combiner needs the
 * whole message for M', so buffer it and defer to the one-shot in final.
 */
static int composite_sig_digest_update(void *vctx, const unsigned char *data,
                                       size_t datalen)
{
    COMPOSITE_SIGCTX *c = vctx;

    return hybrid_msg_accum_append(&c->stream, data, datalen);
}

static int composite_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                           size_t *siglen, size_t sigsize)
{
    COMPOSITE_SIGCTX *c = vctx;

    return composite_sig_digest_sign(vctx, sig, siglen, sigsize,
                                     c->stream.msg, c->stream.msglen);
}

static int composite_sig_digest_verify_final(void *vctx,
                                             const unsigned char *sig,
                                             size_t siglen)
{
    COMPOSITE_SIGCTX *c = vctx;

    return composite_sig_digest_verify(vctx, sig, siglen,
                                       c->stream.msg, c->stream.msglen);
}

#ifdef COMPOSITE_HAVE_MSG_SIG
/*
 * Message-signature API (issue #109). Unlike digest-sign, these entry points
 * sign the *message* itself — which is exactly what the composite combiner does
 * (it builds M' over the whole message). sign/verify
 * are inherently one-shot; the streaming update/final variants buffer the message
 * and defer to the one-shot in final. The streaming-buffer mechanics are shared
 * with hybrid_sig.c's item-14 wiring via HYBRID_MSG_ACCUM (issue #121).
 */

static int composite_sig_sign_message_init(void *vctx, void *vkey,
                                           const OSSL_PARAM params[])
{
    COMPOSITE_SIGCTX *c = vctx;

    hybrid_msg_accum_reset(&c->stream);
    return composite_sig_sign_init(vctx, NULL, vkey, params);
}

static int composite_sig_verify_message_init(void *vctx, void *vkey,
                                             const OSSL_PARAM params[])
{
    COMPOSITE_SIGCTX *c = vctx;

    hybrid_msg_accum_reset(&c->stream);
    return composite_sig_verify_init(vctx, NULL, vkey, params);
}

/* Accumulate a message fragment for the streaming message-signature path. */
static int composite_sig_signverify_message_update(void *vctx,
                                                    const unsigned char *data,
                                                    size_t datalen)
{
    COMPOSITE_SIGCTX *c = vctx;

    return hybrid_msg_accum_append(&c->stream, data, datalen);
}

/* Finish a streaming sign: one-shot over the accumulated message. */
static int composite_sig_sign_message_final(void *vctx, unsigned char *sig,
                                            size_t *siglen, size_t sigsize)
{
    COMPOSITE_SIGCTX *c = vctx;

    return composite_sig_digest_sign(vctx, sig, siglen, sigsize,
                                     c->stream.msg, c->stream.msglen);
}

/*
 * Finish a streaming verify: one-shot over the accumulated message against the
 * signature previously delivered via OSSL_SIGNATURE_PARAM_SIGNATURE.
 */
static int composite_sig_verify_message_final(void *vctx)
{
    COMPOSITE_SIGCTX *c = vctx;

    if (c->stream.sigbuf == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "no signature set for the streaming verify (expected the "
                       "OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param)");
        return 0;
    }
    return composite_sig_digest_verify(vctx, c->stream.sigbuf, c->stream.sigbuflen,
                                       c->stream.msg, c->stream.msglen);
}

#endif /* COMPOSITE_HAVE_MSG_SIG */

static int composite_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return composite_sig_apply_params(vctx, params);
}

static const OSSL_PARAM *composite_sig_settable_ctx_params(void *vctx,
                                                           void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
#endif
#ifdef COMPOSITE_HAVE_MSG_SIG
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
#endif
        OSSL_PARAM_END
    };
    return params;
}

/* Provide the X.509 AlgorithmIdentifier (DER SEQUENCE { composite OID }, absent
 * parameters) so X509_sign()/verify and TLS CertificateVerify can label the
 * signature — mirrors the hybrid family. */
static int composite_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    COMPOSITE_SIGCTX *c = vctx;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);

    if (p != NULL) {
        const COMPOSITE_SIG_INFO *info;
        X509_ALGOR *alg = NULL;
        ASN1_OBJECT *oid = NULL;
        unsigned char *der = NULL;
        int derlen, ok = 0;

        if (c == NULL || c->key == NULL)
            return 0;
        info = c->key->info;
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

static const OSSL_PARAM *composite_sig_gettable_ctx_params(void *vctx,
                                                           void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

const OSSL_DISPATCH composite_sig_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))composite_sig_dupctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,
      (void (*)(void))composite_sig_raw_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))composite_sig_raw_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))composite_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))composite_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))composite_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))composite_sig_digest_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))composite_sig_digest_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))composite_sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))composite_sig_digest_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))composite_sig_digest_verify_final },
#ifdef COMPOSITE_HAVE_MSG_SIG
    /* Message-signature API (issue #109): one-shot + streaming. */
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
      (void (*)(void))composite_sig_sign_message_init },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
      (void (*)(void))composite_sig_signverify_message_update },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
      (void (*)(void))composite_sig_sign_message_final },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
      (void (*)(void))composite_sig_verify_message_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
      (void (*)(void))composite_sig_signverify_message_update },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
      (void (*)(void))composite_sig_verify_message_final },
#endif
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
      (void (*)(void))composite_sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))composite_sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
      (void (*)(void))composite_sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))composite_sig_gettable_ctx_params },
    { 0, NULL }
};
