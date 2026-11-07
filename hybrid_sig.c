/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hybrid signature dispatch — one-shot DigestSign/DigestVerify combining two
 * component signatures over the same message, matching oqsprovider's hybrid-sig
 * wire format:
 *
 *   sig = ENCODE_UINT32(comp1_len) || comp1_sig || comp2_sig
 *
 * The path is slot-SYMMETRIC: each component is handled by its own kind, resolved
 * from the alg name (hybrid_sig_is_digest_taking), so EITHER slot may hold a
 * classical or a PQ algorithm (classical×PQ, and the PQ/PQ §3.4 rows):
 *   - digest-taking (classical ECDSA/RSA): the provider pre-hashes with a digest
 *     chosen by the hybrid's NIST level (1 -> SHA-256, 2/3 -> SHA-384, 4/5 ->
 *     SHA-512) and signs it via EVP_PKEY_sign (ECDSA DER, or RSA PKCS#1 v1.5);
 *   - md-less (every PQ signature and EdDSA): signs the raw message via
 *     EVP_DigestSign with a NULL digest.
 * Verify requires BOTH components to pass.
 */

#include "hybrid_prov.h"
#include "hybrid_msg_accum.h"
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/proverr.h>

/*
 * OSSL_SIGNATURE_PARAM_CONTEXT_STRING ("context-string") was added to
 * core_names.h in OpenSSL 3.2. On 3.0/3.1 the provider builds KEM-only and no
 * hybrid signature is operable (they need a 3.2+ component provider), so the
 * per-op context-string plumbing is compiled out where the param name is absent
 * — guarding on presence of the specific define rather than assuming the name.
 */
#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
# define HYBRID_HAVE_CTX_STR 1
#endif

/*
 * The message-signature API (sign_message_init/update/final, verify_message_*,
 * and the OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param) landed in OpenSSL 3.4 — the
 * dispatch numbers below are absent on 3.0–3.3. Guard on presence of the
 * specific dispatch define rather than a version test, so the block compiles out
 * cleanly where the API does not exist (KEM-only 3.0/3.1, or 3.2/3.3). Presence
 * of SIGN_MESSAGE_INIT (3.4) implies OSSL_SIGNATURE_PARAM_SIGNATURE (also 3.4),
 * and hence HYBRID_HAVE_CTX_STR, whose OSSL_SIGNATURE_PARAM_CONTEXT_STRING is
 * older still (3.2, see above) — so the nested guard below is always satisfiable.
 */
#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
# define HYBRID_HAVE_MSG_SIG 1
#endif

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
     * Optional per-operation signature context string (issue #46). Applied to
     * every md-less component (ML-DSA and the other PQ signatures take a context
     * string; for a PQ/PQ pair, both halves) and never to a digest-taking
     * classical component (ECDSA/RSA over a digest have no such concept). A
     * component that does not itself honour one ignores the param — best-effort,
     * no hard failure. Owned here; freed in freectx, deep-copied in dupctx.
     */
    unsigned char *ctxstr;
    size_t ctxstrlen;
    /*
     * Streaming message-signature buffers (item 14), driven by the CMS content-
     * signing path (`cms -sign -noattr`). Mechanics shared with composite_sig.c
     * via HYBRID_MSG_ACCUM (issue #121); the hybrid combiner runs one-shot over
     * the accumulated message in final(). Freed in freectx, deep-copied in dupctx.
     */
    HYBRID_MSG_ACCUM stream;
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
        hybrid_msg_accum_reset(&ctx->stream);
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
    /* Deep-copy the owned buffers so each ctx frees its own copy. Drop the
     * aliases first so a partial-copy error path frees only what it allocated. */
    ret->ctxstr = NULL;
    hybrid_msg_accum_init(&ret->stream);
    if (ctx->ctxstr != NULL
            && (ret->ctxstr = OPENSSL_memdup(ctx->ctxstr, ctx->ctxstrlen)) == NULL)
        goto err;
    if (!hybrid_msg_accum_dup(&ret->stream, &ctx->stream))
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
    if (params == NULL)
        return 1;
#ifdef HYBRID_HAVE_CTX_STR
    const OSSL_PARAM *p =
        OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);

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
# ifdef HYBRID_HAVE_MSG_SIG
    /* The signature to check for the streaming verify-message path (item 14):
     * verify_message_final() takes only the ctx, so libcrypto delivers it here as
     * an octet string before calling it (shared mechanics, issue #121). */
    if (!hybrid_msg_accum_set_sig_param(&ctx->stream, params))
        return 0;
# endif
#else
    (void)ctx;
#endif
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
 * Raw (non-digest) signature init. EVP_PKEY_sign_init()/EVP_PKEY_verify_init()
 * dispatch here; without these entries the raw one-shot SIGN/VERIFY below are
 * unreachable via the public EVP API. The digest is chosen internally by NIST
 * level, so there is no mdname to honour — defer to the digest-init helpers,
 * exactly as the message-signature init wrappers do.
 */
static int
hybrid_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return hybrid_sig_digest_sign_init(vctx, NULL, vkey, params);
}

static int
hybrid_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    return hybrid_sig_digest_verify_init(vctx, NULL, vkey, params);
}

/*
 * Digest a digest-taking (classical ECDSA/RSA) component signs, chosen by the
 * hybrid's NIST level. Uses the static (non-fetched) EVP_MD accessors — matching
 * oqsprovider and avoiding an EVP_MD_fetch per operation. Only ever consulted for
 * a digest-taking component; for a PQ/PQ pair (no such component) it is unused.
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
 * A resolved view of one hybrid signature component, by component index
 * (HYBRID_COMP_ALG1 = wire-first, HYBRID_COMP_ALG2 = the tail). The sign/verify
 * path is slot-SYMMETRIC: each component is handled by its own kind (digest-taking
 * vs md-less), never by assuming "component 0 is classical". Either component may
 * hold a classical (ECDSA/RSA) or a PQ (ML-DSA/Falcon/…) algorithm. Resolved from
 * the key by hybrid_sig_component.
 */
typedef struct {
    EVP_PKEY   *pkey;          /* the component key, HYBRID_KEY_COMP(key, i) */
    const char *propq;         /* per-component property query */
    size_t      max_sig;       /* signing output bound: hybrid_key_comp_sig_bytes */
    int         digest_taking; /* 1 = ECDSA/RSA over an external digest; 0 = md-less */
    int         is_rsa;        /* digest-taking RSA -> PKCS#1 v1.5 padding */
} HYBRID_SIG_COMP;

/*
 * A signature component is "digest-taking" iff it is classical ECDSA or RSA: the
 * caller pre-hashes and the component signs the digest. Every other family — all
 * PQ signatures (ML-DSA, Falcon, MAYO, …) and EdDSA — is md-less: it signs the
 * message directly (md == NULL). The digest-taking set is frozen and tiny, so it
 * is listed explicitly rather than probed (a prober would be the same two names
 * behind more code). Keyed on the component's alg name, so it is correct in
 * EITHER slot.
 */
static int hybrid_sig_is_digest_taking(const char *alg_name)
{
    return strcmp(alg_name, "EC") == 0 || strcmp(alg_name, "RSA") == 0;
}

/* Resolve component `i` (HYBRID_COMP_ALG1/ALG2) of `key` into *c, through the
 * component-indexed accessors (issue #135). The per-component property query
 * (hybrid_key_comp_propq) and the type-named accessors are a provider-steering
 * concern shared with the KEM family and are orthogonal to which component kind
 * sits in the slot. */
static void hybrid_sig_component(const HYBRID_KEY *key, unsigned i,
                                 HYBRID_SIG_COMP *c)
{
    const char *alg = hybrid_key_comp_name(key, i);

    c->digest_taking = hybrid_sig_is_digest_taking(alg);
    c->is_rsa = (strcmp(alg, "RSA") == 0);
    c->pkey = HYBRID_KEY_COMP(key, i);
    c->propq = hybrid_key_comp_propq(key, i);
    c->max_sig = hybrid_key_comp_sig_bytes(key, i);
}

/*
 * Digest-taking sign/verify over a pre-computed digest via EVP_PKEY_sign/verify
 * (ECDSA DER, or RSA PKCS#1 v1.5). For signing, sig/siglen receive the signature
 * (bounded by c->max_sig); for verify, sig/siglen are the input. Returns 1 on
 * success.
 */
static int hybrid_sig_digest_taking_op(const HYBRID_KEY *key,
                        const HYBRID_SIG_COMP *c, int sign, const EVP_MD *md,
                        const unsigned char *tbs, size_t tbslen,
                        unsigned char *sig, size_t *siglen)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char dig[EVP_MAX_MD_SIZE];
    unsigned int diglen = sizeof(dig);
    int ret = 0;

    if (!EVP_Digest(tbs, tbslen, dig, &diglen, md, NULL))
        return 0;

    pctx = EVP_PKEY_CTX_new_from_pkey(key->libctx, c->pkey, c->propq);
    if (pctx == NULL)
        goto end;
    if ((sign ? EVP_PKEY_sign_init(pctx) : EVP_PKEY_verify_init(pctx)) <= 0)
        goto end;
    if (c->is_rsa && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) <= 0)
        goto end;
    if (EVP_PKEY_CTX_set_signature_md(pctx, md) <= 0)
        goto end;

    if (sign) {
        *siglen = c->max_sig;
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
 * Build the OSSL_PARAM array handed to an md-less component's DigestSign/Verify
 * init (issue #46). Returns the array (into the caller-provided storage) when a
 * context string is set, or NULL when none is — so the component runs with its
 * default (empty) context, preserving the oqsprovider-compatible wire format.
 *
 * The rule, generalized for either-slot / PQ-PQ hybrids (issue #114): the context
 * string is applied to EVERY md-less component (ML-DSA, and for a PQ/PQ pair both
 * halves) and never to a digest-taking classical component (ECDSA/RSA have no
 * such concept). A component that does not itself honour a context string simply
 * ignores the param — best-effort, no hard failure — so a pair whose components
 * do not all support one cannot enforce domain separation across both halves.
 */
static OSSL_PARAM *pq_ctx_params(HYBRID_SIG_CTX *ctx, OSSL_PARAM store[2])
{
    if (ctx->ctxstr == NULL)
        return NULL;
#ifdef HYBRID_HAVE_CTX_STR
    store[0] = OSSL_PARAM_construct_octet_string(
                   OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                   ctx->ctxstr, ctx->ctxstrlen);
    store[1] = OSSL_PARAM_construct_end();
    return store;
#else
    (void)store;                 /* ctxstr is never set without the param name */
    return NULL;
#endif
}

/*
 * Md-less sign/verify over the raw message via EVP_DigestSign/Verify with a NULL
 * digest (ML-DSA and every other PQ/EdDSA family). The context string (if any) is
 * applied here, to this component. For signing, sig/siglen receive the signature
 * (bounded by c->max_sig); for verify, sig/siglen are the input. Returns 1.
 */
static int hybrid_sig_mdless_op(HYBRID_SIG_CTX *ctx, const HYBRID_KEY *key,
                        const HYBRID_SIG_COMP *c, int sign,
                        const unsigned char *tbs, size_t tbslen,
                        unsigned char *sig, size_t *siglen)
{
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    OSSL_PARAM pqp_store[2], *pqp = pq_ctx_params(ctx, pqp_store);
    int ret = 0;

    if (mctx == NULL)
        goto end;
    if (sign) {
        if (EVP_DigestSignInit_ex(mctx, NULL, NULL, key->libctx, c->propq,
                                  c->pkey, pqp) <= 0)
            goto end;
        *siglen = c->max_sig;
        if (EVP_DigestSign(mctx, sig, siglen, tbs, tbslen) <= 0)
            goto end;
    } else {
        if (EVP_DigestVerifyInit_ex(mctx, NULL, NULL, key->libctx, c->propq,
                                    c->pkey, pqp) <= 0)
            goto end;
        if (EVP_DigestVerify(mctx, sig, *siglen, tbs, tbslen) <= 0)
            goto end;
    }
    ret = 1;
end:
    EVP_MD_CTX_free(mctx);
    return ret;
}

/*
 * Sign/verify one resolved component into/from the wire buffer, dispatching on
 * its kind. slen is in/out: for signing it receives the produced length; for
 * verify it is the input length to check. Slot-symmetric — identical for slot 0
 * and slot 1.
 */
static int hybrid_sig_component_op(HYBRID_SIG_CTX *ctx, const HYBRID_KEY *key,
                        const HYBRID_SIG_COMP *c, int sign,
                        const unsigned char *tbs, size_t tbslen,
                        unsigned char *sig, size_t *slen)
{
    const HYBRID_SIG_INFO *info = (const HYBRID_SIG_INFO *)key->info;

    if (c->digest_taking)
        return hybrid_sig_digest_taking_op(key, c, sign,
                                           classical_md(info->nist_level),
                                           tbs, tbslen, sig, slen);
    return hybrid_sig_mdless_op(ctx, key, c, sign, tbs, tbslen, sig, slen);
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
    HYBRID_SIG_COMP c0, c1;
    size_t len0 = 0, len1 = 0, maxsig;

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

    /* The hybrid signature wire format carries a single length prefix and exactly
     * two component signatures (comp0 || comp1); it is intrinsically 2-component
     * (no multi-component signature is specified — issue #135), so unlike the
     * concat-KEM path this does not loop over N. The components are the logical
     * slots HYBRID_COMP_ALG1/ALG2 (sig keys concatenate ALG1 first). */
    assert(HYBRID_KEY_NCOMP(key) == 2);

    hybrid_sig_component(key, HYBRID_COMP_ALG1, &c0);
    hybrid_sig_component(key, HYBRID_COMP_ALG2, &c1);

    /* component 0 signature, written after the 4-byte length prefix */
    if (!hybrid_sig_component_op(ctx, key, &c0, 1, tbs, tbslen,
                                 sig + sizeof(uint32_t), &len0)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid component 1 signing failed");
        return 0;
    }
    sig[0] = (unsigned char)(len0 >> 24);
    sig[1] = (unsigned char)(len0 >> 16);
    sig[2] = (unsigned char)(len0 >> 8);
    sig[3] = (unsigned char)(len0);

    /* component 1 signature over the same message, appended as the tail */
    if (!hybrid_sig_component_op(ctx, key, &c1, 1, tbs, tbslen,
                                 sig + sizeof(uint32_t) + len0, &len1)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid component 2 signing failed");
        return 0;
    }

    *siglen = sizeof(uint32_t) + len0 + len1;
    return 1;
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
    HYBRID_SIG_COMP c0, c1;
    size_t len0, len1;

    if (!hybrid_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
                       "hybrid verification requires a public key");
        return 0;
    }
    /* Bounds guards: the signature must hold the 4-byte component-1 length prefix
     * before we read sig[0..3], and that length must fit within siglen before we
     * split off the two component signatures (else a malformed signature would
     * cause an out-of-bounds read). */
    if (siglen < sizeof(uint32_t)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                       "hybrid signature %zu too short for the length prefix",
                       siglen);
        return 0;
    }
    len0 = ((size_t)sig[0] << 24) | ((size_t)sig[1] << 16)
         | ((size_t)sig[2] << 8) | (size_t)sig[3];
    if (sizeof(uint32_t) + len0 > siglen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
                       "hybrid component 1 length %zu inconsistent with "
                       "signature length %zu", len0, siglen);
        return 0;
    }
    len1 = siglen - sizeof(uint32_t) - len0;

    assert(HYBRID_KEY_NCOMP(key) == 2);   /* 2-component wire format, see sign */

    hybrid_sig_component(key, HYBRID_COMP_ALG1, &c0);
    hybrid_sig_component(key, HYBRID_COMP_ALG2, &c1);

    /* verify component 0 (after the length prefix) */
    if (!hybrid_sig_component_op(ctx, key, &c0, 0, tbs, tbslen,
                                 (unsigned char *)sig + sizeof(uint32_t),
                                 &len0)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid component 1 verification failed");
        return 0;
    }
    /* verify component 1 (the tail); context string, if any, applied to every
     * md-less component on both the sign and verify sides */
    if (!hybrid_sig_component_op(ctx, key, &c1, 0, tbs, tbslen,
                                 (unsigned char *)sig + sizeof(uint32_t) + len0,
                                 &len1)) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_EVP_LIB,
                       "hybrid component 2 verification failed");
        return 0;
    }

    return 1;
}

#ifdef HYBRID_HAVE_MSG_SIG
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

    hybrid_msg_accum_reset(&ctx->stream);
    return hybrid_sig_digest_sign_init(vctx, NULL, vkey, params);
}

static int
hybrid_sig_verify_message_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_SIG_CTX *ctx = vctx;

    hybrid_msg_accum_reset(&ctx->stream);
    return hybrid_sig_digest_verify_init(vctx, NULL, vkey, params);
}

/* Accumulate a message fragment for the streaming message-signature path. */
static int
hybrid_sig_signverify_message_update(void *vctx, const unsigned char *data,
                                     size_t datalen)
{
    HYBRID_SIG_CTX *ctx = vctx;

    return hybrid_msg_accum_append(&ctx->stream, data, datalen);
}

/* Finish a streaming sign: one-shot over the accumulated message. */
static int
hybrid_sig_sign_message_final(void *vctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize)
{
    HYBRID_SIG_CTX *ctx = vctx;

    return hybrid_sig_digest_sign(vctx, sig, siglen, sigsize,
                                  ctx->stream.msg, ctx->stream.msglen);
}

/*
 * Finish a streaming verify: one-shot over the accumulated message against the
 * signature previously delivered via OSSL_SIGNATURE_PARAM_SIGNATURE.
 */
static int
hybrid_sig_verify_message_final(void *vctx)
{
    HYBRID_SIG_CTX *ctx = vctx;

    if (ctx->stream.sigbuf == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "no signature set for the streaming verify (expected the "
                       "OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param)");
        return 0;
    }
    return hybrid_sig_digest_verify(vctx, ctx->stream.sigbuf,
                                    ctx->stream.sigbuflen,
                                    ctx->stream.msg, ctx->stream.msglen);
}
#endif /* HYBRID_HAVE_MSG_SIG */

static const OSSL_PARAM *hybrid_sig_settable_ctx_params(void *vctx,
                                                          void *provctx)
{
    static const OSSL_PARAM params[] = {
#ifdef HYBRID_HAVE_CTX_STR
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
# ifdef HYBRID_HAVE_MSG_SIG
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0),
# endif
#endif
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
    /*
     * Raw one-shot API (EVP_PKEY_sign/verify). sign/verify reuse the digest-sign
     * one-shot, which already signs the raw message; their *_INIT entries make
     * that path reachable via EVP_PKEY_sign_init/verify_init (issue #79).
     */
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,
      (void (*)(void))hybrid_sig_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN,
      (void (*)(void))hybrid_sig_digest_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,
      (void (*)(void))hybrid_sig_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY,
      (void (*)(void))hybrid_sig_digest_verify },
#ifdef HYBRID_HAVE_MSG_SIG
    /* Message-signature API (item 14): one-shot + streaming. sign/verify reuse
     * the digest-sign one-shot, which already signs the raw message. */
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT,
      (void (*)(void))hybrid_sig_sign_message_init },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE,
      (void (*)(void))hybrid_sig_signverify_message_update },
    { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL,
      (void (*)(void))hybrid_sig_sign_message_final },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
      (void (*)(void))hybrid_sig_verify_message_init },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE,
      (void (*)(void))hybrid_sig_signverify_message_update },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL,
      (void (*)(void))hybrid_sig_verify_message_final },
#endif
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
