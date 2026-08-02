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
 *  - The concat split assumes a FIXED-length PQ signature (ML-DSA, MAYO). A
 *    variable-length PQ sig (e.g. Falcon) in the experimental tier would need a
 *    length prefix — a follow-up for that tier.
 */
#include "composite_prov.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include <string.h>
#include <stdint.h>

/* PH(M): PREFIX || label || 0x00 (empty ctx) || digest(prehash, M). */
static int build_mprime(const COMPOSITE_SIG_INFO *info, OSSL_LIB_CTX *libctx,
                        const unsigned char *msg, size_t msglen,
                        unsigned char **out, size_t *outlen)
{
    static const char prefix[] = COMPOSITE_SIG_PREFIX; /* no trailing NUL used */
    EVP_MD *md = EVP_MD_fetch(libctx, info->prehash, NULL);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    unsigned char ph[EVP_MAX_MD_SIZE];
    size_t plen = sizeof(prefix) - 1, llen = strlen(info->label), phlen = 0;
    unsigned char *buf = NULL;
    int ret = 0;

    if (md == NULL || mc == NULL
            || EVP_DigestInit_ex2(mc, md, NULL) <= 0
            || EVP_DigestUpdate(mc, msg, msglen) <= 0)
        goto end;
    if ((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
        phlen = 64;                       /* draft's fixed XOF output (SHAKE256) */
        if (EVP_DigestFinalXOF(mc, ph, phlen) <= 0)
            goto end;
    } else {
        unsigned int l = 0;
        if (EVP_DigestFinal_ex(mc, ph, &l) <= 0)
            goto end;
        phlen = l;
    }

    *outlen = plen + llen + 1 + phlen;
    if ((buf = OPENSSL_malloc(*outlen)) == NULL)
        goto end;
    memcpy(buf, prefix, plen);
    memcpy(buf + plen, info->label, llen);
    buf[plen + llen] = 0x00;              /* len(ctx) = 0, ctx absent */
    memcpy(buf + plen + llen + 1, ph, phlen);
    *out = buf;
    ret = 1;
end:
    EVP_MD_CTX_free(mc);
    EVP_MD_free(md);
    return ret;
}

/* ML-DSA component: one-shot over M' with context string = label. */
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
    if (sign) {
        if (EVP_DigestSignInit_ex(m, NULL, NULL, libctx, propq, pq, sp) <= 0
                || EVP_DigestSign(m, NULL, &l, mp, mplen) <= 0
                || (s = OPENSSL_malloc(l)) == NULL
                || EVP_DigestSign(m, s, &l, mp, mplen) <= 0)
            goto end;
        *osig = s; *olen = l; s = NULL;
    } else {
        if (EVP_DigestVerifyInit_ex(m, NULL, NULL, libctx, propq, pq, sp) <= 0
                || EVP_DigestVerify(m, isig, ilen, mp, mplen) != 1)
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

int composite_sign(const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                   OSSL_LIB_CTX *libctx, const char *pq_propq,
                   const char *trad_propq, const unsigned char *msg,
                   size_t msglen, unsigned char **sig, size_t *siglen)
{
    unsigned char *mp = NULL, *pqsig = NULL, *tradsig = NULL;
    size_t mplen = 0, pqlen = 0, tradlen = 0;
    int ret = 0;

    if (!build_mprime(info, libctx, msg, msglen, &mp, &mplen)
            || !pq_op(1, info, pq, libctx, pq_propq, mp, mplen,
                      &pqsig, &pqlen, NULL, 0)
            || !trad_op(1, info, trad, libctx, trad_propq, mp, mplen,
                        &tradsig, &tradlen, NULL, 0))
        goto end;

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

int composite_verify(const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                     OSSL_LIB_CTX *libctx, const char *pq_propq,
                     const char *trad_propq, const unsigned char *msg,
                     size_t msglen, const unsigned char *sig, size_t siglen)
{
    unsigned char *mp = NULL;
    size_t mplen = 0;
    int pqfixed = EVP_PKEY_get_size(pq);   /* fixed ML-DSA/MAYO signature length */
    int ret = 0;

    if (pqfixed <= 0 || (size_t)pqfixed >= siglen)
        return 0;                          /* need room for both components */
    if (!build_mprime(info, libctx, msg, msglen, &mp, &mplen))
        goto end;
    if (!pq_op(0, info, pq, libctx, pq_propq, mp, mplen,
               NULL, NULL, sig, (size_t)pqfixed))
        goto end;
    if (!trad_op(0, info, trad, libctx, trad_propq, mp, mplen,
                 NULL, NULL, sig + pqfixed, siglen - (size_t)pqfixed))
        goto end;
    ret = 1;
end:
    OPENSSL_free(mp);
    return ret;
}
