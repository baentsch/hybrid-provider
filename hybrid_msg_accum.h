/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared streaming message-signature buffer (issue #121).
 *
 * Both signature families — the concat hybrids (hybrid_sig.c) and the
 * LAMPS composites (composite_sig.c, issue #109) — are inherently one-shot, yet
 * OpenSSL's CMS content-signing path (`openssl cms -sign -noattr`) drives the
 * streaming message-signature API (sign_message_init + update* + final) rather
 * than digest-sign. Both satisfy it the same way: accumulate the update() bytes
 * and run the one-shot over the whole buffer in final(); for the verify path the
 * signature to check is delivered out-of-band via the
 * OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param before verify_message_final().
 *
 * The two families deliberately keep separate ctx types and dispatch tables
 * (their serialization and combiner differ), but the buffer mechanics — the
 * realloc/overflow-guarded accumulator, the ownership/reset rules, and the
 * signature ctx-param plumbing — are identical. This header is the single source
 * of truth for them: both ctxs embed a HYBRID_MSG_ACCUM and drive it through
 * these helpers. The families' own digest_sign/digest_verify plumbing stays put.
 *
 * Header-only (static inline) on purpose: composite_sig.c is also compiled
 * standalone into composite_sig_test, so a separate translation unit would mean
 * a CMake/link change there; inline functions avoid it (and unused ones do not
 * warn). The struct and the free/reset/append/dup mechanics use only 3.0 EVP, so
 * they are always available; only the OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param
 * handling (3.4+) is guarded on that symbol, matching the callers' msg-sig guard.
 */
#ifndef HYBRID_MSG_ACCUM_H
#define HYBRID_MSG_ACCUM_H

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <string.h>
#include <stdint.h>

typedef struct hybrid_msg_accum_st {
    /* Message accumulated across streaming update() calls, signed/verified as a
     * whole in final(). Owned here. */
    unsigned char *msg;
    size_t msglen;
    /* Signature to check for the streaming verify path, delivered via the
     * OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param (verify_message_final() takes only
     * the ctx). Owned here. */
    unsigned char *sigbuf;
    size_t sigbuflen;
} HYBRID_MSG_ACCUM;

/* Clear the pointers/lengths WITHOUT freeing — for a ctx just bit-copied from
 * another (dupctx), whose buffers still alias the source. Drops the aliases so a
 * later error path frees only real copies. */
static inline void hybrid_msg_accum_init(HYBRID_MSG_ACCUM *a)
{
    a->msg = NULL;
    a->msglen = 0;
    a->sigbuf = NULL;
    a->sigbuflen = 0;
}

/* Free + zero both buffers so a reused (or dup'd) ctx starts each operation
 * clean. Safe on an all-NULL accum. */
static inline void hybrid_msg_accum_reset(HYBRID_MSG_ACCUM *a)
{
    OPENSSL_free(a->msg);
    OPENSSL_free(a->sigbuf);
    hybrid_msg_accum_init(a);
}

/* Append a message fragment. Returns 1 on success, 0 (with an error raised) on
 * failure. */
static inline int hybrid_msg_accum_append(HYBRID_MSG_ACCUM *a,
                                          const unsigned char *data,
                                          size_t datalen)
{
    unsigned char *grown;

    if (datalen == 0)
        return 1;
    /* Guard the running total against size_t wrap before it sizes the realloc:
     * a wrapped (small) allocation would be overflowed by the memcpy below. */
    if (datalen > SIZE_MAX - a->msglen) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "streamed message length overflow");
        return 0;
    }
    if ((grown = OPENSSL_realloc(a->msg, a->msglen + datalen)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    a->msg = grown;
    memcpy(a->msg + a->msglen, data, datalen);
    a->msglen += datalen;
    return 1;
}

/* Deep-copy src's buffers into dst so each ctx frees its own copy. dst's pointers
 * are owned on return; on failure dst is left clean (freed + zeroed). Returns 1
 * on success, 0 (with an error raised) on failure. */
static inline int hybrid_msg_accum_dup(HYBRID_MSG_ACCUM *dst,
                                       const HYBRID_MSG_ACCUM *src)
{
    dst->msg = NULL;
    dst->msglen = src->msglen;
    dst->sigbuf = NULL;
    dst->sigbuflen = src->sigbuflen;
    if (src->msg != NULL
            && (dst->msg = OPENSSL_memdup(src->msg, src->msglen)) == NULL)
        goto err;
    if (src->sigbuf != NULL
            && (dst->sigbuf = OPENSSL_memdup(src->sigbuf, src->sigbuflen)) == NULL)
        goto err;
    return 1;
err:
    hybrid_msg_accum_reset(dst);
    return 0;
}

#ifdef OSSL_SIGNATURE_PARAM_SIGNATURE
/* Receive the signature to check for the streaming verify-message path from the
 * OSSL_SIGNATURE_PARAM_SIGNATURE ctx-param, if present (absent is not an error).
 * params must be non-NULL. Returns 1 on success, 0 (with an error raised). */
static inline int hybrid_msg_accum_set_sig_param(HYBRID_MSG_ACCUM *a,
                                                  const OSSL_PARAM params[])
{
    const OSSL_PARAM *p =
        OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_SIGNATURE);
    void *buf = NULL;
    size_t len = 0;

    if (p == NULL)
        return 1;
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
    OPENSSL_free(a->sigbuf);
    a->sigbuf = buf;
    a->sigbuflen = len;
    return 1;
}
#endif /* OSSL_SIGNATURE_PARAM_SIGNATURE */

#endif /* HYBRID_MSG_ACCUM_H */
