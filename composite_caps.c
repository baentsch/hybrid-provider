/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLS 1.3 signature-algorithm capabilities for the composite (LAMPS) signatures,
 * so a composite key can authenticate a TLS 1.3 handshake (CertificateVerify).
 *
 * Code points are from draft-reddy-tls-composite-mldsa (an early *individual*
 * draft, not WG-adopted); the values are still **TBD in IANA**, so they are
 * provisional and only guaranteed to interoperate between peers that agree on
 * them out of band (e.g. two instances of this provider). This is wired for the
 * self-driven TLS scenario test; cross-implementation TLS composite interop is
 * not yet meaningful (no draft-aligned peer — see redesign.md Phase-2).
 *
 * The IANA-name/fetch-name is our registered algorithm name; a fully spec-faithful
 * cross-impl deployment would additionally map to the draft-reddy TLS names.
 */
#include "composite_prov.h"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/prov_ssl.h>   /* TLS1_3_VERSION */
#include <string.h>

/* draft-reddy-tls-composite-mldsa SignatureScheme code points, keyed by the
 * master-list index. 0 = no TLS code point (skipped): the experimental row, and
 * any standardized combo the TLS draft does not (yet) enumerate. */
static const unsigned int composite_tls_codepoint[COMPOSITE_SIG_ALG_COUNT] = {
    [COMPOSITE_SIG_IDX_mldsa44_ecdsa_p256]  = 0x0907,
    [COMPOSITE_SIG_IDX_mldsa87_ecdsa_p384]  = 0x0909,
    [COMPOSITE_SIG_IDX_mldsa65_ed25519]     = 0x090B,
    [COMPOSITE_SIG_IDX_mldsa65_rsa3072_pss] = 0x0910,
    [COMPOSITE_SIG_IDX_mldsa87_ed448]       = 0x0912,
};

/* Composite security is bounded by the ML-DSA level (44->128, 65->192, 87->256). */
static unsigned int secbits_for(const char *pq_alg)
{
    if (strstr(pq_alg, "87") != NULL)
        return 256;
    if (strstr(pq_alg, "65") != NULL)
        return 192;
    return 128;
}

int composite_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    if (capability == NULL
            || OPENSSL_strcasecmp(capability, "TLS-SIGALG") != 0)
        return 0;

    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const COMPOSITE_SIG_INFO *in = &composite_sig_table[i];
        unsigned int cp = composite_tls_codepoint[i];
        unsigned int sb;
        int mintls = TLS1_3_VERSION, maxtls = 0;
        OSSL_PARAM p[8];
        int n = 0;

        if (cp == 0 || in->oid == NULL)
            continue;
        sb = secbits_for(in->pq_alg);
        /* cb is synchronous, so stack-lifetime params + locals are fine. */
        p[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, (char *)in->name, 0);
        p[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_NAME, (char *)in->name, 0);
        p[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_SIGALG_OID, (char *)in->oid, 0);
        p[n++] = OSSL_PARAM_construct_uint(
            OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, &cp);
        p[n++] = OSSL_PARAM_construct_uint(
            OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, &sb);
        p[n++] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, &mintls);
        p[n++] = OSSL_PARAM_construct_int(
            OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, &maxtls);
        p[n] = OSSL_PARAM_construct_end();

        if (!cb(p, arg))
            return 0;
    }
    return 1;
}
