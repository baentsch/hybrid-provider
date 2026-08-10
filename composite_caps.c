/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * TLS 1.3 signature-algorithm capabilities for the composite (LAMPS) signatures,
 * so a composite key can authenticate a TLS 1.3 handshake (CertificateVerify).
 *
 * Like hybrid_caps.c, both the constants table and the per-algorithm OSSL_PARAM
 * arrays are generated from the single master list (COMPOSITE_SIG_LIST): the code
 * point and security level come from that list's `tls_codepoint` / `security_bits`
 * columns, so there is no separate lookup to keep in sync. Rows whose code point
 * is 0 (the experimental tier, and any combo the TLS draft does not enumerate)
 * are skipped at advertisement time.
 *
 * draft-reddy-tls-composite-mldsa (an early *individual* draft, not WG-adopted)
 * enumerates which combos get a TLS sigalg, but we deliberately do NOT reuse its
 * code points: they sit in IANA-managed SignatureScheme space and a real
 * allocation can overrun a provisional value. OpenSSL 4.1 added native SLH-DSA at
 * 0x0911-0x091C, colliding with draft-reddy's 0x0912 for mldsa87_ed448 and
 * silently shadowing our advertisement in libssl's dedup (issue #38). Instead we
 * assign private-use code points (RFC 8446 SignatureScheme 0xFE00-0xFFFF) like the
 * hybrid families, which can never collide with an IANA allocation. They are still
 * provisional and only interoperate between peers that agree out of band (e.g. two
 * instances of this provider). See design.md (Composite signatures).
 *
 * As a guard against regressing into managed space, advertisement below refuses
 * any code point outside the private-use range.
 */
#include "composite_prov.h"
#include <openssl/core_names.h>
#include <openssl/prov_ssl.h>   /* TLS1_3_VERSION */
#include <string.h>

typedef struct {
    unsigned int code_point;
    unsigned int secbits;
    int mintls;
    int maxtls;
} COMPOSITE_TLS_SIGALG_CONSTANTS;

/* Per-algorithm constants, generated in master-list order from the list's
 * tls_codepoint / security_bits columns. */
#define COMPOSITE_CAPS_CONST_ROW(cf, nm, pq, tr, grp, bits, oid, lbl, ph, tmd,  \
                                 seed, tier, cp, sb)                            \
    { (unsigned int)(cp), (unsigned int)(sb), TLS1_3_VERSION, 0 },
static const COMPOSITE_TLS_SIGALG_CONSTANTS composite_sigalg_list[] = {
    COMPOSITE_SIG_LIST(COMPOSITE_CAPS_CONST_ROW)
};
#undef COMPOSITE_CAPS_CONST_ROW

/* One OSSL_PARAM array per signature. NAME is the algorithm the TLS layer fetches
 * to build the signature context; OID matches the SPKI/PKCS8 encoders. The row
 * index (COMPOSITE_SIG_IDX_*) keeps this aligned with the constants table. */
#define COMPOSITE_TLS_SIGALG_ENTRY(signame, sigoid, idx)                       \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,           \
            signame, sizeof(signame)),                                         \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,                \
            signame, sizeof(signame)),                                         \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID,                 \
            sigoid, sizeof(sigoid)),                                           \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,                 \
            (unsigned int *)&composite_sigalg_list[idx].code_point),          \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,             \
            (unsigned int *)&composite_sigalg_list[idx].secbits),             \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                     \
            (int *)&composite_sigalg_list[idx].mintls),                        \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                     \
            (int *)&composite_sigalg_list[idx].maxtls),                        \
        OSSL_PARAM_END                                                         \
    }

/* `oid` is a string literal (or NULL for the experimental row); passing it
 * directly keeps sizeof() a compile-time length as in hybrid_caps.c. The
 * experimental row carries code point 0 and is skipped at advertisement time, so
 * its NULL oid entry is never handed to the callback. */
#define COMPOSITE_CAPS_PARAM_ROW(cf, nm, pq, tr, grp, bits, oid, lbl, ph, tmd,  \
                                 seed, tier, cp, sb)                            \
    COMPOSITE_TLS_SIGALG_ENTRY(nm, oid, COMPOSITE_SIG_IDX_##cf),
static const OSSL_PARAM composite_param_sigalg_list[][8] = {
    COMPOSITE_SIG_LIST(COMPOSITE_CAPS_PARAM_ROW)
};
#undef COMPOSITE_CAPS_PARAM_ROW

int composite_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    if (capability == NULL
            || OPENSSL_strcasecmp(capability, "TLS-SIGALG") != 0)
        return 0;

    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        if (composite_sigalg_list[i].code_point == 0)
            continue;   /* no (provisional) TLS code point -> not advertised */
        /* Advertise only private-use code points (RFC 8446 SignatureScheme
         * 0xFE00-0xFFFF). A provisional value in IANA-managed space can be
         * silently shadowed by a later native sigalg (SLH-DSA took 0x0911-0x091C
         * in OpenSSL 4.1, overrunning draft-reddy's 0x0912; issue #38), so any
         * code point outside the private-use range is refused here. */
        if (composite_sigalg_list[i].code_point < 0xFE00)
            continue;
        /* Withdrawn because the default provider serves it (cede-to-default,
         * e.g. once OpenSSL ships native composite signatures). */
        if (hybrid_is_ceded(composite_sig_table[i].name))
            continue;
        if (!cb(composite_param_sigalg_list[i], arg))
            return 0;
    }
    return 1;
}
