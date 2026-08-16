/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/core_names.h>
#include <openssl/opensslv.h>   /* OPENSSL_VERSION_NUMBER */
#include <openssl/prov_ssl.h>   /* TLS1_3_VERSION */
#include <stdarg.h>
#include <stdio.h>
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
#endif

/*
 * The TLS-SIGALG provider capability params (OSSL_CAPABILITY_TLS_SIGALG_*) were
 * added in OpenSSL 3.2. On 3.0/3.1 the provider builds KEM-only: the hybrid KEMs
 * and their TLS groups still work; hybrid signatures are simply not advertised as
 * TLS SignatureSchemes (and hybrid signatures need a 3.2+ component provider
 * anyway). TLS-GROUP has existed since 3.0.
 */
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
# define HYBRID_HAVE_TLS_SIGALG 1
#endif

/* See hybrid_prov.h: silent unless HYBRID_LOG is set in the environment. */
void hybrid_log(const char *fmt, ...)
{
    va_list ap;

    if (getenv("HYBRID_LOG") == NULL)
        return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/*
 * Operability probe (issue #45): only advertise a hybrid whose BOTH component
 * sub-algorithms can actually be instantiated in the component libctx.
 * Otherwise libssl would offer a group/sigalg that then fails mid-handshake
 * ("no suitable key share" / "no suitable signature algorithm") — e.g. a
 * Frodo/BIKE/HQC group when oqsprovider is not loaded to supply its PQ base.
 *
 * Each component is resolved exactly as key generation resolves it
 * (EVP_PKEY_CTX_new_from_name + keygen_init — the provider-agnostic path, with
 * no EVP_PKEY_Q_keygen name allowlist), using the per-component property
 * queries from the provider context. keygen_init stops short of generating a
 * key, so this is cheap; the EC group / RSA size are only needed at keygen
 * time, so a bare "EC"/"RSA" resolve is a sufficient availability check. The
 * probe pushes "unable to fetch" errors for absent components (the expected
 * negative case), so the callers bracket it with ERR_set_mark/ERR_pop_to_mark.
 */
static int component_operable(OSSL_LIB_CTX *libctx, const char *name,
                              const char *propq)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    int ok = (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0);

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int hybrid_group_operable(HYBRID_PROV_CTX *ctx,
                                 const HYBRID_KEM_INFO *info)
{
    OSSL_LIB_CTX *libctx = HYBRID_COMPONENT_LIBCTX(ctx);
    int ok;

    ERR_set_mark();
    ok = component_operable(libctx, info->alg1_name, ctx->classic_propq)
        && component_operable(libctx, info->alg2_name, ctx->pq_propq);
    ERR_pop_to_mark();
    return ok;
}

#ifdef HYBRID_HAVE_TLS_SIGALG
static int hybrid_sigalg_operable(HYBRID_PROV_CTX *ctx,
                                  const HYBRID_SIG_INFO *info)
{
    OSSL_LIB_CTX *libctx = HYBRID_COMPONENT_LIBCTX(ctx);
    int ok;

    ERR_set_mark();
    ok = component_operable(libctx, info->alg1_name, ctx->classic_propq)
        && component_operable(libctx, info->alg2_name, ctx->pq_propq);
    ERR_pop_to_mark();
    return ok;
}
#endif

/*
 * TLS group capabilities for the hybrid KEMs.
 *
 * Both the constants table and the per-group OSSL_PARAM arrays are generated
 * from the single master list in hybrid_prov.h, so a hybrid KEM automatically
 * becomes a TLS group with its listed code point and security level. Groups
 * whose code point is 0 (e.g. X448MLKEM1024, which has no registered code
 * point) are skipped at advertisement time and remain usable only via the KEM
 * API.
 *
 * The group name and the fetched ALG name are identical to the algorithm names
 * registered in hybrid_prov.c — the canonical MLX names for the standardized
 * hybrids (so hybrid vs. default provider is a config-only choice) and the OQS
 * names for the rest (matching oqsprovider, so the two interoperate on the
 * wire). Code points come from their standards: the MLX groups from IETF
 * draft-ietf-tls-ecdhe-mlkem (also what OpenSSL's default provider registers),
 * the OQS-legacy groups from oqsprovider's `oqs-template/generate.yml`. They are
 * fixed integer constants, so there is nothing to "pull" at build time (a spec
 * document is not machine-readable, and OpenSSL's own group tables live behind
 * internal headers we must not use). Instead, drift is caught at test time:
 * `hybrid_capability_test` compares every code point here against the values the
 * default provider / oqsprovider actually advertise via OSSL_PROVIDER_get_
 * capabilities("TLS-GROUP"). See the provenance note in hybrid_prov.h.
 */

typedef struct {
    unsigned int group_id;
    unsigned int secbits;
    int mintls;
    int maxtls;
    int mindtls;
    int maxdtls;
    int is_kem;
} HYBRID_TLS_GROUP_CONSTANTS;

/*
 * Per-group constants, generated in master-list order. min_tls = TLS1_3_VERSION
 * enables every group for TLS 1.3 — including the BIKE-L1 groups, which
 * oqsprovider disables (enable_tls:false -> min_tls=-1). Per oqsprovider PR #711
 * that disablement is an arbitrary test artifact, not a security decision, so we
 * keep BIKE-L1 enabled here.
 */
#define HYBRID_CAPS_CONST_ROW(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid) \
    { (cp), (sb), TLS1_3_VERSION, 0, -1, -1, 1 },
static const HYBRID_TLS_GROUP_CONSTANTS hybrid_group_list[] = {
    HYBRID_KEM_LIST(HYBRID_CAPS_CONST_ROW)
};
#undef HYBRID_CAPS_CONST_ROW

/*
 * One OSSL_PARAM array per group. NAME and ALG are the algorithm name; the ALG
 * name is what the TLS layer fetches as a KEM. The row index into the constants
 * table is the algorithm's list-order index (HYBRID_KEM_IDX_*), so the two
 * generated tables stay aligned.
 */
#define HYBRID_TLS_GROUP_ENTRY(tlsname, idx)                            \
    {                                                                   \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,          \
            tlsname, sizeof(tlsname)),                                  \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
            "", sizeof("")),                                            \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,           \
            tlsname, sizeof(tlsname)),                                  \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                   \
            (unsigned int *)&hybrid_group_list[idx].group_id),          \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,        \
            (unsigned int *)&hybrid_group_list[idx].secbits),           \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,               \
            (int *)&hybrid_group_list[idx].mintls),                     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,               \
            (int *)&hybrid_group_list[idx].maxtls),                     \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,              \
            (int *)&hybrid_group_list[idx].mindtls),                    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,              \
            (int *)&hybrid_group_list[idx].maxdtls),                    \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                \
            (int *)&hybrid_group_list[idx].is_kem),                     \
        OSSL_PARAM_END                                                  \
    }

#define HYBRID_CAPS_PARAM_ROW(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid) \
    HYBRID_TLS_GROUP_ENTRY(nm, HYBRID_KEM_IDX_##cf),
static const OSSL_PARAM hybrid_param_group_list[][11] = {
    HYBRID_KEM_LIST(HYBRID_CAPS_PARAM_ROW)
};
#undef HYBRID_CAPS_PARAM_ROW

#define HYBRID_TLS_GROUP_COUNT \
    (sizeof(hybrid_param_group_list) / sizeof(hybrid_param_group_list[0]))

/*
 * TLS signature-algorithm capabilities for the hybrid signatures — the
 * signature-side analogue of the TLS groups above, so hybrid signatures can be
 * negotiated for certificate authentication in a TLS 1.3 handshake. Generated
 * from HYBRID_SIG_LIST: each signature becomes a TLS SignatureScheme with its
 * code point (oqsprovider's, from `oqs-template/generate.yml`) and the same OID
 * the encoders use. Security bits derive from the PQ NIST level (1/2 -> 128,
 * 3/4 -> 192, 5 -> 256). Drift is caught by hybrid_capability_test.
 */
#ifdef HYBRID_HAVE_TLS_SIGALG
typedef struct {
    unsigned int code_point;
    unsigned int secbits;
    int mintls;
    int maxtls;
} HYBRID_TLS_SIGALG_CONSTANTS;

#define HYBRID_SIGALG_SECBITS(lvl) ((lvl) <= 2 ? 128u : (lvl) <= 4 ? 192u : 256u)

#define HYBRID_CAPS_SIG_CONST_ROW(cf, nm, a1, grp, a2, lvl, oid, ds, cp)      \
    { (unsigned int)(cp), HYBRID_SIGALG_SECBITS(lvl), TLS1_3_VERSION, 0 },
static const HYBRID_TLS_SIGALG_CONSTANTS hybrid_sigalg_list[] = {
    HYBRID_SIG_LIST(HYBRID_CAPS_SIG_CONST_ROW)
};
#undef HYBRID_CAPS_SIG_CONST_ROW

/* One OSSL_PARAM array per signature. NAME is the algorithm the TLS layer
 * fetches to build the signature context; OID matches the SPKI/PKCS8 encoders. */
#define HYBRID_TLS_SIGALG_ENTRY(signame, sigoid, idx)                         \
    {                                                                         \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME,          \
            signame, sizeof(signame)),                                        \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_NAME,               \
            signame, sizeof(signame)),                                        \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_SIGALG_OID,                \
            sigoid, sizeof(sigoid)),                                          \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,                \
            (unsigned int *)&hybrid_sigalg_list[idx].code_point),            \
        OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS,             \
            (unsigned int *)&hybrid_sigalg_list[idx].secbits),               \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS,                    \
            (int *)&hybrid_sigalg_list[idx].mintls),                         \
        OSSL_PARAM_int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS,                    \
            (int *)&hybrid_sigalg_list[idx].maxtls),                         \
        OSSL_PARAM_END                                                        \
    }

#define HYBRID_CAPS_SIG_PARAM_ROW(cf, nm, a1, grp, a2, lvl, oid, ds, cp)      \
    HYBRID_TLS_SIGALG_ENTRY(nm, oid, HYBRID_SIG_IDX_##cf),
static const OSSL_PARAM hybrid_param_sigalg_list[][8] = {
    HYBRID_SIG_LIST(HYBRID_CAPS_SIG_PARAM_ROW)
};
#undef HYBRID_CAPS_SIG_PARAM_ROW

#define HYBRID_TLS_SIGALG_COUNT \
    (sizeof(hybrid_param_sigalg_list) / sizeof(hybrid_param_sigalg_list[0]))
#endif /* HYBRID_HAVE_TLS_SIGALG */

int hybrid_get_capabilities(void *provctx, const char *capability,
                            OSSL_CALLBACK *cb, void *arg)
{
    HYBRID_PROV_CTX *ctx = provctx;
    size_t i;
    size_t advertised = 0;

    if (capability == NULL)
        return 0;

    if (OPENSSL_strcasecmp(capability, "TLS-GROUP") == 0) {
        for (i = 0; i < HYBRID_TLS_GROUP_COUNT; i++) {
            const char *name = hybrid_kem_table[i].hybrid_name;

            if (hybrid_group_list[i].group_id == 0)
                continue;   /* no registered TLS code point */
            /* Withdrawn because the default provider serves it (cede-to-default);
             * the group index is the master-list order, shared with the KEM
             * table, so match by that KEM's name. */
            if (hybrid_is_ceded(provctx, name))
                continue;
            /* Never advertise a group whose components are not both fetchable
             * here — libssl would otherwise negotiate it and fail mid-handshake. */
            if (ctx != NULL && !hybrid_group_operable(ctx, &hybrid_kem_table[i])) {
                hybrid_log("hybrid: not advertising TLS group %s (0x%04x): "
                           "a component is not fetchable in this libctx\n",
                           name, hybrid_group_list[i].group_id);
                continue;
            }
            if (advertised >= HYBRID_MAX_TLS_GROUPS) {
                hybrid_log("hybrid: TLS-GROUP advertisement cap (%d) reached; "
                           "dropping %s (0x%04x)\n", HYBRID_MAX_TLS_GROUPS,
                           name, hybrid_group_list[i].group_id);
                continue;
            }
            if (!cb(hybrid_param_group_list[i], arg))
                return 0;
            advertised++;
        }
        return 1;
    }

#ifdef HYBRID_HAVE_TLS_SIGALG
    if (OPENSSL_strcasecmp(capability, "TLS-SIGALG") == 0) {
        for (i = 0; i < HYBRID_TLS_SIGALG_COUNT; i++) {
            const char *name = hybrid_sig_table[i].hybrid_name;

            if (hybrid_sigalg_list[i].code_point == 0)
                continue;
            /* Withdrawn because the default provider serves it (cede-to-default);
             * the sigalg index is the master-list order, shared with the SIG
             * table, so match by that signature's name. */
            if (hybrid_is_ceded(provctx, name))
                continue;
            if (ctx != NULL && !hybrid_sigalg_operable(ctx, &hybrid_sig_table[i])) {
                hybrid_log("hybrid: not advertising TLS sigalg %s (0x%04x): "
                           "a component is not fetchable in this libctx\n",
                           name, hybrid_sigalg_list[i].code_point);
                continue;
            }
            if (advertised >= HYBRID_MAX_TLS_SIGALGS) {
                hybrid_log("hybrid: TLS-SIGALG advertisement cap (%d) reached; "
                           "dropping %s (0x%04x)\n", HYBRID_MAX_TLS_SIGALGS,
                           name, hybrid_sigalg_list[i].code_point);
                continue;
            }
            if (!cb(hybrid_param_sigalg_list[i], arg))
                return 0;
            advertised++;
        }
# ifdef HYBRID_COMPOSITE
        if (!composite_get_capabilities(provctx, capability, cb, arg))
            return 0;   /* also advertise the composite TLS SignatureSchemes */
# endif
        return 1;
    }
#endif

    return 0;
}
