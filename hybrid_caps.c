/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/core_names.h>
#include <openssl/prov_ssl.h>   /* TLS1_3_VERSION */

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
 * wire). Code points are the oqsprovider / IETF defaults; per the EVP-only rule
 * they are hard-coded here rather than pulled from internal TLS headers.
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

int hybrid_get_capabilities(void *provctx, const char *capability,
                            OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    if (capability == NULL
            || OPENSSL_strcasecmp(capability, "TLS-GROUP") != 0)
        return 0;

    for (i = 0; i < HYBRID_TLS_GROUP_COUNT; i++) {
        if (hybrid_group_list[i].group_id == 0)
            continue;   /* no registered TLS code point */
        if (!cb(hybrid_param_group_list[i], arg))
            return 0;
    }
    return 1;
}
