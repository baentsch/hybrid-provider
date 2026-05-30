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
 * Only the three MLX hybrids with standardized TLS codepoints
 * (draft-ietf-tls-ecdhe-mlkem) are advertised; X448MLKEM1024 has no registered
 * codepoint and is therefore usable only via the KEM API, not as a TLS group.
 *
 * Codepoints (wire values) are hard-coded rather than pulled from
 * internal/tlsgroups.h, per the EVP-only / no-internal-headers rule.
 *
 * The TLS group names and ALG names are the canonical MLX names, identical to
 * the default provider's, so that choosing between the two implementations is
 * driven purely by provider load order / property query (config-only
 * switching) rather than by distinct names.
 */
#define HYBRID_TLS_GROUP_ID_SecP256r1MLKEM768   0x11EB
#define HYBRID_TLS_GROUP_ID_X25519MLKEM768      0x11EC
#define HYBRID_TLS_GROUP_ID_SecP384r1MLKEM1024  0x11ED

/* ML-KEM security strengths: ML-KEM-768 = NIST level 3, ML-KEM-1024 = level 5 */
#define HYBRID_MLKEM768_SECBITS    192
#define HYBRID_MLKEM1024_SECBITS   256

typedef struct {
    unsigned int group_id;
    unsigned int secbits;
    int mintls;
    int maxtls;
    int mindtls;
    int maxdtls;
    int is_kem;
} HYBRID_TLS_GROUP_CONSTANTS;

static const HYBRID_TLS_GROUP_CONSTANTS hybrid_group_list[] = {
    { HYBRID_TLS_GROUP_ID_X25519MLKEM768,     HYBRID_MLKEM768_SECBITS,
      TLS1_3_VERSION, 0, -1, -1, 1 },
    { HYBRID_TLS_GROUP_ID_SecP256r1MLKEM768,  HYBRID_MLKEM768_SECBITS,
      TLS1_3_VERSION, 0, -1, -1, 1 },
    { HYBRID_TLS_GROUP_ID_SecP384r1MLKEM1024, HYBRID_MLKEM1024_SECBITS,
      TLS1_3_VERSION, 0, -1, -1, 1 },
};

/*
 * One OSSL_PARAM array per group. NAME and ALG are the canonical name; the
 * ALG name is what the TLS layer fetches as a KEM/keymgmt — it matches the
 * algorithm names registered in hybrid_prov.c. NAME_INTERNAL is left empty,
 * as the default provider does for these groups.
 */
#define HYBRID_TLS_GROUP_ENTRY(tlsname, algorithm, idx)                 \
    {                                                                   \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME,          \
            tlsname, sizeof(tlsname)),                                  \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, \
            "", sizeof("")),                                            \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG,           \
            algorithm, sizeof(algorithm)),                              \
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

static const OSSL_PARAM hybrid_param_group_list[][11] = {
    HYBRID_TLS_GROUP_ENTRY("X25519MLKEM768",     "X25519MLKEM768",     0),
    HYBRID_TLS_GROUP_ENTRY("SecP256r1MLKEM768",  "SecP256r1MLKEM768",  1),
    HYBRID_TLS_GROUP_ENTRY("SecP384r1MLKEM1024", "SecP384r1MLKEM1024", 2),
};

#define HYBRID_TLS_GROUP_COUNT \
    (sizeof(hybrid_param_group_list) / sizeof(hybrid_param_group_list[0]))

int hybrid_get_capabilities(void *provctx, const char *capability,
                            OSSL_CALLBACK *cb, void *arg)
{
    size_t i;

    if (capability == NULL
            || OPENSSL_strcasecmp(capability, "TLS-GROUP") != 0)
        return 0;

    for (i = 0; i < HYBRID_TLS_GROUP_COUNT; i++)
        if (!cb(hybrid_param_group_list[i], arg))
            return 0;
    return 1;
}
