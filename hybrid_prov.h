/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef HYBRID_PROV_H
#define HYBRID_PROV_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include <string.h>

/* Config-section keys for selecting component sub-algorithm providers. */
#define HYBRID_CONF_PQ_PROPQUERY       "pq-propquery"
#define HYBRID_CONF_CLASSIC_PROPQUERY  "classic-propquery"

/* Provider context */
typedef struct {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *handle;
    /*
     * Optional component property queries read from the provider's config
     * section (pq-propquery / classic-propquery). They steer which provider
     * supplies the PQ and classic sub-algorithms, independently of how the
     * hybrid algorithm itself was selected. NULL when unset. Owned here.
     */
    char *pq_propq;
    char *classic_propq;
} HYBRID_PROV_CTX;

/* Key state */
#define HYBRID_HAVE_NOKEYS  0
#define HYBRID_HAVE_PUBKEY  1
#define HYBRID_HAVE_PRVKEY  2

/* KEM component info */
typedef struct {
    const char *hybrid_name;    /* e.g., "X25519MLKEM768" */
    const char *alg1_name;      /* e.g., "X25519" */
    const char *alg1_group;     /* e.g., NULL or "P-256" */
    int         alg1_is_kem;    /* 0 = key-exchange, 1 = native KEM */
    const char *alg2_name;      /* e.g., "ML-KEM-768" */
    const char *alg2_group;     /* e.g., NULL */
    int         alg2_is_kem;    /* 1 = native KEM */
    int         alg2_slot;      /* position of alg2 in concatenation (0 or 1) */
    size_t      alg1_pubkey_bytes;
    size_t      alg1_prvkey_bytes;
    size_t      alg1_shsec_bytes;
    size_t      alg2_pubkey_bytes;
    size_t      alg2_prvkey_bytes;
    size_t      alg2_shsec_bytes;
    size_t      alg2_ctext_bytes;
    int         tls_codepoint;  /* TLS group code point, 0 if none */
} HYBRID_KEM_INFO;

/* Signature component info */
typedef struct {
    const char *hybrid_name;    /* e.g., "ed25519mldsa44" */
    const char *alg1_name;      /* e.g., "Ed25519" */
    const char *alg1_group;     /* e.g., NULL or "P-256" */
    const char *alg2_name;      /* e.g., "MLDSA44" */
    size_t      alg1_pubkey_bytes;
    size_t      alg1_prvkey_bytes;
    size_t      alg1_sig_bytes;     /* max signature size for alg1 */
    size_t      alg2_pubkey_bytes;
    size_t      alg2_prvkey_bytes;
    size_t      alg2_sig_bytes;
} HYBRID_SIG_INFO;

/* Hybrid key — used for both KEM and SIG hybrids */
typedef struct hybrid_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const void *info;           /* HYBRID_KEM_INFO * or HYBRID_SIG_INFO * */
    int is_kem;                 /* 1 = KEM, 0 = signature */
    EVP_PKEY *key1;             /* classical component */
    EVP_PKEY *key2;             /* PQ component */
    unsigned int state;
    /*
     * Per-component property queries (borrowed pointers into the provider
     * context, which outlives the key; not freed here). NULL when unset, in
     * which case the per-component accessors fall back to propq.
     */
    const char *pq_propq;       /* for the PQ component (key2 / alg2) */
    const char *classic_propq;  /* for the classical component (key1 / alg1) */
} HYBRID_KEY;

/* Per-component property query, falling back to the key's generic propq. */
#define HYBRID_KEY_PQ_PROPQ(k) \
    ((k)->pq_propq != NULL ? (k)->pq_propq : (k)->propq)
#define HYBRID_KEY_CLASSIC_PROPQ(k) \
    ((k)->classic_propq != NULL ? (k)->classic_propq : (k)->propq)

#define hybrid_have_pubkey(key)  ((key)->state >= HYBRID_HAVE_PUBKEY)
#define hybrid_have_prvkey(key)  ((key)->state >= HYBRID_HAVE_PRVKEY)

/*
 * Master hybrid-KEM list — single source of truth. One row per algorithm drives
 * the info table (below), the per-algorithm keymgmt thunks/dispatch tables
 * (hybrid_keymgmt.c) and the provider registration (hybrid_prov.c). To add a
 * hybrid KEM, add exactly one row here.
 *
 * The alg2 (PQ) component is always a native ML-KEM. `slot` is the position of
 * the PQ share in the ctext/shared-secret/pubkey concatenation (0 = PQ first),
 * which equals oqsprovider's `reverse_share` (reverse_share=1 -> slot 0). It
 * also matches OpenSSL's built-in MLX layout for the standardized names.
 *
 * X(cfield, name,
 *   alg1, alg1_group, alg1_is_kem,   alg2, slot,
 *   a1_pub,a1_prv,a1_ss,   a2_pub,a2_prv,a2_ss,a2_ct,
 *   tls_codepoint, desc)
 */
#define HYBRID_KEM_LIST(X)                                                    \
  /* --- default-provider MLX names (raw concat) --- */                       \
  X(x25519mlkem768,    "X25519MLKEM768",     "X25519", NULL,           0,     \
      "MLKEM768",  0,  32,32,32,    1184,2400,32,1088,  0x11ec,               \
      "X25519+ML-KEM-768")                                                    \
  X(x448mlkem1024,     "X448MLKEM1024",      "X448",   NULL,           0,     \
      "MLKEM1024", 0,  56,56,56,    1568,3168,32,1568,  0x0000,               \
      "X448+ML-KEM-1024")                                                     \
  X(secp256r1mlkem768, "SecP256r1MLKEM768",  "EC",     "P-256",        0,     \
      "MLKEM768",  1,  65,32,32,    1184,2400,32,1088,  0x11eb,               \
      "P-256+ML-KEM-768")                                                     \
  X(secp384r1mlkem1024,"SecP384r1MLKEM1024", "EC",     "P-384",        0,     \
      "MLKEM1024", 1,  97,48,48,    1568,3168,32,1568,  0x11ed,               \
      "P-384+ML-KEM-1024")                                                    \
  /* --- oqsprovider OQS-legacy ML-KEM hybrids --- */                         \
  X(x25519_mlkem512,   "x25519_mlkem512",    "X25519", NULL,           0,     \
      "MLKEM512",  0,  32,32,32,    800,1632,32,768,    0x2fb6,               \
      "X25519+ML-KEM-512")                                                    \
  X(p256_mlkem512,     "p256_mlkem512",      "EC",     "P-256",        0,     \
      "MLKEM512",  1,  65,32,32,    800,1632,32,768,    0x2f4b,               \
      "P-256+ML-KEM-512")                                                     \
  X(bp256_mlkem512,    "bp256_mlkem512",     "EC",   "brainpoolP256r1",0,     \
      "MLKEM512",  0,  65,32,32,    800,1632,32,768,    0xfe20,               \
      "brainpoolP256r1+ML-KEM-512")                                          \
  X(p384_mlkem768,     "p384_mlkem768",      "EC",     "P-384",        0,     \
      "MLKEM768",  1,  97,48,48,    1184,2400,32,1088,  0x2f4c,               \
      "P-384+ML-KEM-768")                                                     \
  X(x448_mlkem768,     "x448_mlkem768",      "X448",   NULL,           0,     \
      "MLKEM768",  0,  56,56,56,    1184,2400,32,1088,  0x2fb7,               \
      "X448+ML-KEM-768")                                                      \
  X(bp384_mlkem768,    "bp384_mlkem768",     "EC",   "brainpoolP384r1",0,     \
      "MLKEM768",  0,  97,48,48,    1184,2400,32,1088,  0xfe21,               \
      "brainpoolP384r1+ML-KEM-768")                                          \
  X(p521_mlkem1024,    "p521_mlkem1024",     "EC",     "P-521",        0,     \
      "MLKEM1024", 1,  133,66,66,   1568,3168,32,1568,  0x2f4d,               \
      "P-521+ML-KEM-1024")                                                    \
  X(bp512_mlkem1024,   "bp512_mlkem1024",    "EC",   "brainpoolP512r1",0,     \
      "MLKEM1024", 0,  129,64,64,   1568,3168,32,1568,  0xfe22,               \
      "brainpoolP512r1+ML-KEM-1024")

/* Generate the info table from the master list. */
#define HYBRID_KEM_ROW(cf, nm, a1, grp, a1k, a2, slot,                        \
                       a1p, a1v, a1s, a2p, a2v, a2s, a2c, cp, ds)             \
    { nm, a1, grp, a1k, a2, NULL, 1, slot,                                    \
      a1p, a1v, a1s, a2p, a2v, a2s, a2c, cp },
static const HYBRID_KEM_INFO hybrid_kem_table[] = {
    HYBRID_KEM_LIST(HYBRID_KEM_ROW)
};
#undef HYBRID_KEM_ROW

/* Per-algorithm table index, in list order (used to bind keymgmt thunks). */
#define HYBRID_KEM_IDX_ROW(cf, ...) HYBRID_KEM_IDX_##cf,
enum { HYBRID_KEM_LIST(HYBRID_KEM_IDX_ROW) HYBRID_KEM_ALG_COUNT_ENUM };
#undef HYBRID_KEM_IDX_ROW

#define HYBRID_KEM_ALG_COUNT \
    (sizeof(hybrid_kem_table) / sizeof(hybrid_kem_table[0]))

/*
 * Signature algorithm table.
 * Wire format: sig = alg1_sig || alg2_sig (classical first, PQ second).
 * ECDSA signatures are DER-encoded with variable length; we use max sizes.
 */
static const HYBRID_SIG_INFO hybrid_sig_table[] = {
    {
        "ed25519mldsa44",
        "Ed25519", NULL, "MLDSA44",
        32, 32, 64,                  /* Ed25519: pub, prv, sig */
        1312, 2560, 2420             /* ML-DSA-44: pub, prv, sig */
    },
    {
        "ed25519mldsa65",
        "Ed25519", NULL, "MLDSA65",
        32, 32, 64,
        1952, 4032, 3309
    },
    {
        "ed448mldsa87",
        "Ed448", NULL, "MLDSA87",
        57, 57, 114,                 /* Ed448: pub, prv, sig */
        2592, 4896, 4627
    },
    {
        "p256mldsa44",
        "EC", "P-256", "MLDSA44",
        65, 32, 72,                  /* P-256: pub, prv, max DER sig */
        1312, 2560, 2420
    },
    {
        "p256mldsa65",
        "EC", "P-256", "MLDSA65",
        65, 32, 72,
        1952, 4032, 3309
    },
    {
        "p384mldsa87",
        "EC", "P-384", "MLDSA87",
        97, 48, 104,                 /* P-384: pub, prv, max DER sig */
        2592, 4896, 4627
    },
};

#define HYBRID_SIG_ALG_COUNT \
    (sizeof(hybrid_sig_table) / sizeof(hybrid_sig_table[0]))

/* Accessor macros — work for both KEM and SIG info via HYBRID_KEY */
#define HYBRID_KEY_ALG1_NAME(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg1_name \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg1_name)
#define HYBRID_KEY_ALG1_GROUP(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg1_group \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg1_group)
#define HYBRID_KEY_ALG2_NAME(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg2_name \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg2_name)
#define HYBRID_KEY_ALG1_PUBKEY_BYTES(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg1_pubkey_bytes \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg1_pubkey_bytes)
#define HYBRID_KEY_ALG2_PUBKEY_BYTES(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg2_pubkey_bytes \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg2_pubkey_bytes)
#define HYBRID_KEY_ALG1_PRVKEY_BYTES(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg1_prvkey_bytes \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg1_prvkey_bytes)
#define HYBRID_KEY_ALG2_PRVKEY_BYTES(k) \
    ((k)->is_kem ? ((const HYBRID_KEM_INFO *)(k)->info)->alg2_prvkey_bytes \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg2_prvkey_bytes)

/* Total sizes for KEM algorithms */
static inline size_t hybrid_kem_pubkey_bytes(const HYBRID_KEM_INFO *info)
{
    return info->alg1_pubkey_bytes + info->alg2_pubkey_bytes;
}

static inline size_t hybrid_kem_prvkey_bytes(const HYBRID_KEM_INFO *info)
{
    return info->alg1_prvkey_bytes + info->alg2_prvkey_bytes;
}

static inline size_t hybrid_kem_ctext_bytes(const HYBRID_KEM_INFO *info)
{
    /* For key-exchange alg, "ciphertext" is the ephemeral public key */
    size_t alg1_ct = info->alg1_is_kem ? 0 : info->alg1_pubkey_bytes;
    return alg1_ct + info->alg2_ctext_bytes;
}

static inline size_t hybrid_kem_shsec_bytes(const HYBRID_KEM_INFO *info)
{
    return info->alg1_shsec_bytes + info->alg2_shsec_bytes;
}

/* Total sizes for signature algorithms */
static inline size_t hybrid_sig_pubkey_bytes(const HYBRID_SIG_INFO *info)
{
    return info->alg1_pubkey_bytes + info->alg2_pubkey_bytes;
}

static inline size_t hybrid_sig_prvkey_bytes(const HYBRID_SIG_INFO *info)
{
    return info->alg1_prvkey_bytes + info->alg2_prvkey_bytes;
}

static inline size_t hybrid_sig_max_sig_bytes(const HYBRID_SIG_INFO *info)
{
    return info->alg1_sig_bytes + info->alg2_sig_bytes;
}

/* Generic total sizes via HYBRID_KEY */
static inline size_t hybrid_key_pubkey_bytes(const HYBRID_KEY *key)
{
    if (key->is_kem)
        return hybrid_kem_pubkey_bytes((const HYBRID_KEM_INFO *)key->info);
    return hybrid_sig_pubkey_bytes((const HYBRID_SIG_INFO *)key->info);
}

static inline size_t hybrid_key_prvkey_bytes(const HYBRID_KEY *key)
{
    if (key->is_kem)
        return hybrid_kem_prvkey_bytes((const HYBRID_KEM_INFO *)key->info);
    return hybrid_sig_prvkey_bytes((const HYBRID_SIG_INFO *)key->info);
}

/* Extern declarations for dispatch tables */
extern const OSSL_DISPATCH hybrid_kem_functions[];
extern const OSSL_DISPATCH hybrid_sig_functions[];

/* TLS-GROUP capability advertising (hybrid_caps.c) */
int hybrid_get_capabilities(void *provctx, const char *capability,
                            OSSL_CALLBACK *cb, void *arg);

/* Per-algorithm keymgmt dispatch — declared by macro in hybrid_keymgmt.c */
#define DECLARE_HYBRID_KMGMT_EXTERN(name) \
    extern const OSSL_DISPATCH hybrid_##name##_kmgmt_functions[];

/* KEM keymgmt — generated from the master list */
#define HYBRID_KEM_EXTERN_ROW(cf, ...) DECLARE_HYBRID_KMGMT_EXTERN(cf)
HYBRID_KEM_LIST(HYBRID_KEM_EXTERN_ROW)
#undef HYBRID_KEM_EXTERN_ROW

/* Signature keymgmt */
DECLARE_HYBRID_KMGMT_EXTERN(ed25519mldsa44)
DECLARE_HYBRID_KMGMT_EXTERN(ed25519mldsa65)
DECLARE_HYBRID_KMGMT_EXTERN(ed448mldsa87)
DECLARE_HYBRID_KMGMT_EXTERN(p256mldsa44)
DECLARE_HYBRID_KMGMT_EXTERN(p256mldsa65)
DECLARE_HYBRID_KMGMT_EXTERN(p384mldsa87)

#endif /* HYBRID_PROV_H */
