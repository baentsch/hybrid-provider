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
/*
 * Optional private component context. When "component-providers" is set (a
 * space-separated list of provider module names, e.g. "default oqsprovider"),
 * the hybrid provider loads those providers into its OWN library context and
 * sources all component sub-algorithms from there, instead of from the
 * application's context. This lets a base algorithm (e.g. FrodoKEM from
 * oqsprovider) be composed without that provider's competing hybrid groups
 * colliding in the application's context. "component-path" optionally sets the
 * module search path for that context (defaults to the OPENSSL_MODULES env).
 */
#define HYBRID_CONF_COMPONENT_PROVIDERS "component-providers"
#define HYBRID_CONF_COMPONENT_PATH      "component-path"

#define HYBRID_MAX_COMPONENT_PROVIDERS  8

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
    /*
     * Context used to fetch component sub-algorithms. Equals `libctx` by
     * default; when "component-providers" is configured it is a private context
     * (comp_owned == 1) holding the named providers. Component operations use
     * this, so the application's context need not load those providers.
     */
    OSSL_LIB_CTX *comp_libctx;
    int comp_owned;
    OSSL_PROVIDER *comp_provs[HYBRID_MAX_COMPONENT_PROVIDERS];
    int n_comp_provs;
} HYBRID_PROV_CTX;

/* The context to use for component sub-algorithm fetches. */
#define HYBRID_COMPONENT_LIBCTX(pctx) \
    ((pctx)->comp_libctx != NULL ? (pctx)->comp_libctx : (pctx)->libctx)

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
    int         tls_codepoint;  /* TLS group code point, 0 if none */
    /* Component sizes are discovered at runtime; see HYBRID_SIZES. */
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

/*
 * Per-component sizes for a KEM hybrid, discovered at runtime from the actual
 * component algorithms (see hybrid_kem_ensure_sizes) rather than hardcoded.
 * This keeps the algorithm table free of size constants: adding a hybrid needs
 * only component names + slot. `ct` is the ciphertext contribution (ephemeral
 * public-key length for a key-exchange component, KEM ciphertext otherwise).
 */
typedef struct {
    size_t a1_pub, a1_prv, a1_ss, a1_ct;   /* classical (alg1) */
    size_t a2_pub, a2_prv, a2_ss, a2_ct;   /* PQ (alg2) */
    int    valid;
} HYBRID_SIZES;

/* Hybrid key — used for both KEM and SIG hybrids */
typedef struct hybrid_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const void *info;           /* HYBRID_KEM_INFO * or HYBRID_SIG_INFO * */
    int is_kem;                 /* 1 = KEM, 0 = signature */
    EVP_PKEY *key1;             /* classical component */
    EVP_PKEY *key2;             /* PQ component */
    unsigned int state;
    HYBRID_SIZES sizes;         /* KEM only: runtime-discovered component sizes */
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
 * The alg2 (PQ) component is always a native KEM. `slot` is the position of
 * the PQ share in the ctext/shared-secret/pubkey concatenation (0 = PQ first),
 * which equals oqsprovider's `reverse_share` (reverse_share=1 -> slot 0). It
 * also matches OpenSSL's built-in MLX layout for the standardized names.
 *
 * Component sizes are NOT listed here — they are discovered at runtime from the
 * component algorithms (hybrid_kem_ensure_sizes), so a new hybrid needs only its
 * component names, EC group and slot.
 *
 * X(cfield, name, alg1, alg1_group, alg1_is_kem, alg2, slot,
 *   tls_codepoint, secbits, desc)
 *
 * tls_codepoint / secbits are the oqsprovider (and IETF, for MLX) defaults; a
 * 0 codepoint means "no TLS group" (KEM API only, e.g. X448MLKEM1024).
 */
#define HYBRID_KEM_LIST(X)                                                    \
  /* --- default-provider MLX names (raw concat) --- */                       \
  X(x25519mlkem768,    "X25519MLKEM768",     "X25519", NULL,            0,    \
      "MLKEM768",  0, 0x11ec, 192, "X25519+ML-KEM-768")                       \
  X(x448mlkem1024,     "X448MLKEM1024",      "X448",   NULL,            0,    \
      "MLKEM1024", 0, 0x0000, 256, "X448+ML-KEM-1024")                        \
  X(secp256r1mlkem768, "SecP256r1MLKEM768",  "EC",     "P-256",         0,    \
      "MLKEM768",  1, 0x11eb, 192, "P-256+ML-KEM-768")                        \
  X(secp384r1mlkem1024,"SecP384r1MLKEM1024", "EC",     "P-384",         0,    \
      "MLKEM1024", 1, 0x11ed, 256, "P-384+ML-KEM-1024")                       \
  /* --- oqsprovider OQS-legacy ML-KEM hybrids --- */                         \
  X(x25519_mlkem512,   "x25519_mlkem512",    "X25519", NULL,            0,    \
      "MLKEM512",  0, 0x2fb6, 128, "X25519+ML-KEM-512")                       \
  X(p256_mlkem512,     "p256_mlkem512",      "EC",     "P-256",         0,    \
      "MLKEM512",  1, 0x2f4b, 128, "P-256+ML-KEM-512")                        \
  X(bp256_mlkem512,    "bp256_mlkem512",     "EC",   "brainpoolP256r1", 0,    \
      "MLKEM512",  0, 0xfe20, 128, "brainpoolP256r1+ML-KEM-512")              \
  X(p384_mlkem768,     "p384_mlkem768",      "EC",     "P-384",         0,    \
      "MLKEM768",  1, 0x2f4c, 192, "P-384+ML-KEM-768")                        \
  X(x448_mlkem768,     "x448_mlkem768",      "X448",   NULL,            0,    \
      "MLKEM768",  0, 0x2fb7, 192, "X448+ML-KEM-768")                         \
  X(bp384_mlkem768,    "bp384_mlkem768",     "EC",   "brainpoolP384r1", 0,    \
      "MLKEM768",  0, 0xfe21, 192, "brainpoolP384r1+ML-KEM-768")              \
  X(p521_mlkem1024,    "p521_mlkem1024",     "EC",     "P-521",         0,    \
      "MLKEM1024", 1, 0x2f4d, 256, "P-521+ML-KEM-1024")                       \
  X(bp512_mlkem1024,   "bp512_mlkem1024",    "EC",   "brainpoolP512r1", 0,    \
      "MLKEM1024", 0, 0xfe22, 256, "brainpoolP512r1+ML-KEM-1024")             \
  /* --- oqsprovider FrodoKEM hybrids (PQ base from oqsprovider only) --- */   \
  X(p256_frodo640aes,  "p256_frodo640aes",   "EC",     "P-256",         0,    \
      "frodo640aes", 1, 0xfe24, 128, "P-256+FrodoKEM-640-AES")                \
  X(x25519_frodo640aes,"x25519_frodo640aes", "X25519", NULL,            0,    \
      "frodo640aes", 1, 0xfe25, 128, "X25519+FrodoKEM-640-AES")               \
  X(p256_frodo640shake,"p256_frodo640shake", "EC",     "P-256",         0,    \
      "frodo640shake", 1, 0xfe27, 128, "P-256+FrodoKEM-640-SHAKE")            \
  X(x25519_frodo640shake,"x25519_frodo640shake","X25519",NULL,          0,    \
      "frodo640shake", 1, 0xfe28, 128, "X25519+FrodoKEM-640-SHAKE")           \
  X(p384_frodo976aes,  "p384_frodo976aes",   "EC",     "P-384",         0,    \
      "frodo976aes", 1, 0xfe2a, 192, "P-384+FrodoKEM-976-AES")                \
  X(x448_frodo976aes,  "x448_frodo976aes",   "X448",   NULL,            0,    \
      "frodo976aes", 1, 0xfe2b, 192, "X448+FrodoKEM-976-AES")                 \
  X(p384_frodo976shake,"p384_frodo976shake", "EC",     "P-384",         0,    \
      "frodo976shake", 1, 0xfe2d, 192, "P-384+FrodoKEM-976-SHAKE")            \
  X(x448_frodo976shake,"x448_frodo976shake", "X448",   NULL,            0,    \
      "frodo976shake", 1, 0xfe2e, 192, "X448+FrodoKEM-976-SHAKE")             \
  X(p521_frodo1344aes, "p521_frodo1344aes",  "EC",     "P-521",         0,    \
      "frodo1344aes", 1, 0xfe30, 256, "P-521+FrodoKEM-1344-AES")              \
  X(p521_frodo1344shake,"p521_frodo1344shake","EC",    "P-521",         0,    \
      "frodo1344shake", 1, 0xfe32, 256, "P-521+FrodoKEM-1344-SHAKE")          \
  /* --- oqsprovider BIKE hybrids --- */                                      \
  X(p256_bikel1,       "p256_bikel1",        "EC",     "P-256",         0,    \
      "bikel1", 1, 0xfe11, 128, "P-256+BIKE-L1")                              \
  X(x25519_bikel1,     "x25519_bikel1",      "X25519", NULL,            0,    \
      "bikel1", 1, 0xfe12, 128, "X25519+BIKE-L1")                             \
  X(p384_bikel3,       "p384_bikel3",        "EC",     "P-384",         0,    \
      "bikel3", 1, 0xfe14, 192, "P-384+BIKE-L3")                              \
  X(x448_bikel3,       "x448_bikel3",        "X448",   NULL,            0,    \
      "bikel3", 1, 0xfe15, 192, "X448+BIKE-L3")                               \
  X(p521_bikel5,       "p521_bikel5",        "EC",     "P-521",         0,    \
      "bikel5", 1, 0xfe17, 256, "P-521+BIKE-L5")                              \
  /* --- oqsprovider HQC hybrids --- */                                       \
  X(p256_hqc1,         "p256_hqc1",          "EC",     "P-256",         0,    \
      "hqc1", 1, 0xfe34, 128, "P-256+HQC-1")                                  \
  X(x25519_hqc1,       "x25519_hqc1",        "X25519", NULL,            0,    \
      "hqc1", 1, 0xfe35, 128, "X25519+HQC-1")                                 \
  X(p384_hqc3,         "p384_hqc3",          "EC",     "P-384",         0,    \
      "hqc3", 1, 0xfe37, 192, "P-384+HQC-3")                                  \
  X(x448_hqc3,         "x448_hqc3",          "X448",   NULL,            0,    \
      "hqc3", 1, 0xfe38, 192, "X448+HQC-3")                                   \
  X(p521_hqc5,         "p521_hqc5",          "EC",     "P-521",         0,    \
      "hqc5", 1, 0xfe3a, 256, "P-521+HQC-5")

/* Generate the info table from the master list. */
#define HYBRID_KEM_ROW(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds)           \
    { nm, a1, grp, a1k, a2, NULL, 1, slot, cp },
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
/*
 * KEM size accessors read the runtime-discovered cache (key->sizes); SIG size
 * accessors read the static signature table. Callers must have populated the
 * KEM cache via hybrid_kem_ensure_sizes() before using the KEM branch.
 */
#define HYBRID_KEY_ALG1_PUBKEY_BYTES(k) \
    ((k)->is_kem ? (k)->sizes.a1_pub \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg1_pubkey_bytes)
#define HYBRID_KEY_ALG2_PUBKEY_BYTES(k) \
    ((k)->is_kem ? (k)->sizes.a2_pub \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg2_pubkey_bytes)
#define HYBRID_KEY_ALG1_PRVKEY_BYTES(k) \
    ((k)->is_kem ? (k)->sizes.a1_prv \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg1_prvkey_bytes)
#define HYBRID_KEY_ALG2_PRVKEY_BYTES(k) \
    ((k)->is_kem ? (k)->sizes.a2_prv \
                 : ((const HYBRID_SIG_INFO *)(k)->info)->alg2_prvkey_bytes)

/* Total ciphertext / shared-secret sizes for a KEM key (from the cache). */
static inline size_t hybrid_kem_ctext_bytes(const HYBRID_KEY *key)
{
    return key->sizes.a1_ct + key->sizes.a2_ct;
}

static inline size_t hybrid_kem_shsec_bytes(const HYBRID_KEY *key)
{
    return key->sizes.a1_ss + key->sizes.a2_ss;
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
        return key->sizes.a1_pub + key->sizes.a2_pub;
    return hybrid_sig_pubkey_bytes((const HYBRID_SIG_INFO *)key->info);
}

static inline size_t hybrid_key_prvkey_bytes(const HYBRID_KEY *key)
{
    if (key->is_kem)
        return key->sizes.a1_prv + key->sizes.a2_prv;
    return hybrid_sig_prvkey_bytes((const HYBRID_SIG_INFO *)key->info);
}

/* Extern declarations for dispatch tables */
extern const OSSL_DISPATCH hybrid_kem_functions[];
extern const OSSL_DISPATCH hybrid_sig_functions[];

/*
 * Populate key->sizes for a KEM hybrid by querying the component algorithms
 * (using existing components when present, otherwise throwaway keygens). Safe to
 * call repeatedly; a no-op once the cache is valid. Returns 1 on success.
 * Implemented in hybrid_keymgmt.c.
 */
int hybrid_kem_ensure_sizes(HYBRID_KEY *key);

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
