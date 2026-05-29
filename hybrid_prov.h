/*
 * Copyright 2025 hybrid-provider contributors
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

/* Provider context */
typedef struct {
    OSSL_LIB_CTX *libctx;
    const OSSL_CORE_HANDLE *handle;
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
} HYBRID_KEM_INFO;

/* Composite key */
typedef struct hybrid_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const HYBRID_KEM_INFO *info;
    EVP_PKEY *key1;             /* classical component */
    EVP_PKEY *key2;             /* PQ component */
    unsigned int state;
} HYBRID_KEY;

#define hybrid_have_pubkey(key)  ((key)->state >= HYBRID_HAVE_PUBKEY)
#define hybrid_have_prvkey(key)  ((key)->state >= HYBRID_HAVE_PRVKEY)

/*
 * Algorithm table — matches OpenSSL's built-in MLX KEM wire format.
 *
 * Wire format analysis from openssl/providers/implementations/kem/mlx_kem.c:
 *   X25519MLKEM768:    ml_kem_slot=0 → ctext = mlkem_ct || x25519_pub
 *   X448MLKEM1024:     ml_kem_slot=0 → ctext = mlkem_ct || x448_pub
 *   SecP256r1MLKEM768: ml_kem_slot=1 → ctext = ec_pub   || mlkem_ct
 *   SecP384r1MLKEM1024:ml_kem_slot=1 → ctext = ec_pub   || mlkem_ct
 *
 * Our alg2_slot matches ml_kem_slot (alg2 = PQ = ML-KEM).
 */
static const HYBRID_KEM_INFO hybrid_kem_table[] = {
    {
        "X25519MLKEM768",
        "X25519", NULL, 0,          /* alg1: key-exchange */
        "ML-KEM-768", NULL, 1,      /* alg2: native KEM */
        0,                           /* alg2_slot: ML-KEM first in ctext/ss */
        32, 32, 32,                  /* X25519: pub, prv, shsec */
        1184, 2400, 32, 1088         /* ML-KEM-768: pub, prv, shsec, ctext */
    },
    {
        "X448MLKEM1024",
        "X448", NULL, 0,
        "ML-KEM-1024", NULL, 1,
        0,
        56, 56, 56,                  /* X448 */
        1568, 3168, 32, 1568         /* ML-KEM-1024 */
    },
    {
        "SecP256r1MLKEM768",
        "EC", "P-256", 0,
        "ML-KEM-768", NULL, 1,
        1,                           /* alg2_slot: ML-KEM second in ctext/ss */
        65, 32, 32,                  /* P-256 */
        1184, 2400, 32, 1088         /* ML-KEM-768 */
    },
    {
        "SecP384r1MLKEM1024",
        "EC", "P-384", 0,
        "ML-KEM-1024", NULL, 1,
        1,
        97, 48, 48,                  /* P-384 */
        1568, 3168, 32, 1568         /* ML-KEM-1024 */
    },
};

#define HYBRID_KEM_ALG_COUNT \
    (sizeof(hybrid_kem_table) / sizeof(hybrid_kem_table[0]))

/* Total sizes for a given algorithm */
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

/* Extern declarations for dispatch tables */
extern const OSSL_DISPATCH hybrid_kem_functions[];

/* Per-algorithm keymgmt dispatch — declared by macro in hybrid_keymgmt.c */
#define DECLARE_HYBRID_KEM_KMGMT_EXTERN(name) \
    extern const OSSL_DISPATCH hybrid_##name##_kmgmt_functions[];

DECLARE_HYBRID_KEM_KMGMT_EXTERN(x25519mlkem768)
DECLARE_HYBRID_KEM_KMGMT_EXTERN(x448mlkem1024)
DECLARE_HYBRID_KEM_KMGMT_EXTERN(secp256r1mlkem768)
DECLARE_HYBRID_KEM_KMGMT_EXTERN(secp384r1mlkem1024)

#endif /* HYBRID_PROV_H */
