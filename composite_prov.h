/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) signature family — shared types + master info table.
 *
 * Composite is a build-flag-gated capability *inside this provider*
 * (-DHYBRID_COMPOSITE), NOT a separate module.
 *
 * Construction (draft-ietf-lamps-pq-composite-sigs-19):
 *     M' = COMPOSITE_SIG_PREFIX || label || len(ctx) || ctx || PH(M)
 *     pqSig   = PQ.Sign(pqSK,   M', ctx = label)
 *     tradSig = Trad.Sign(tradSK, M')
 *     serialization is raw CONCATENATION (not ASN.1 SEQUENCE):
 *         pubkey  = pqPub  || tradPub
 *         privkey = pqPriv || tradPriv   (pqPriv = 32-byte seed for ML-DSA)
 *         sig     = pqSig  || tradSig
 *     component sizes are fixed per OID, so the split is unambiguous.
 *
 * The combiner is GENERIC over the PQ component: everything ML-DSA-specific lives
 * in a table row, so the family can span research PQ sigs (experimental tier).
 * Two tiers, never blurred:
 *   - standardized : PQ = ML-DSA only, IANA/LAMPS OID arc; byte-exact against the
 *                    draft-19 reference vectors. Ceded to the default provider if
 *                    OpenSSL ships native composite (openssl#26121), like MLX.
 *   - experimental : any other PQ sig, DISJOINT OID arc, non-normative labels.
 */
#ifndef HYBRID_COMPOSITE_PROV_H
#define HYBRID_COMPOSITE_PROV_H

#include <openssl/types.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>   /* OSSL_PKEY_PARAM_* used in the master list */
#include <openssl/opensslv.h>     /* OPENSSL_VERSION_NUMBER (seed-API gate) */
#include <stddef.h>
#include "hybrid_prov.h"   /* composite is a capability OF the hybrid provider;
                            * it shares HYBRID_PROV_CTX (libctx + BIO up-calls). */

/*
 * Seed API gate. The standardized composite tier serializes the PQ private key
 * as its ML-DSA seed, which needs OpenSSL 3.5's seed param API
 * (OSSL_PKEY_PARAM_ML_DSA_SEED). Below 3.5 that macro is not even declared, so
 * define a fallback to its stable value ("seed") purely so the master list, which
 * names it for the standardized rows, still *compiles*. The standardized rows are
 * not registered below 3.5 (see hybrid_prov.c); only the experimental tier —
 * which names OSSL_PKEY_PARAM_PRIV_KEY (raw private key, present since 3.0) — runs
 * there, so this fallback value is never actually exercised on <3.5. */
#ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
# define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
#endif

/* True when the ML-DSA/ML-KEM seed API is available (>=3.5); gates the
 * standardized composite tiers at build (tests) and at registration time. */
#define COMPOSITE_SEED_AVAILABLE (OPENSSL_VERSION_NUMBER >= 0x30500000L)

/* Whole-scheme domain separator (fixed ASCII, draft-19). Shared by every combo,
 * standardized and experimental; the per-combo `label` differentiates them. */
#define COMPOSITE_SIG_PREFIX "CompositeAlgorithmSignatures2025"

/* The PQ private split length is discovered at runtime from the component
 * algorithm (info->pq_priv_param on a fresh key) — no hardcoded seed size, so a
 * non-ML-DSA PQ component with a different seed / raw-private length works. */

/* Default RSA modulus for the combiner self-test (composite_sig_test); the
 * provider itself uses the per-combo COMPOSITE_SIG_INFO.trad_rsa_bits instead. */
#define COMPOSITE_RSA_TRAD_BITS 3072

/* Tier — governs OID arc + wire-format contract; must never be blurred. */
enum {
    COMPOSITE_TIER_STANDARD = 0,  /* ML-DSA only; IANA/LAMPS OID; normative */
    COMPOSITE_TIER_EXPERIMENTAL   /* other PQ sig; our experimental arc */
};

/* Key material states (parallels the hybrid family's HYBRID_HAVE_*). */
enum {
    COMPOSITE_HAVE_NOKEYS = 0,
    COMPOSITE_HAVE_PUBKEY,
    COMPOSITE_HAVE_PRVKEY
};

/*
 * One composite signature combination. The combiner reads a row and delegates to
 * both components via EVP with no ML-DSA hardcoding; adding a combo (standardized
 * or experimental) is one row here — the oqs-hybrid pattern.
 */
typedef struct {
    const char *name;        /* provider algorithm name we register            */
    const char *pq_alg;      /* PQ component EVP fetch name (e.g. "ML-DSA-44")  */
    const char *trad_alg;    /* "EC" | "RSA" (PKCS#1v1.5) | "RSA-PSS" |          */
                             /* "ED25519" | "ED448"                             */
    const char *trad_group;  /* EC curve group (e.g. "P-256"), else NULL        */
    int         trad_rsa_bits;/* RSA modulus size (2048/3072/4096); 0 if not RSA */
    const char *oid;         /* composite OID (draft-19); NULL for experimental */
    const char *label;       /* domain-sep label bytes (ASCII), per draft-19    */
    const char *prehash;     /* PH(M) digest name ("SHA256"/"SHA512"/"SHAKE256")*/
    const char *trad_md;     /* traditional component's OWN hash — distinct from */
                             /* prehash (e.g. RSA3072-PSS uses SHA256 here even  */
                             /* though the label says SHA512); NULL = pure (Ed)  */
    const char *pq_priv_param;/* OSSL_PKEY param naming the PQ private material to  */
                             /* serialize. Standardized rows use the ML-DSA seed   */
                             /* (OSSL_PKEY_PARAM_ML_DSA_SEED, 32B, draft-mandated; */
                             /* the reason composite needs OpenSSL 3.5's ML-DSA    */
                             /* seed API); experimental rows use the raw private   */
                             /* key (OSSL_PKEY_PARAM_PRIV_KEY). The code never     */
                             /* assumes ML-DSA: it reads this param and discovers  */
                             /* the length from the algorithm, no hardcoded size.  */
                             /* Touches ONLY the PKCS#8 private key + interop: the */
                             /* SPKI/cert and signature are identical either way,  */
                             /* so cert size is unaffected. ML-DSA could use raw   */
                             /* too (self-consistent, and would drop the 3.5 floor)*/
                             /* but that breaks draft interop, hence seed. Mirrors */
                             /* the composite-KEM family's pq_priv_param (#34/#35).*/
    int         tier;        /* COMPOSITE_TIER_STANDARD | _EXPERIMENTAL         */
    int         tls_codepoint;/* TLS SignatureScheme code point (0 = none), the  */
                             /* single source consumed by composite_caps.c —     */
                             /* mirrors HYBRID_SIG_INFO.tls_codepoint            */
    int         security_bits;/* strength lookup (ML-DSA 44/65/87 -> 128/192/256)*/
} COMPOSITE_SIG_INFO;

/*
 * Composite key: a PQ component + a classical component, sourced by EVP.
 * pq_propq / trad_propq select the provider for each half (config-driven, see
 * composite_key_new). Parallels HYBRID_KEY: kept a distinct type because the
 * composite serialization (raw concat, ML-DSA seed) and combiner differ from the
 * hybrid concat-signature layout, so the format-specific layers are not shared.
 */
typedef struct composite_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const COMPOSITE_SIG_INFO *info;
    EVP_PKEY *pq_key;           /* PQ component (ML-DSA or research sig)        */
    EVP_PKEY *trad_key;         /* classical component (default provider)       */
    unsigned int state;         /* COMPOSITE_HAVE_*                             */
    const char *pq_propq;       /* source for the PQ component                  */
    const char *trad_propq;     /* source for the classical component          */
} COMPOSITE_KEY;

/*
 * Master composite-signature list — single source of truth (mirrors
 * HYBRID_SIG_LIST). One row per combination drives the info table, the keymgmt
 * thunks and provider registration. To add a combo, add exactly one row.
 *
 * X(cfield, name, pq_alg, trad_alg, trad_group, rsa_bits, oid, label, prehash,
 *   trad_md, pq_priv_param, tier, tls_codepoint, security_bits)
 *
 * This is the FULL draft-19 standardized composite ML-DSA matrix (18 combos,
 * OIDs 1.3.6.1.5.5.7.6.37 .. .54), each field taken verbatim from the
 * authoritative sources in lamps-wg/draft-composite-sigs at tag
 * draft-ietf-lamps-pq-composite-sigs-19:
 *   - OID + prehash (PH) + RSA size + traditional signature algorithm: src/algParams.md
 *   - label bytes: src/algParams.md "Label:" (NOT labelsTable.md, which drops the
 *     "ECDSA-" infix and is a known doc bug — see composite-sigs-labelsTable.patch)
 *   - RSA-PSS params: draft body {{rsa-pss-params2048-3072}} = SHA256/MGF1-SHA256/
 *     salt 32; {{rsa-pss-params4096}} = SHA384/MGF1-SHA384/salt 48 (salt == hash
 *     length, so trad_md fully determines them via RSA_PSS_SALTLEN_DIGEST).
 * `trad_md` is the traditional component's OWN hash, distinct from PH(M): for
 * ECDSA it is the curve-native hash (P-256/bp256 -> SHA-256, P-384/bp384 ->
 * SHA-384, P-521 -> SHA-512); for RSA-PKCS#1v1.5 it is the shaNNNWithRSAEncryption
 * hash; for RSA-PSS it is the PSS hash; NULL for the pure EdDSA combos. Every row
 * here is KAT-validated against src/testvectors.json (test/composite_kat.txt).
 * `tls_codepoint` (provisional draft-reddy-tls-composite-mldsa, TBD in IANA) is
 * the single source read by composite_caps.c, set only for the combos the TLS
 * draft enumerates and 0 otherwise; `security_bits` is the ML-DSA level's strength.
 */
#define COMPOSITE_SIG_LIST(X)                                                  \
  /* --- standardized (LAMPS Composite ML-DSA), OID order .37 .. .54 --- */    \
  X(mldsa44_rsa2048_pss, "mldsa44_rsa2048_pss", "ML-DSA-44", "RSA-PSS", NULL,  \
      2048, "1.3.6.1.5.5.7.6.37", "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",        \
      "SHA256", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 128)                  \
  X(mldsa44_rsa2048_pkcs15, "mldsa44_rsa2048_pkcs15", "ML-DSA-44", "RSA", NULL,\
      2048, "1.3.6.1.5.5.7.6.38", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",     \
      "SHA256", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 128)                  \
  X(mldsa44_ed25519, "mldsa44_ed25519", "ML-DSA-44", "ED25519", NULL,          \
      0, "1.3.6.1.5.5.7.6.39", "COMPSIG-MLDSA44-Ed25519-SHA512",               \
      "SHA512", NULL, OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 128)                      \
  X(mldsa44_ecdsa_p256, "mldsa44_ecdsa_p256", "ML-DSA-44", "EC", "P-256",      \
      0, "1.3.6.1.5.5.7.6.40", "COMPSIG-MLDSA44-ECDSA-P256-SHA256",            \
      "SHA256", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0x0907, 128)             \
  X(mldsa65_rsa3072_pss, "mldsa65_rsa3072_pss", "ML-DSA-65", "RSA-PSS", NULL,  \
      3072, "1.3.6.1.5.5.7.6.41", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",        \
      "SHA512", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0x0910, 192)             \
  X(mldsa65_rsa3072_pkcs15, "mldsa65_rsa3072_pkcs15", "ML-DSA-65", "RSA", NULL,\
      3072, "1.3.6.1.5.5.7.6.42", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",     \
      "SHA512", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_rsa4096_pss, "mldsa65_rsa4096_pss", "ML-DSA-65", "RSA-PSS", NULL,  \
      4096, "1.3.6.1.5.5.7.6.43", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",        \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_rsa4096_pkcs15, "mldsa65_rsa4096_pkcs15", "ML-DSA-65", "RSA", NULL,\
      4096, "1.3.6.1.5.5.7.6.44", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",     \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ecdsa_p256, "mldsa65_ecdsa_p256", "ML-DSA-65", "EC", "P-256",      \
      0, "1.3.6.1.5.5.7.6.45", "COMPSIG-MLDSA65-ECDSA-P256-SHA512",            \
      "SHA512", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ecdsa_p384, "mldsa65_ecdsa_p384", "ML-DSA-65", "EC", "P-384",      \
      0, "1.3.6.1.5.5.7.6.46", "COMPSIG-MLDSA65-ECDSA-P384-SHA512",            \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ecdsa_bp256, "mldsa65_ecdsa_bp256", "ML-DSA-65", "EC",             \
      "brainpoolP256r1", 0, "1.3.6.1.5.5.7.6.47",                              \
      "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",                                    \
      "SHA512", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ed25519, "mldsa65_ed25519", "ML-DSA-65", "ED25519", NULL,          \
      0, "1.3.6.1.5.5.7.6.48", "COMPSIG-MLDSA65-Ed25519-SHA512",               \
      "SHA512", NULL, OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0x090B, 192)                 \
  X(mldsa87_ecdsa_p384, "mldsa87_ecdsa_p384", "ML-DSA-87", "EC", "P-384",      \
      0, "1.3.6.1.5.5.7.6.49", "COMPSIG-MLDSA87-ECDSA-P384-SHA512",            \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0x0909, 256)             \
  X(mldsa87_ecdsa_bp384, "mldsa87_ecdsa_bp384", "ML-DSA-87", "EC",             \
      "brainpoolP384r1", 0, "1.3.6.1.5.5.7.6.50",                              \
      "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",                                    \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  X(mldsa87_ed448, "mldsa87_ed448", "ML-DSA-87", "ED448", NULL,                \
      0, "1.3.6.1.5.5.7.6.51", "COMPSIG-MLDSA87-Ed448-SHAKE256",               \
      "SHAKE256", NULL, OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0x0912, 256)               \
  X(mldsa87_rsa3072_pss, "mldsa87_rsa3072_pss", "ML-DSA-87", "RSA-PSS", NULL,  \
      3072, "1.3.6.1.5.5.7.6.52", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",        \
      "SHA512", "SHA256", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  X(mldsa87_rsa4096_pss, "mldsa87_rsa4096_pss", "ML-DSA-87", "RSA-PSS", NULL,  \
      4096, "1.3.6.1.5.5.7.6.53", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",        \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  X(mldsa87_ecdsa_p521, "mldsa87_ecdsa_p521", "ML-DSA-87", "EC", "P-521",      \
      0, "1.3.6.1.5.5.7.6.54", "COMPSIG-MLDSA87-ECDSA-P521-SHA512",            \
      "SHA512", "SHA512", OSSL_PKEY_PARAM_ML_DSA_SEED, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  /* --- experimental (non-ML-DSA PQ; DISJOINT arc; non-normative label) ---   \
   * One combo per NIST level per OQS signature family, proving the combiner is \
   * generic over the PQ component. Each PQ half is paired with a level-matched  \
   * ECDSA classical half (L1->P-256, L3->P-384, L5->P-521), mirroring the       \
   * prehash/trad_md conventions of the standardized ECDSA rows above (L1:        \
   * SHA256/SHA256; L3: SHA512/SHA384; L5: SHA512/SHA512).                        \
   *                                                                             \
   * OIDs live in a dedicated leaf of the private arc OQS uses for its own       \
   * hybrids (1.3.9999): 1.3.9999.99.<n>, clearly marked experimental so they    \
   * never collide with the OQS per-family hybrid arcs (.3/.8/.9/.10/.11) or the  \
   * LAMPS standardized composite arc. Labels are our own non-normative strings; \
   * no TLS code point (0): experimental combos are not TLS sigalgs.             \
   *                                                                             \
   * The concat serialization splits the signature at the fixed PQ length        \
   * (EVP_PKEY_get_size), so every PQ component here MUST be fixed-length: Falcon \
   * therefore uses the *padded* variants (constant-size sig); MAYO/CROSS/OV/     \
   * SNOVA/MQOM are already fixed-length. pq_priv_param = OSSL_PKEY_PARAM_PRIV_KEY:\
   * raw PQ private keys (no seed API needed).                                    */\
  /* Falcon (padded, fixed-length): L1, L5 (no L3 parameter set) */             \
  X(exp_falconpadded512_ecdsa_p256, "exp_falconpadded512_ecdsa_p256",          \
      "falconpadded512", "EC", "P-256", 0, "1.3.9999.99.1",                    \
      "COMPSIG-EXP-FALCONPADDED512-ECDSA-P256-SHA256", "SHA256", "SHA256",     \
      OSSL_PKEY_PARAM_PRIV_KEY,  \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 128)                                     \
  X(exp_falconpadded1024_ecdsa_p521, "exp_falconpadded1024_ecdsa_p521",        \
      "falconpadded1024", "EC", "P-521", 0, "1.3.9999.99.2",                   \
      "COMPSIG-EXP-FALCONPADDED1024-ECDSA-P521-SHA512", "SHA512", "SHA512",     \
      OSSL_PKEY_PARAM_PRIV_KEY, \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 256)                                     \
  /* MAYO: L1 (mayo2), L3 (mayo3), L5 (mayo5) */                               \
  X(exp_mayo2_ecdsa_p256, "exp_mayo2_ecdsa_p256", "mayo2", "EC", "P-256",      \
      0, "1.3.9999.99.3", "COMPSIG-EXP-MAYO2-ECDSA-P256-SHA256",              \
      "SHA256", "SHA256", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 128)             \
  X(exp_mayo3_ecdsa_p384, "exp_mayo3_ecdsa_p384", "mayo3", "EC", "P-384",      \
      0, "1.3.9999.99.4", "COMPSIG-EXP-MAYO3-ECDSA-P384-SHA512",              \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 192)             \
  X(exp_mayo5_ecdsa_p521, "exp_mayo5_ecdsa_p521", "mayo5", "EC", "P-521",      \
      0, "1.3.9999.99.5", "COMPSIG-EXP-MAYO5-ECDSA-P521-SHA512",              \
      "SHA512", "SHA512", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 256)             \
  /* CROSS (RSDP, category-1 balanced): only L1 built in this oqsprovider */   \
  X(exp_cross128bal_ecdsa_p256, "exp_cross128bal_ecdsa_p256",                  \
      "CROSSrsdp128balanced", "EC", "P-256", 0, "1.3.9999.99.6",              \
      "COMPSIG-EXP-CROSSR128B-ECDSA-P256-SHA256", "SHA256", "SHA256",         \
      OSSL_PKEY_PARAM_PRIV_KEY,      \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 128)                                     \
  /* UOV (OV_Is, pkc): only category-1 built in this oqsprovider */            \
  X(exp_ovIspkc_ecdsa_p256, "exp_ovIspkc_ecdsa_p256", "OV_Is_pkc", "EC",       \
      "P-256", 0, "1.3.9999.99.7", "COMPSIG-EXP-OVIS-ECDSA-P256-SHA256",      \
      "SHA256", "SHA256", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 128)             \
  /* SNOVA: L1 (24-5-4), L3 (24-5-5), L5 (29-6-5) */                          \
  X(exp_snova2454_ecdsa_p256, "exp_snova2454_ecdsa_p256", "snova2454", "EC",   \
      "P-256", 0, "1.3.9999.99.8", "COMPSIG-EXP-SNOVA2454-ECDSA-P256-SHA256", \
      "SHA256", "SHA256", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 128)             \
  X(exp_snova2455_ecdsa_p384, "exp_snova2455_ecdsa_p384", "snova2455", "EC",   \
      "P-384", 0, "1.3.9999.99.9", "COMPSIG-EXP-SNOVA2455-ECDSA-P384-SHA512", \
      "SHA512", "SHA384", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 192)             \
  X(exp_snova2965_ecdsa_p521, "exp_snova2965_ecdsa_p521", "snova2965", "EC",   \
      "P-521", 0, "1.3.9999.99.10", "COMPSIG-EXP-SNOVA2965-ECDSA-P521-SHA512",\
      "SHA512", "SHA512", OSSL_PKEY_PARAM_PRIV_KEY, COMPOSITE_TIER_EXPERIMENTAL, 0, 256)             \
  /* MQOM2 (GF16, fast, r5): L1 (cat1), L3 (cat3), L5 (cat5) */               \
  X(exp_mqom2cat1_ecdsa_p256, "exp_mqom2cat1_ecdsa_p256",                      \
      "mqom2cat1gf16fastr5", "EC", "P-256", 0, "1.3.9999.99.11",             \
      "COMPSIG-EXP-MQOM2C1-ECDSA-P256-SHA256", "SHA256", "SHA256",            \
      OSSL_PKEY_PARAM_PRIV_KEY,         \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 128)                                     \
  X(exp_mqom2cat3_ecdsa_p384, "exp_mqom2cat3_ecdsa_p384",                      \
      "mqom2cat3gf16fastr5", "EC", "P-384", 0, "1.3.9999.99.12",             \
      "COMPSIG-EXP-MQOM2C3-ECDSA-P384-SHA512", "SHA512", "SHA384",            \
      OSSL_PKEY_PARAM_PRIV_KEY,         \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 192)                                     \
  X(exp_mqom2cat5_ecdsa_p521, "exp_mqom2cat5_ecdsa_p521",                      \
      "mqom2cat5gf16fastr5", "EC", "P-521", 0, "1.3.9999.99.13",             \
      "COMPSIG-EXP-MQOM2C5-ECDSA-P521-SHA512", "SHA512", "SHA512",            \
      OSSL_PKEY_PARAM_PRIV_KEY,         \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 256)

/* Generate the info table from the master list. */
#define COMPOSITE_SIG_ROW(cf, nm, pq, tr, grp, bits, oid, lbl, ph, tmd, pqpp,  \
                          tier, cp, sb)                                        \
    { nm, pq, tr, grp, bits, oid, lbl, ph, tmd, pqpp, tier, cp, sb },
static const COMPOSITE_SIG_INFO composite_sig_table[] = {
    COMPOSITE_SIG_LIST(COMPOSITE_SIG_ROW)
};
#undef COMPOSITE_SIG_ROW

/* Per-algorithm table index, in list order (used to bind keymgmt thunks). */
#define COMPOSITE_SIG_IDX_ROW(cf, ...) COMPOSITE_SIG_IDX_##cf,
enum { COMPOSITE_SIG_LIST(COMPOSITE_SIG_IDX_ROW) COMPOSITE_SIG_ALG_COUNT_ENUM };
#undef COMPOSITE_SIG_IDX_ROW

#define COMPOSITE_SIG_ALG_COUNT \
    (sizeof(composite_sig_table) / sizeof(composite_sig_table[0]))

/* Per-algorithm keymgmt dispatch tables (composite_keymgmt.c) + the shared
 * signature dispatch (composite_sig.c), bound to names in composite_prov.c. */
#define COMPOSITE_KMGMT_EXTERN(cf, ...) \
    extern const OSSL_DISPATCH composite_##cf##_kmgmt_functions[];
COMPOSITE_SIG_LIST(COMPOSITE_KMGMT_EXTERN)
#undef COMPOSITE_KMGMT_EXTERN

extern const OSSL_DISPATCH composite_sig_functions[];

/* SubjectPublicKeyInfo encoders (composite_encoder.c). */
extern const OSSL_DISPATCH composite_spki_der_encoder_functions[];
extern const OSSL_DISPATCH composite_spki_pem_encoder_functions[];

/* SubjectPublicKeyInfo DER decoder (composite_decoder.c). */
extern const OSSL_DISPATCH composite_spki_der_decoder_functions[];

/* PrivateKeyInfo (PKCS#8) encoders + decoder. */
extern const OSSL_DISPATCH composite_pkcs8_der_encoder_functions[];
extern const OSSL_DISPATCH composite_pkcs8_pem_encoder_functions[];
extern const OSSL_DISPATCH composite_pkcs8_der_decoder_functions[];

/* Human-readable text encoder (openssl pkey -text). */
extern const OSSL_DISPATCH composite_text_encoder_functions[];

/* TLS 1.3 signature-algorithm capabilities (composite_caps.c). */
int composite_get_capabilities(void *provctx, const char *capability,
                               OSSL_CALLBACK *cb, void *arg);

/* Build the raw-concat composite public key blob: pqPub || tradPub (draft-19
 * order), component sizes fixed per OID. Caller frees *out. */
int composite_encode_pub_blob(COMPOSITE_KEY *key, unsigned char **out,
                              size_t *outlen);
/* Build the raw-concat composite private key blob: pqPriv || tradPriv (pqPriv is
 * the ML-DSA seed for standardized combos). Caller frees *out (clear). */
int composite_encode_priv_blob(COMPOSITE_KEY *key, unsigned char **out,
                               size_t *outlen);

/* Keymgmt helpers used by the decoder (composite_keymgmt.c). */
COMPOSITE_KEY *composite_keymgmt_new_by_index(void *provctx, size_t idx);
void composite_keymgmt_free(COMPOSITE_KEY *key);
/* Rebuild both public components from their raw split (pqPub then tradPub). */
int composite_key_load_pub(COMPOSITE_KEY *key,
                           const unsigned char *pqpub, size_t pqlen,
                           const unsigned char *tradpub, size_t tradlen);
/* Rebuild both private components from their raw split (pqPriv then tradPriv);
 * pqPriv is the ML-DSA seed for the standardized combos. */
int composite_key_load_prv(COMPOSITE_KEY *key,
                           const unsigned char *pqpriv, size_t pqlen,
                           const unsigned char *tradpriv, size_t tradlen);

/* --- Combiner (composite_sig.c) ---
 *
 * The cryptographic core, independent of the provider plumbing so it can be
 * unit-tested directly with EVP-generated component keys. Builds the draft-19
 * message representative M' = PREFIX || label || len(ctx) || ctx || PH(M) (empty
 * ctx), signs it with each component (PQ one-shot with context = label; classic
 * with trad_md, or pure for Ed), and concatenates PQ-sig || trad-sig. Verify
 * splits at the fixed ML-DSA signature length. *sig is malloc'd; caller frees. */
int composite_sign(const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                   OSSL_LIB_CTX *libctx, const char *pq_propq,
                   const char *trad_propq, const unsigned char *msg,
                   size_t msglen, unsigned char **sig, size_t *siglen);
int composite_verify(const COMPOSITE_SIG_INFO *info, EVP_PKEY *pq, EVP_PKEY *trad,
                     OSSL_LIB_CTX *libctx, const char *pq_propq,
                     const char *trad_propq, const unsigned char *msg,
                     size_t msglen, const unsigned char *sig, size_t siglen);

#endif /* HYBRID_COMPOSITE_PROV_H */
