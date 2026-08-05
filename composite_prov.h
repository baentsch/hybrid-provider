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
#include <stddef.h>
#include "hybrid_prov.h"   /* composite is a capability OF the hybrid provider;
                            * it shares HYBRID_PROV_CTX (libctx + BIO up-calls). */

/* Whole-scheme domain separator (fixed ASCII, draft-19). Shared by every combo,
 * standardized and experimental; the per-combo `label` differentiates them. */
#define COMPOSITE_SIG_PREFIX "CompositeAlgorithmSignatures2025"

/* ML-DSA private key is serialized as its 32-byte seed (draft-19, all levels). */
#define COMPOSITE_MLDSA_SEED_BYTES 32

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
    int         pq_priv_seed;/* 1: PQ priv serialized as seed (ML-DSA 32B); 0 raw*/
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
 *   trad_md, pq_priv_seed, tier, tls_codepoint, security_bits)
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
      "SHA256", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0, 128)                  \
  X(mldsa44_rsa2048_pkcs15, "mldsa44_rsa2048_pkcs15", "ML-DSA-44", "RSA", NULL,\
      2048, "1.3.6.1.5.5.7.6.38", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",     \
      "SHA256", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0, 128)                  \
  X(mldsa44_ed25519, "mldsa44_ed25519", "ML-DSA-44", "ED25519", NULL,          \
      0, "1.3.6.1.5.5.7.6.39", "COMPSIG-MLDSA44-Ed25519-SHA512",               \
      "SHA512", NULL, 1, COMPOSITE_TIER_STANDARD, 0, 128)                      \
  X(mldsa44_ecdsa_p256, "mldsa44_ecdsa_p256", "ML-DSA-44", "EC", "P-256",      \
      0, "1.3.6.1.5.5.7.6.40", "COMPSIG-MLDSA44-ECDSA-P256-SHA256",            \
      "SHA256", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0x0907, 128)             \
  X(mldsa65_rsa3072_pss, "mldsa65_rsa3072_pss", "ML-DSA-65", "RSA-PSS", NULL,  \
      3072, "1.3.6.1.5.5.7.6.41", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",        \
      "SHA512", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0x0910, 192)             \
  X(mldsa65_rsa3072_pkcs15, "mldsa65_rsa3072_pkcs15", "ML-DSA-65", "RSA", NULL,\
      3072, "1.3.6.1.5.5.7.6.42", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",     \
      "SHA512", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_rsa4096_pss, "mldsa65_rsa4096_pss", "ML-DSA-65", "RSA-PSS", NULL,  \
      4096, "1.3.6.1.5.5.7.6.43", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",        \
      "SHA512", "SHA384", 1, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_rsa4096_pkcs15, "mldsa65_rsa4096_pkcs15", "ML-DSA-65", "RSA", NULL,\
      4096, "1.3.6.1.5.5.7.6.44", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",     \
      "SHA512", "SHA384", 1, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ecdsa_p256, "mldsa65_ecdsa_p256", "ML-DSA-65", "EC", "P-256",      \
      0, "1.3.6.1.5.5.7.6.45", "COMPSIG-MLDSA65-ECDSA-P256-SHA512",            \
      "SHA512", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ecdsa_p384, "mldsa65_ecdsa_p384", "ML-DSA-65", "EC", "P-384",      \
      0, "1.3.6.1.5.5.7.6.46", "COMPSIG-MLDSA65-ECDSA-P384-SHA512",            \
      "SHA512", "SHA384", 1, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ecdsa_bp256, "mldsa65_ecdsa_bp256", "ML-DSA-65", "EC",             \
      "brainpoolP256r1", 0, "1.3.6.1.5.5.7.6.47",                              \
      "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",                                    \
      "SHA512", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0, 192)                  \
  X(mldsa65_ed25519, "mldsa65_ed25519", "ML-DSA-65", "ED25519", NULL,          \
      0, "1.3.6.1.5.5.7.6.48", "COMPSIG-MLDSA65-Ed25519-SHA512",               \
      "SHA512", NULL, 1, COMPOSITE_TIER_STANDARD, 0x090B, 192)                 \
  X(mldsa87_ecdsa_p384, "mldsa87_ecdsa_p384", "ML-DSA-87", "EC", "P-384",      \
      0, "1.3.6.1.5.5.7.6.49", "COMPSIG-MLDSA87-ECDSA-P384-SHA512",            \
      "SHA512", "SHA384", 1, COMPOSITE_TIER_STANDARD, 0x0909, 256)             \
  X(mldsa87_ecdsa_bp384, "mldsa87_ecdsa_bp384", "ML-DSA-87", "EC",             \
      "brainpoolP384r1", 0, "1.3.6.1.5.5.7.6.50",                              \
      "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",                                    \
      "SHA512", "SHA384", 1, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  X(mldsa87_ed448, "mldsa87_ed448", "ML-DSA-87", "ED448", NULL,                \
      0, "1.3.6.1.5.5.7.6.51", "COMPSIG-MLDSA87-Ed448-SHAKE256",               \
      "SHAKE256", NULL, 1, COMPOSITE_TIER_STANDARD, 0x0912, 256)               \
  X(mldsa87_rsa3072_pss, "mldsa87_rsa3072_pss", "ML-DSA-87", "RSA-PSS", NULL,  \
      3072, "1.3.6.1.5.5.7.6.52", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",        \
      "SHA512", "SHA256", 1, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  X(mldsa87_rsa4096_pss, "mldsa87_rsa4096_pss", "ML-DSA-87", "RSA-PSS", NULL,  \
      4096, "1.3.6.1.5.5.7.6.53", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",        \
      "SHA512", "SHA384", 1, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  X(mldsa87_ecdsa_p521, "mldsa87_ecdsa_p521", "ML-DSA-87", "EC", "P-521",      \
      0, "1.3.6.1.5.5.7.6.54", "COMPSIG-MLDSA87-ECDSA-P521-SHA512",            \
      "SHA512", "SHA512", 1, COMPOSITE_TIER_STANDARD, 0, 256)                  \
  /* --- experimental (non-ML-DSA PQ; DISJOINT arc; non-normative label) ---   \
   * Illustrative single row — proves the family is generic over the PQ         \
   * component. No TLS code point (0): experimental combos are not TLS sigalgs.*/\
  X(exp_mayo2_ecdsa_p256, "exp_mayo2_ecdsa_p256", "mayo2", "EC", "P-256",      \
      0, NULL, "COMPSIG-EXP-MAYO2-ECDSA-P256-SHA256", "SHA256", "SHA256", 0,   \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 128)

/* Generate the info table from the master list. */
#define COMPOSITE_SIG_ROW(cf, nm, pq, tr, grp, bits, oid, lbl, ph, tmd, seed,  \
                          tier, cp, sb)                                        \
    { nm, pq, tr, grp, bits, oid, lbl, ph, tmd, seed, tier, cp, sb },
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
