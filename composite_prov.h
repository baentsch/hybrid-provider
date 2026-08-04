/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) signature family — shared types + master info table.
 *
 * SCAFFOLD (issue #6): this header fixes the *shape* of the composite family;
 * the keymgmt/sig/encoder/decoder .c files follow. Composite is a build-flag-
 * gated capability *inside this provider* (default off), NOT a separate module —
 * see redesign.md "Phase 2 — Composite (LAMPS), later".
 *
 * Construction (draft-ietf-lamps-pq-composite-sigs-19 — verify verbatim before
 * the combiner lands):
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
 * in a table row, so the family can span research PQ sigs (experimental tier),
 * mirroring the oqs-hybrid matrix. Two tiers, never blurred:
 *   - standardized : PQ = ML-DSA only, IANA/LAMPS OID arc, byte-exact vs Bouncy
 *                    Castle / future OpenSSL-native composite. Ceded to default
 *                    once OpenSSL ships it (openssl#26121), like MLX today.
 *   - experimental : any other PQ sig, DISJOINT experimental OID arc, non-
 *                    normative labels, interop only with ourselves / oqsprovider.
 *
 * OPEN (see redesign.md Phase-2 open items): the `oid` values are left NULL until
 * enumerated from the draft-19 IANA registry (standardized) and the chosen
 * experimental arc (matching oqsprovider main if it defines composite combos).
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

/* The traditional RSA component in the standardized RSA-PSS combo is RSA-3072
 * (draft-19 "RSA3072"). Shared by keymgmt keygen and the tests. */
#define COMPOSITE_RSA_TRAD_BITS 3072

/* ML-DSA private key is serialized as its 32-byte seed (draft-19, all levels). */
#define COMPOSITE_MLDSA_SEED_BYTES 32

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
    const char *trad_alg;    /* "EC" | "RSA" | "RSA-PSS" | "ED25519" | "ED448"  */
    const char *trad_group;  /* EC curve group (e.g. "P-256"), else NULL        */
    const char *oid;         /* composite OID; NULL until filled (see header)   */
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
 * pq_propq steers the PQ component to {oqsprovider|default}; classical is always
 * the default provider. Parallels HYBRID_KEY (duplicated per #6's "no shared
 * combiner abstraction" — clarity over reuse for the format-specific layers).
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
 * X(cfield, name, pq_alg, trad_alg, trad_group, oid, label, prehash, trad_md,
 *   pq_priv_seed, tier, tls_codepoint, security_bits)
 *
 * oid/label/prehash/trad_md are the draft-19 values from src/algParams.md; every
 * standardized row is verified against the draft's reference signatures by
 * test/composite_kat_test. The `tls_codepoint` values are provisional
 * (draft-reddy-tls-composite-mldsa, still TBD in IANA) and are the single source
 * read by composite_caps.c; `security_bits` is the ML-DSA level's strength. This
 * is a representative starter set; the full standardized matrix (ML-DSA x
 * {RSA-PSS, RSA-PKCS1.5, ECDSA-P256/P384/P521/brainpool, Ed25519, Ed448}) is
 * filled the same way. The experimental row keeps oid = NULL (disjoint arc).
 */
#define COMPOSITE_SIG_LIST(X)                                                  \
  /* --- standardized (LAMPS Composite ML-DSA) --- */                         \
  X(mldsa44_ecdsa_p256, "mldsa44_ecdsa_p256", "ML-DSA-44", "EC", "P-256",     \
      "1.3.6.1.5.5.7.6.40", "COMPSIG-MLDSA44-ECDSA-P256-SHA256",             \
      "SHA256", "SHA256", 1,                                                   \
      COMPOSITE_TIER_STANDARD, 0x0907, 128)                                    \
  X(mldsa65_rsa3072_pss, "mldsa65_rsa3072_pss", "ML-DSA-65", "RSA-PSS", NULL, \
      "1.3.6.1.5.5.7.6.41", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",            \
      "SHA512", "SHA256", 1,                                                   \
      COMPOSITE_TIER_STANDARD, 0x0910, 192)                                    \
  X(mldsa65_ed25519, "mldsa65_ed25519", "ML-DSA-65", "ED25519", NULL,         \
      "1.3.6.1.5.5.7.6.48", "COMPSIG-MLDSA65-Ed25519-SHA512",                \
      "SHA512", NULL, 1,                                                       \
      COMPOSITE_TIER_STANDARD, 0x090B, 192)                                    \
  X(mldsa87_ecdsa_p384, "mldsa87_ecdsa_p384", "ML-DSA-87", "EC", "P-384",     \
      /* trad_md is the curve-native ECDSA hash (P-384 -> SHA-384), NOT the    \
       * SHA-512 in the name (that is only PH(M)); the label keeps the "ECDSA-"\
       * infix (algParams.md), which labelsTable.md drops. */                  \
      "1.3.6.1.5.5.7.6.49", "COMPSIG-MLDSA87-ECDSA-P384-SHA512",              \
      "SHA512", "SHA384", 1,                                                   \
      COMPOSITE_TIER_STANDARD, 0x0909, 256)                                    \
  X(mldsa87_ed448, "mldsa87_ed448", "ML-DSA-87", "ED448", NULL,               \
      "1.3.6.1.5.5.7.6.51", "COMPSIG-MLDSA87-Ed448-SHAKE256",                \
      "SHAKE256", NULL, 1,                                                     \
      COMPOSITE_TIER_STANDARD, 0x0912, 256)                                    \
  /* --- experimental (non-ML-DSA PQ; DISJOINT arc; non-normative label) ---  \
   * Illustrative single row — proves the family is generic over the PQ        \
   * component. Extend with research sigs (Falcon/MAYO/SLH-DSA/on-ramp) as     \
   * needed. No TLS code point (0): experimental combos are not TLS sigalgs. */\
  X(exp_mayo2_ecdsa_p256, "exp_mayo2_ecdsa_p256", "mayo2", "EC", "P-256",     \
      NULL, "COMPSIG-EXP-MAYO2-ECDSA-P256-SHA256", "SHA256", "SHA256", 0,     \
      COMPOSITE_TIER_EXPERIMENTAL, 0, 128)

/* Generate the info table from the master list. */
#define COMPOSITE_SIG_ROW(cf, nm, pq, tr, grp, oid, lbl, ph, tmd, seed, tier,  \
                          cp, sb)                                              \
    { nm, pq, tr, grp, oid, lbl, ph, tmd, seed, tier, cp, sb },
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
