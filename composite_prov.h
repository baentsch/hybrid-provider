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
#include <stddef.h>

/* Whole-scheme domain separator (fixed ASCII, draft-19). Shared by every combo,
 * standardized and experimental; the per-combo `label` differentiates them. */
#define COMPOSITE_SIG_PREFIX "CompositeAlgorithmSignatures2025"

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
    int         pq_priv_seed;/* 1: PQ priv serialized as seed (ML-DSA 32B); 0 raw*/
    int         tier;        /* COMPOSITE_TIER_STANDARD | _EXPERIMENTAL         */
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
 * X(cfield, name, pq_alg, trad_alg, trad_group, oid, label, prehash,
 *   pq_priv_seed, tier)
 *
 * Labels/prehash for the standardized rows are the draft-19 normative constants;
 * OIDs are NULL pending the registry (see header). This is a representative
 * starter set — the full standardized matrix (ML-DSA x {RSA-PSS, RSA-PKCS1.5,
 * ECDSA-P256/P384/P521/brainpool, Ed25519, Ed448}) is filled alongside the OIDs.
 */
#define COMPOSITE_SIG_LIST(X)                                                  \
  /* --- standardized (LAMPS Composite ML-DSA) --- */                         \
  X(mldsa44_ecdsa_p256, "mldsa44_ecdsa_p256", "ML-DSA-44", "EC", "P-256",     \
      NULL, "COMPSIG-MLDSA44-ECDSA-P256-SHA256", "SHA256", 1,                 \
      COMPOSITE_TIER_STANDARD)                                                 \
  X(mldsa65_rsa3072_pss, "mldsa65_rsa3072_pss", "ML-DSA-65", "RSA-PSS", NULL, \
      NULL, "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", "SHA512", 1,                \
      COMPOSITE_TIER_STANDARD)                                                 \
  X(mldsa65_ed25519, "mldsa65_ed25519", "ML-DSA-65", "ED25519", NULL,         \
      NULL, "COMPSIG-MLDSA65-Ed25519-SHA512", "SHA512", 1,                    \
      COMPOSITE_TIER_STANDARD)                                                 \
  X(mldsa87_ecdsa_p384, "mldsa87_ecdsa_p384", "ML-DSA-87", "EC", "P-384",     \
      NULL, "COMPSIG-MLDSA87-ECDSA-P384-SHA512", "SHA512", 1,                 \
      COMPOSITE_TIER_STANDARD)                                                 \
  X(mldsa87_ed448, "mldsa87_ed448", "ML-DSA-87", "ED448", NULL,               \
      NULL, "COMPSIG-MLDSA87-Ed448-SHAKE256", "SHAKE256", 1,                  \
      COMPOSITE_TIER_STANDARD)                                                 \
  /* --- experimental (non-ML-DSA PQ; DISJOINT arc; non-normative label) ---  \
   * Illustrative single row — proves the family is generic over the PQ        \
   * component. Extend with research sigs (Falcon/MAYO/SLH-DSA/on-ramp) as     \
   * needed; sourced from oqsprovider via pq_propq. */                        \
  X(exp_mayo2_ecdsa_p256, "exp_mayo2_ecdsa_p256", "mayo2", "EC", "P-256",     \
      NULL, "COMPSIG-EXP-MAYO2-ECDSA-P256-SHA256", "SHA256", 0,               \
      COMPOSITE_TIER_EXPERIMENTAL)

/* Generate the info table from the master list. */
#define COMPOSITE_SIG_ROW(cf, nm, pq, tr, grp, oid, lbl, ph, seed, tier)      \
    { nm, pq, tr, grp, oid, lbl, ph, seed, tier },
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

#endif /* HYBRID_COMPOSITE_PROV_H */
