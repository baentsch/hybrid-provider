/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM family — shared types + master info table. The KEM
 * analogue of composite_prov.h; a build-flag-gated capability *inside* this
 * provider (-DHYBRID_COMPOSITE), NOT a separate module.
 *
 * Construction (draft-ietf-lamps-pq-composite-kem-18, combiner stable since -14):
 *     ss = SHA3-256( mlkemSS || tradSS || tradCT || tradPK || Label )
 * One fixed KDF for every combo (always SHA3-256, always a 256-bit output); no
 * length-prefixing because each component is fixed-size per OID. This is markedly
 * simpler than the composite *signature* M' construction. `tradPK` is bound in to
 * defend against collisions when the traditional component lacks C2PRI.
 *   - mlkemSS : ML-KEM shared secret (32 bytes, both levels)
 *   - tradSS  : traditional shared secret
 *               EC/X : DH result (EC = X-coordinate Z; X25519/X448 = K per RFC 7748)
 *               RSA  : a freshly generated 32-byte value carried under RSA-OAEP
 *   - tradCT  : traditional ciphertext = the SAME encoding as the trad public key
 *               EC   : uncompressed point (leading 0x04)   [RFC 5480]
 *               X    : raw 32/56-byte value                [RFC 7748 §5]
 *               RSA  : the RSA-OAEP ciphertext (modulus length)
 *   - tradPK  : recipient's traditional public key, same encoding as tradCT
 *   - Label   : per-combo domain separator (see the master list). ASCII for most
 *               combos; the X25519 combo's label is the 6 RAW bytes 5c 2e 2f 2f
 *               5e 5c (a known draft quirk) — treated as bytes, not a mnemonic.
 * Composite serialization (raw CONCATENATION, PQ first, like the sig family):
 *     pubkey     = mlkemPK || tradPK
 *     privkey    = mlkemSK || tradSK
 *     ciphertext = mlkemCT || tradCT
 *
 * Standardized only (no experimental tier): every combo pairs ML-KEM with a
 * classical KEM on the IANA/LAMPS OID arc 1.3.6.1.5.5.7.6.55 .. .66. Ceded to the
 * default provider if OpenSSL ships native composite ML-KEM, exactly like MLX.
 */
#ifndef HYBRID_COMPOSITE_KEM_PROV_H
#define HYBRID_COMPOSITE_KEM_PROV_H

#include <openssl/types.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>   /* OSSL_PKEY_PARAM_* used in the master list */
#include <stddef.h>
#include "hybrid_prov.h"   /* composite is a capability OF the hybrid provider;
                            * it shares HYBRID_PROV_CTX (libctx + BIO up-calls). */

/* Composite ss and the ML-KEM component ss are both 256-bit (draft-18 §3.2/§3.4);
 * RSA-OAEP also carries a 32-byte tradSS "at all security levels". */
#define COMPOSITE_KEM_SS_BYTES  32

/* RSA-OAEP parameters for the RSA combos (draft-18 §6.1 Table 2): SHA-256 hash,
 * MGF1-SHA-256, empty pSource. Shared by all three RSA levels. */
#define COMPOSITE_KEM_RSA_OAEP_MD  "SHA2-256"

/* Key material states (parallels the composite-sig family's COMPOSITE_HAVE_*). */
enum {
    COMPOSITE_KEM_HAVE_NOKEYS = 0,
    COMPOSITE_KEM_HAVE_PUBKEY,
    COMPOSITE_KEM_HAVE_PRVKEY
};

/*
 * One composite ML-KEM combination. The combiner reads a row and delegates to
 * both components via EVP with no ML-KEM hardcoding; adding a combo is one row.
 */
typedef struct {
    const char *name;        /* provider algorithm name we register             */
    const char *pq_alg;      /* ML-KEM EVP fetch name ("ML-KEM-768"/"ML-KEM-1024")*/
    const char *trad_alg;    /* "EC" | "X25519" | "X448" | "RSA-OAEP"            */
    const char *trad_group;  /* EC curve group (e.g. "P-256"), else NULL         */
    int         trad_rsa_bits;/* RSA modulus size (2048/3072/4096); 0 if not RSA */
    const char *oid;         /* composite OID (draft-18)                         */
    const char *label;       /* combiner domain-separator bytes (no embedded NUL,*/
                             /* so strlen() gives the length — true even for the */
                             /* X25519 raw-byte label 5c 2e 2f 2f 5e 5c)         */
    int         security_bits;/* ML-KEM level strength (768 -> 192, 1024 -> 256) */
    const char *pq_priv_param;/* OSSL_PKEY param naming the PQ private material to  */
                             /* serialize. Standardized rows use the ML-KEM seed   */
                             /* (OSSL_PKEY_PARAM_ML_KEM_SEED); a future seed-based  */
                             /* KEM would name ITS OWN seed param, and a raw-private*/
                             /* KEM (Frodo/BIKE/HQC) OSSL_PKEY_PARAM_PRIV_KEY. The  */
                             /* code never assumes ML-KEM: it reads this param and  */
                             /* discovers the length from the algorithm, with no    */
                             /* hardcoded seed size. Generalizes the sig family's   */
                             /* boolean pq_priv_seed.                               */
} COMPOSITE_KEM_INFO;

/*
 * Composite ML-KEM key: an ML-KEM component + a classical component, sourced by
 * EVP. Parallels COMPOSITE_KEY (the sig family); a distinct type because the
 * component algorithms and the KEM operation differ.
 */
typedef struct composite_kem_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const COMPOSITE_KEM_INFO *info;
    EVP_PKEY *pq_key;           /* ML-KEM component                             */
    EVP_PKEY *trad_key;         /* classical component (EC / X / RSA)           */
    unsigned int state;         /* COMPOSITE_KEM_HAVE_*                         */
    const char *pq_propq;       /* source for the ML-KEM component              */
    const char *trad_propq;     /* source for the classical component          */
} COMPOSITE_KEM_KEY;

/*
 * Master composite-ML-KEM list — single source of truth (mirrors
 * COMPOSITE_SIG_LIST). One row per combination. To add a combo, add one row.
 *
 * X(cfield, name, pq_alg, trad_alg, trad_group, rsa_bits, oid, label, secbits,
 *   pq_priv_param)
 *
 * All standardized rows name the ML-KEM seed param (PQ private = ML-KEM seed, per
 * the draft). A future experimental row would name a different seed param (for a
 * seed-based non-ML-KEM KEM) or OSSL_PKEY_PARAM_PRIV_KEY (for a raw-private KEM
 * such as Frodo/BIKE/HQC), exactly like the experimental composite-signature tier.
 *
 * The FULL draft-18 standardized matrix (12 combos, OIDs 1.3.6.1.5.5.7.6.55 .. .66),
 * each field taken from lamps-wg/draft-composite-kem src/algParams.md and the
 * draft §6.1 parameter table. Labels are verbatim; the X25519 label is the raw
 * 6-byte value, written as separate \x escapes so the compiler does not fold it
 * into one over-long hex escape.
 */
#define COMPOSITE_KEM_OID(n)  "1.3.6.1.5.5.7.6." #n

#define COMPOSITE_KEM_LIST(X)                                                  \
  X(mlkem768_rsa2048, "mlkem768_rsa2048", "ML-KEM-768", "RSA-OAEP", NULL,      \
      2048, COMPOSITE_KEM_OID(55), "MLKEM768-RSAOAEP2048", 192,                \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem768_rsa3072, "mlkem768_rsa3072", "ML-KEM-768", "RSA-OAEP", NULL,      \
      3072, COMPOSITE_KEM_OID(56), "MLKEM768-RSAOAEP3072", 192,                \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem768_rsa4096, "mlkem768_rsa4096", "ML-KEM-768", "RSA-OAEP", NULL,      \
      4096, COMPOSITE_KEM_OID(57), "MLKEM768-RSAOAEP4096", 192,                \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem768_x25519, "mlkem768_x25519", "ML-KEM-768", "X25519", NULL,          \
      0, COMPOSITE_KEM_OID(58), "\x5c\x2e\x2f\x2f\x5e\x5c", 192,               \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem768_p256, "mlkem768_p256", "ML-KEM-768", "EC", "P-256",               \
      0, COMPOSITE_KEM_OID(59), "MLKEM768-P256", 192,                          \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem768_p384, "mlkem768_p384", "ML-KEM-768", "EC", "P-384",               \
      0, COMPOSITE_KEM_OID(60), "MLKEM768-P384", 192,                          \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem768_bp256, "mlkem768_bp256", "ML-KEM-768", "EC", "brainpoolP256r1",   \
      0, COMPOSITE_KEM_OID(61), "MLKEM768-BP256", 192,                         \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem1024_rsa3072, "mlkem1024_rsa3072", "ML-KEM-1024", "RSA-OAEP", NULL,   \
      3072, COMPOSITE_KEM_OID(62), "MLKEM1024-RSAOAEP3072", 256,               \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem1024_p384, "mlkem1024_p384", "ML-KEM-1024", "EC", "P-384",            \
      0, COMPOSITE_KEM_OID(63), "MLKEM1024-P384", 256,                         \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem1024_bp384, "mlkem1024_bp384", "ML-KEM-1024", "EC", "brainpoolP384r1",\
      0, COMPOSITE_KEM_OID(64), "MLKEM1024-BP384", 256,                        \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem1024_x448, "mlkem1024_x448", "ML-KEM-1024", "X448", NULL,             \
      0, COMPOSITE_KEM_OID(65), "MLKEM1024-X448", 256,                         \
      OSSL_PKEY_PARAM_ML_KEM_SEED)                                             \
  X(mlkem1024_p521, "mlkem1024_p521", "ML-KEM-1024", "EC", "P-521",            \
      0, COMPOSITE_KEM_OID(66), "MLKEM1024-P521", 256,                         \
      OSSL_PKEY_PARAM_ML_KEM_SEED)

/* Generate the info table from the master list. */
#define COMPOSITE_KEM_ROW(cf, nm, pq, tr, grp, bits, oid, lbl, sb, pqpp)       \
    { nm, pq, tr, grp, bits, oid, lbl, sb, pqpp },
static const COMPOSITE_KEM_INFO composite_kem_table[] = {
    COMPOSITE_KEM_LIST(COMPOSITE_KEM_ROW)
};
#undef COMPOSITE_KEM_ROW

/* Per-algorithm table index, in list order (used to bind keymgmt thunks). */
#define COMPOSITE_KEM_IDX_ROW(cf, ...) COMPOSITE_KEM_IDX_##cf,
enum { COMPOSITE_KEM_LIST(COMPOSITE_KEM_IDX_ROW) COMPOSITE_KEM_ALG_COUNT_ENUM };
#undef COMPOSITE_KEM_IDX_ROW

#define COMPOSITE_KEM_ALG_COUNT \
    (sizeof(composite_kem_table) / sizeof(composite_kem_table[0]))

/* --- Combiner + component KEM ops (composite_kem.c) ---
 *
 * The cryptographic core, independent of provider plumbing so it can be unit-
 * tested directly with EVP-generated component keys (test/composite_kem_test.c).
 */

/* ss_out (COMPOSITE_KEM_SS_BYTES) = SHA3-256(mlkemSS||tradSS||tradCT||tradPK||label). */
int composite_kem_combine(OSSL_LIB_CTX *libctx,
                          const unsigned char *mlkemss, size_t mlkemsslen,
                          const unsigned char *tradss, size_t tradsslen,
                          const unsigned char *tradct, size_t tradctlen,
                          const unsigned char *tradpk, size_t tradpklen,
                          const unsigned char *label, size_t labellen,
                          unsigned char *ss_out);

/* Encapsulate to (pq_pub, trad_pub): composite ct = mlkemCT||tradCT, ss via the
 * combiner. *ct and *ss are malloc'd; caller frees (*ss with clear). */
int composite_kem_encaps(const COMPOSITE_KEM_INFO *info,
                         EVP_PKEY *pq_pub, EVP_PKEY *trad_pub,
                         OSSL_LIB_CTX *libctx, const char *pq_propq,
                         const char *trad_propq,
                         unsigned char **ct, size_t *ctlen,
                         unsigned char **ss, size_t *sslen);

/* Decapsulate composite ct with (pq_priv, trad_priv); recompute ss. *ss malloc'd. */
int composite_kem_decaps(const COMPOSITE_KEM_INFO *info,
                         EVP_PKEY *pq_priv, EVP_PKEY *trad_priv,
                         OSSL_LIB_CTX *libctx, const char *pq_propq,
                         const char *trad_propq,
                         const unsigned char *ct, size_t ctlen,
                         unsigned char **ss, size_t *sslen);

/* Provider KEM dispatch (wraps the combiner over a COMPOSITE_KEM_KEY). */
extern const OSSL_DISPATCH composite_kem_functions[];

/* The PQ private split length is discovered at runtime from the component
 * algorithm (info->pq_priv_param on a fresh key) — no hardcoded seed size, so a
 * non-ML-KEM PQ component with a different seed / raw-private length works. */

/* --- keymgmt (composite_kem_keymgmt.c) --- */
/* Build the raw-concat public blob mlkemPK||tradPK (draft-18 order). Caller frees. */
int composite_kem_encode_pub_blob(COMPOSITE_KEM_KEY *key, unsigned char **out,
                                  size_t *outlen);
/* Build the raw-concat private blob mlkemSeed||tradSK. Caller frees (clear). */
int composite_kem_encode_priv_blob(COMPOSITE_KEM_KEY *key, unsigned char **out,
                                   size_t *outlen);
/* Decoder support. */
COMPOSITE_KEM_KEY *composite_kem_keymgmt_new_by_index(void *provctx, size_t idx);
void composite_kem_keymgmt_free(COMPOSITE_KEM_KEY *key);
/* Rebuild both public components from the raw split (mlkemPK then tradPK). */
int composite_kem_key_load_pub(COMPOSITE_KEM_KEY *key,
                               const unsigned char *pqpub, size_t pqlen,
                               const unsigned char *tradpub, size_t tradlen);
/* Rebuild both private components (mlkemSeed then tradSK). */
int composite_kem_key_load_prv(COMPOSITE_KEM_KEY *key,
                               const unsigned char *pqpriv, size_t pqlen,
                               const unsigned char *tradpriv, size_t tradlen);

/* Per-algorithm keymgmt dispatch tables (composite_kem_keymgmt.c). */
#define COMPOSITE_KEM_KMGMT_EXTERN(cf, ...) \
    extern const OSSL_DISPATCH composite_##cf##_kem_kmgmt_functions[];
COMPOSITE_KEM_LIST(COMPOSITE_KEM_KMGMT_EXTERN)
#undef COMPOSITE_KEM_KMGMT_EXTERN

/* SPKI + PKCS#8 encoders and decoders (composite_kem_encoder.c / _decoder.c). */
extern const OSSL_DISPATCH composite_kem_spki_der_encoder_functions[];
extern const OSSL_DISPATCH composite_kem_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH composite_kem_pkcs8_der_encoder_functions[];
extern const OSSL_DISPATCH composite_kem_pkcs8_pem_encoder_functions[];
extern const OSSL_DISPATCH composite_kem_text_encoder_functions[];
extern const OSSL_DISPATCH composite_kem_spki_der_decoder_functions[];
extern const OSSL_DISPATCH composite_kem_pkcs8_der_decoder_functions[];

#endif /* HYBRID_COMPOSITE_KEM_PROV_H */
