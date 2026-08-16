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
/*
 * Cede-to-default lever. Some of this provider's algorithms are also provided
 * by OpenSSL's default provider; re-implementing them exists only so the two
 * can be compared for interoperability, and in real operation duplicating them
 * is pointless. So by DEFAULT the provider withdraws every algorithm the
 * default provider already serves in the same library context — from the query
 * tables and the TLS capabilities alike — leaving only what the default
 * provider lacks. Detection is by any of the identifiers the default provider
 * may share with us: algorithm name, TLS code point, or OID (see
 * hybrid_apply_cede). It is intentionally open-ended: it covers whatever the
 * default provider serves today (the standardized hybrid KEM groups) and
 * whatever it may serve in future (e.g. native composite signatures), with no
 * per-algorithm list to maintain here.
 *
 * The behaviour is switchable off (needed for the interoperability tests, which
 * deliberately load both providers and compare the two implementations of the
 * same identifier): set the config-section key "cede-to-default = no" or the
 * environment variable HYBRID_CEDE_TO_DEFAULT=0. The env var, when set, takes
 * precedence over the config key. Accepted booleans: 1/0, yes/no, on/off,
 * true/false.
 */
#define HYBRID_CONF_CEDE_TO_DEFAULT     "cede-to-default"
#define HYBRID_ENV_CEDE_TO_DEFAULT      "HYBRID_CEDE_TO_DEFAULT"

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
    /* Core BIO up-calls, captured from the core dispatch (en/decoders). */
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex;
    /*
     * Per-instance cede-to-default state, computed once at init from this
     * instance's libctx + cede lever and IMMUTABLE thereafter (see
     * hybrid_prov.c). Because it is fully built before *provctx is handed back
     * — and torn down only after the instance is no longer queryable — the read
     * paths (hybrid_query, hybrid_is_ceded) need no lock. `ceded` holds the
     * withdrawn algorithm names (borrowed static-lifetime table pointers) and
     * the *_rt arrays are heap copies of the static query tables with the ceded
     * rows removed. filter_enabled == 0 means nothing was withdrawn and the
     * static tables are served directly. All owned here, freed at teardown.
     */
    const char **ceded;
    size_t n_ceded;
    int filter_enabled;
    OSSL_ALGORITHM *keymgmts_rt, *kems_rt, *signatures_rt,
        *encoders_rt, *decoders_rt;
} HYBRID_PROV_CTX;

/*
 * True if `name` is an algorithm this instance withdrew because the default
 * provider already serves it (cede-to-default; see hybrid_prov.c). Consulted by
 * the capability advertisers (hybrid_caps.c, composite_caps.c) so their output
 * matches the withdrawn query tables. The ceded set is per-provctx (immutable
 * after init), so this is lock-free. `provctx` may be NULL (treated as "nothing
 * ceded"), matching a provider with no cede state.
 */
int hybrid_is_ceded(void *provctx, const char *name);

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
    const char *oid;            /* X.509 OID, or NULL if not key-file encodable
                                 * (mirrors oqsprovider: most hybrid KEMs NULL) */
    /* Component sizes are constants in hybrid_kem_sizes[]; see HYBRID_SIZES. */
} HYBRID_KEM_INFO;

/*
 * Signature component info. Sizes are constants (hybrid_sig_sizes[]); the table
 * carries only identity + the parameters that define oqsprovider's hybrid-sig
 * wire format:
 *   - nist_level: NIST level of the PQ component, which selects the digest the
 *     classical component signs (1 -> SHA-256, 2/3 -> SHA-384, 4/5 -> SHA-512).
 *   - alg1 is always ECDSA ("EC" + group) or "RSA" (3072-bit); no EdDSA.
 * Signature layout: ENCODE_UINT32(classical_len) || classical_sig || pq_sig.
 */
typedef struct {
    const char *hybrid_name;    /* e.g., "p256_mldsa44" */
    const char *alg1_name;      /* "EC" or "RSA" */
    const char *alg1_group;     /* EC group (e.g. "P-256"), or NULL for RSA */
    const char *alg2_name;      /* PQ, e.g. "MLDSA44" */
    int         nist_level;     /* PQ NIST level -> classical digest choice */
    const char *oid;            /* X.509 OID (used by M2 encoders/decoders) */
    int         tls_codepoint;  /* TLS SignatureScheme code point (0 if none) */
} HYBRID_SIG_INFO;

/*
 * Per-component sizes for a hybrid. These are fixed per algorithm (pinned by the
 * component names, which the hybrid name selects), so they are compile-time
 * CONSTANTS held in hybrid_kem_sizes[] / hybrid_sig_sizes[] below; each key just
 * points at its variant's row (HYBRID_KEY.sizes) — never computed at runtime, so
 * there is no shared mutable size cache to synchronize. The values are
 * machine-generated (see test/hybrid_sizes_test.c, which regenerates and, in CI,
 * re-derives them from live component keygens and fails on any drift). `ct` is
 * the ciphertext
 * contribution (ephemeral public-key length for a key-exchange component, KEM
 * ciphertext otherwise); `a1_prv`/`a2_prv` follow the same convention the
 * discovery used (RSA/EC private reported as the scalar/modulus byte width, not
 * the variable DER length, which the encoders length-prefix instead).
 */
typedef struct {
    size_t a1_pub, a1_prv, a1_ss, a1_ct;   /* classical (alg1); KEM: ss/ct */
    size_t a2_pub, a2_prv, a2_ss, a2_ct;   /* PQ (alg2); KEM: ss/ct */
    size_t a1_sig, a2_sig;                 /* SIG only: max signature sizes */
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
    const HYBRID_SIZES *sizes;  /* -> this variant's row in the constant size
                                 * table (hybrid_kem_sizes[]/hybrid_sig_sizes[]);
                                 * borrowed, static-lifetime, not freed here */
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
 * Component sizes are NOT listed in this identity row — they live as constants
 * in hybrid_kem_sizes[] below (machine-generated, CI-verified), so a new hybrid
 * needs only its component names, EC group and slot here.
 *
 * X(cfield, name, alg1, alg1_group, alg1_is_kem, alg2, slot,
 *   tls_codepoint, secbits, desc, oid)
 *
 * PROVENANCE — the `tls_codepoint` and `oid` values are copied from their
 * origins and must stay in sync with them:
 *   - MLX names (X25519MLKEM768, …): code points are IETF
 *     draft-ietf-tls-ecdhe-mlkem, implemented by OpenSSL's default provider.
 *     These groups have no key-file encoders anywhere, hence oid = NULL.
 *   - OQS-legacy names: code points and OIDs are oqsprovider's, defined in its
 *     `oqs-template/generate.yml` (see ALGORITHMS.md). Most hybrid KEMs have
 *     oid = NULL there too (not key-file encodable); only a few carry one.
 * Drift is caught automatically: `hybrid_capability_test` compares every
 * code point against the default/oqsprovider live TLS-GROUP capabilities, and
 * the encode round-trip tests fail on any OID mismatch. `secbits` is the
 * oqsprovider/IETF default; a 0 code point means "no TLS group" (KEM API only,
 * e.g. X448MLKEM1024).
 */
#define HYBRID_KEM_LIST(X)                                                    \
  /* --- default-provider MLX names (raw concat) --- */                       \
  X(x25519mlkem768,    "X25519MLKEM768",     "X25519", NULL,            0,    \
      "MLKEM768",  0, 0x11ec, 192, "X25519+ML-KEM-768", NULL)\
  X(x448mlkem1024,     "X448MLKEM1024",      "X448",   NULL,            0,    \
      "MLKEM1024", 0, 0x0000, 256, "X448+ML-KEM-1024", NULL)\
  X(secp256r1mlkem768, "SecP256r1MLKEM768",  "EC",     "P-256",         0,    \
      "MLKEM768",  1, 0x11eb, 192, "P-256+ML-KEM-768", NULL)\
  X(secp384r1mlkem1024,"SecP384r1MLKEM1024", "EC",     "P-384",         0,    \
      "MLKEM1024", 1, 0x11ed, 256, "P-384+ML-KEM-1024", "1.3.6.1.4.1.42235.6")\
  /* --- oqsprovider OQS-legacy ML-KEM hybrids --- */                         \
  X(x25519_mlkem512,   "x25519_mlkem512",    "X25519", NULL,            0,    \
      "MLKEM512",  0, 0x2fb6, 128, "X25519+ML-KEM-512", "1.3.6.1.4.1.22554.5.8.1")\
  X(p256_mlkem512,     "p256_mlkem512",      "EC",     "P-256",         0,    \
      "MLKEM512",  1, 0x2f4b, 128, "P-256+ML-KEM-512", "1.3.6.1.4.1.22554.5.7.1")\
  X(bp256_mlkem512,    "bp256_mlkem512",     "EC",   "brainpoolP256r1", 0,    \
      "MLKEM512",  0, 0xfe20, 128, "brainpoolP256r1+ML-KEM-512", NULL)\
  X(p384_mlkem768,     "p384_mlkem768",      "EC",     "P-384",         0,    \
      "MLKEM768",  1, 0x2f4c, 192, "P-384+ML-KEM-768", NULL)\
  X(x448_mlkem768,     "x448_mlkem768",      "X448",   NULL,            0,    \
      "MLKEM768",  0, 0x2fb7, 192, "X448+ML-KEM-768", NULL)\
  X(bp384_mlkem768,    "bp384_mlkem768",     "EC",   "brainpoolP384r1", 0,    \
      "MLKEM768",  0, 0xfe21, 192, "brainpoolP384r1+ML-KEM-768", NULL)\
  X(p521_mlkem1024,    "p521_mlkem1024",     "EC",     "P-521",         0,    \
      "MLKEM1024", 1, 0x2f4d, 256, "P-521+ML-KEM-1024", NULL)\
  X(bp512_mlkem1024,   "bp512_mlkem1024",    "EC",   "brainpoolP512r1", 0,    \
      "MLKEM1024", 0, 0xfe22, 256, "brainpoolP512r1+ML-KEM-1024", NULL)\
  /* --- oqsprovider FrodoKEM hybrids (PQ base from oqsprovider only) --- */   \
  X(p256_frodo640aes,  "p256_frodo640aes",   "EC",     "P-256",         0,    \
      "frodo640aes", 1, 0xfe24, 128, "P-256+FrodoKEM-640-AES", NULL)\
  X(x25519_frodo640aes,"x25519_frodo640aes", "X25519", NULL,            0,    \
      "frodo640aes", 1, 0xfe25, 128, "X25519+FrodoKEM-640-AES", NULL)\
  X(p256_frodo640shake,"p256_frodo640shake", "EC",     "P-256",         0,    \
      "frodo640shake", 1, 0xfe27, 128, "P-256+FrodoKEM-640-SHAKE", NULL)\
  X(x25519_frodo640shake,"x25519_frodo640shake","X25519",NULL,          0,    \
      "frodo640shake", 1, 0xfe28, 128, "X25519+FrodoKEM-640-SHAKE", NULL)\
  X(p384_frodo976aes,  "p384_frodo976aes",   "EC",     "P-384",         0,    \
      "frodo976aes", 1, 0xfe2a, 192, "P-384+FrodoKEM-976-AES", NULL)\
  X(x448_frodo976aes,  "x448_frodo976aes",   "X448",   NULL,            0,    \
      "frodo976aes", 1, 0xfe2b, 192, "X448+FrodoKEM-976-AES", NULL)\
  X(p384_frodo976shake,"p384_frodo976shake", "EC",     "P-384",         0,    \
      "frodo976shake", 1, 0xfe2d, 192, "P-384+FrodoKEM-976-SHAKE", NULL)\
  X(x448_frodo976shake,"x448_frodo976shake", "X448",   NULL,            0,    \
      "frodo976shake", 1, 0xfe2e, 192, "X448+FrodoKEM-976-SHAKE", NULL)\
  X(p521_frodo1344aes, "p521_frodo1344aes",  "EC",     "P-521",         0,    \
      "frodo1344aes", 1, 0xfe30, 256, "P-521+FrodoKEM-1344-AES", NULL)\
  X(p521_frodo1344shake,"p521_frodo1344shake","EC",    "P-521",         0,    \
      "frodo1344shake", 1, 0xfe32, 256, "P-521+FrodoKEM-1344-SHAKE", NULL)\
  /* --- oqsprovider eFrodoKEM (ephemeral) hybrids (PQ base from oqsprovider only) --- */ \
  X(p256_efrodo640aes, "p256_efrodo640aes",   "EC",     "P-256",         0,    \
      "efrodo640aes", 1, 0xfe01, 128, "P-256+eFrodoKEM-640-AES", NULL)\
  X(x25519_efrodo640aes,"x25519_efrodo640aes","X25519", NULL,            0,    \
      "efrodo640aes", 1, 0xfe02, 128, "X25519+eFrodoKEM-640-AES", NULL)\
  X(p256_efrodo640shake,"p256_efrodo640shake","EC",     "P-256",         0,    \
      "efrodo640shake", 1, 0xfe04, 128, "P-256+eFrodoKEM-640-SHAKE", NULL)\
  X(x25519_efrodo640shake,"x25519_efrodo640shake","X25519",NULL,         0,    \
      "efrodo640shake", 1, 0xfe05, 128, "X25519+eFrodoKEM-640-SHAKE", NULL)\
  X(p384_efrodo976aes, "p384_efrodo976aes",   "EC",     "P-384",         0,    \
      "efrodo976aes", 1, 0xfe07, 192, "P-384+eFrodoKEM-976-AES", NULL)\
  X(x448_efrodo976aes, "x448_efrodo976aes",   "X448",   NULL,            0,    \
      "efrodo976aes", 1, 0xfe08, 192, "X448+eFrodoKEM-976-AES", NULL)\
  X(p384_efrodo976shake,"p384_efrodo976shake","EC",     "P-384",         0,    \
      "efrodo976shake", 1, 0xfe0a, 192, "P-384+eFrodoKEM-976-SHAKE", NULL)\
  X(x448_efrodo976shake,"x448_efrodo976shake","X448",   NULL,            0,    \
      "efrodo976shake", 1, 0xfe0b, 192, "X448+eFrodoKEM-976-SHAKE", NULL)\
  X(p521_efrodo1344aes,"p521_efrodo1344aes",  "EC",     "P-521",         0,    \
      "efrodo1344aes", 1, 0xfe0d, 256, "P-521+eFrodoKEM-1344-AES", NULL)\
  X(p521_efrodo1344shake,"p521_efrodo1344shake","EC",   "P-521",         0,    \
      "efrodo1344shake", 1, 0xfe0f, 256, "P-521+eFrodoKEM-1344-SHAKE", NULL)\
  /* --- oqsprovider BIKE hybrids --- */                                      \
  X(p256_bikel1,       "p256_bikel1",        "EC",     "P-256",         0,    \
      "bikel1", 1, 0xfe11, 128, "P-256+BIKE-L1", NULL)\
  X(x25519_bikel1,     "x25519_bikel1",      "X25519", NULL,            0,    \
      "bikel1", 1, 0xfe12, 128, "X25519+BIKE-L1", NULL)\
  X(p384_bikel3,       "p384_bikel3",        "EC",     "P-384",         0,    \
      "bikel3", 1, 0xfe14, 192, "P-384+BIKE-L3", NULL)\
  X(x448_bikel3,       "x448_bikel3",        "X448",   NULL,            0,    \
      "bikel3", 1, 0xfe15, 192, "X448+BIKE-L3", NULL)\
  X(p521_bikel5,       "p521_bikel5",        "EC",     "P-521",         0,    \
      "bikel5", 1, 0xfe17, 256, "P-521+BIKE-L5", NULL)\
  /* --- oqsprovider HQC hybrids --- */                                       \
  X(p256_hqc1,         "p256_hqc1",          "EC",     "P-256",         0,    \
      "hqc1", 1, 0xfe34, 128, "P-256+HQC-1", NULL)\
  X(x25519_hqc1,       "x25519_hqc1",        "X25519", NULL,            0,    \
      "hqc1", 1, 0xfe35, 128, "X25519+HQC-1", NULL)\
  X(p384_hqc3,         "p384_hqc3",          "EC",     "P-384",         0,    \
      "hqc3", 1, 0xfe37, 192, "P-384+HQC-3", NULL)\
  X(x448_hqc3,         "x448_hqc3",          "X448",   NULL,            0,    \
      "hqc3", 1, 0xfe38, 192, "X448+HQC-3", NULL)\
  X(p521_hqc5,         "p521_hqc5",          "EC",     "P-521",         0,    \
      "hqc5", 1, 0xfe3a, 256, "P-521+HQC-5", NULL)

/* Generate the info table from the master list. */
#define HYBRID_KEM_ROW(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid)       \
    { nm, a1, grp, a1k, a2, NULL, 1, slot, cp, oid },
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
 * Constant component sizes, one row per hybrid KEM in HYBRID_KEM_LIST order
 * (index = HYBRID_KEM_IDX_*). MACHINE-GENERATED — do not hand-edit; regenerate
 * with `hybrid_sizes_test emit` and paste. hybrid_sizes_test re-derives these
 * from live component keygens in CI and fails on drift. Fields, in order:
 * a1_pub,a1_prv,a1_ss,a1_ct, a2_pub,a2_prv,a2_ss,a2_ct, a1_sig(0), a2_sig(0).
 *
 * (The composite family needs no such table: it always has its two component
 * EVP_PKEYs present when a size is needed and reads EVP_PKEY_get_size() off them
 * directly. The hybrids need constants because the decoder must know a component
 * size to split an incoming key blob *before* the component keys exist.)
 */
static const HYBRID_SIZES hybrid_kem_sizes[HYBRID_KEM_ALG_COUNT] = {
    { 32,32,32,32, 1184,2400,32,1088, 0,0 },        /* X25519MLKEM768 */
    { 56,56,56,56, 1568,3168,32,1568, 0,0 },        /* X448MLKEM1024 */
    { 65,32,32,65, 1184,2400,32,1088, 0,0 },        /* SecP256r1MLKEM768 */
    { 97,48,48,97, 1568,3168,32,1568, 0,0 },        /* SecP384r1MLKEM1024 */
    { 32,32,32,32, 800,1632,32,768, 0,0 },          /* x25519_mlkem512 */
    { 65,32,32,65, 800,1632,32,768, 0,0 },          /* p256_mlkem512 */
    { 65,32,32,65, 800,1632,32,768, 0,0 },          /* bp256_mlkem512 */
    { 97,48,48,97, 1184,2400,32,1088, 0,0 },        /* p384_mlkem768 */
    { 56,56,56,56, 1184,2400,32,1088, 0,0 },        /* x448_mlkem768 */
    { 97,48,48,97, 1184,2400,32,1088, 0,0 },        /* bp384_mlkem768 */
    { 133,66,66,133, 1568,3168,32,1568, 0,0 },      /* p521_mlkem1024 */
    { 129,64,64,129, 1568,3168,32,1568, 0,0 },      /* bp512_mlkem1024 */
    { 65,32,32,65, 9616,19888,16,9752, 0,0 },       /* p256_frodo640aes */
    { 32,32,32,32, 9616,19888,16,9752, 0,0 },       /* x25519_frodo640aes */
    { 65,32,32,65, 9616,19888,16,9752, 0,0 },       /* p256_frodo640shake */
    { 32,32,32,32, 9616,19888,16,9752, 0,0 },       /* x25519_frodo640shake */
    { 97,48,48,97, 15632,31296,24,15792, 0,0 },     /* p384_frodo976aes */
    { 56,56,56,56, 15632,31296,24,15792, 0,0 },     /* x448_frodo976aes */
    { 97,48,48,97, 15632,31296,24,15792, 0,0 },     /* p384_frodo976shake */
    { 56,56,56,56, 15632,31296,24,15792, 0,0 },     /* x448_frodo976shake */
    { 133,66,66,133, 21520,43088,32,21696, 0,0 },   /* p521_frodo1344aes */
    { 133,66,66,133, 21520,43088,32,21696, 0,0 },   /* p521_frodo1344shake */
    { 65,32,32,65, 9616,19888,16,9720, 0,0 },       /* p256_efrodo640aes */
    { 32,32,32,32, 9616,19888,16,9720, 0,0 },       /* x25519_efrodo640aes */
    { 65,32,32,65, 9616,19888,16,9720, 0,0 },       /* p256_efrodo640shake */
    { 32,32,32,32, 9616,19888,16,9720, 0,0 },       /* x25519_efrodo640shake */
    { 97,48,48,97, 15632,31296,24,15744, 0,0 },     /* p384_efrodo976aes */
    { 56,56,56,56, 15632,31296,24,15744, 0,0 },     /* x448_efrodo976aes */
    { 97,48,48,97, 15632,31296,24,15744, 0,0 },     /* p384_efrodo976shake */
    { 56,56,56,56, 15632,31296,24,15744, 0,0 },     /* x448_efrodo976shake */
    { 133,66,66,133, 21520,43088,32,21632, 0,0 },   /* p521_efrodo1344aes */
    { 133,66,66,133, 21520,43088,32,21632, 0,0 },   /* p521_efrodo1344shake */
    { 65,32,32,65, 1541,5223,32,1573, 0,0 },        /* p256_bikel1 */
    { 32,32,32,32, 1541,5223,32,1573, 0,0 },        /* x25519_bikel1 */
    { 97,48,48,97, 3083,10105,32,3115, 0,0 },       /* p384_bikel3 */
    { 56,56,56,56, 3083,10105,32,3115, 0,0 },       /* x448_bikel3 */
    { 133,66,66,133, 5122,16494,32,5154, 0,0 },     /* p521_bikel5 */
    { 65,32,32,65, 2241,2321,32,4433, 0,0 },        /* p256_hqc1 */
    { 32,32,32,32, 2241,2321,32,4433, 0,0 },        /* x25519_hqc1 */
    { 97,48,48,97, 4514,4602,32,8978, 0,0 },        /* p384_hqc3 */
    { 56,56,56,56, 4514,4602,32,8978, 0,0 },        /* x448_hqc3 */
    { 133,66,66,133, 7237,7333,32,14421, 0,0 },     /* p521_hqc5 */
};

/*
 * Master hybrid-SIG list — single source of truth, mirroring HYBRID_KEM_LIST.
 * These are oqsprovider's hybrid signatures (ECDSA/RSA classical + PQ), matching
 * its names, OIDs and wire format. Component sizes are discovered at runtime.
 *
 * PROVENANCE: the `oid` and `tls_codepoint` values are oqsprovider's, from its
 * `oqs-template/generate.yml` (see ALGORITHMS.md). Drift is caught automatically
 * — a wrong OID breaks the cross-provider SPKI/PKCS8 round-trips in
 * hybrid_encode_test, and a wrong code point is caught by hybrid_capability_test
 * (which compares against oqsprovider's advertised TLS-SIGALG capabilities).
 *
 * X(cfield, name, alg1, alg1_group, alg2, nist_level, oid, desc, tls_codepoint)
 *   alg1          : "EC" or "RSA"
 *   alg1_group    : EC group, or NULL for RSA (3072-bit)
 *   nist_level    : PQ NIST level -> classical digest (1:SHA256 2/3:SHA384 4/5:SHA512)
 *   tls_codepoint : TLS SignatureScheme code point (advertised via hybrid_caps.c)
 */
#define HYBRID_SIG_LIST(X)                                                    \
  /* --- ML-DSA hybrids --- */                                                \
  X(p256_mldsa44,   "p256_mldsa44",   "EC",  "P-256", "MLDSA44", 2,           \
      "1.3.9999.7.5", "P-256+ML-DSA-44", 0xff06)                                      \
  X(rsa3072_mldsa44,"rsa3072_mldsa44","RSA", NULL,    "MLDSA44", 2,           \
      "1.3.9999.7.6", "RSA3072+ML-DSA-44", 0xff07)                                    \
  X(p384_mldsa65,   "p384_mldsa65",   "EC",  "P-384", "MLDSA65", 3,           \
      "1.3.9999.7.7", "P-384+ML-DSA-65", 0xff08)                                      \
  X(p521_mldsa87,   "p521_mldsa87",   "EC",  "P-521", "MLDSA87", 5,           \
      "1.3.9999.7.8", "P-521+ML-DSA-87", 0xff09)                                      \
  /* --- Falcon hybrids (PQ base from oqsprovider only) --- */                \
  X(p256_falcon512, "p256_falcon512", "EC",  "P-256", "falcon512", 1,         \
      "1.3.9999.3.12", "P-256+Falcon-512", 0xfed8)                                    \
  X(rsa3072_falcon512,"rsa3072_falcon512","RSA",NULL, "falcon512", 1,         \
      "1.3.9999.3.13", "RSA3072+Falcon-512", 0xfed9)                                  \
  X(p521_falcon1024,"p521_falcon1024","EC",  "P-521", "falcon1024", 5,        \
      "1.3.9999.3.15", "P-521+Falcon-1024", 0xfedb)                                   \
  /* --- Falcon-padded hybrids --- */                                         \
  X(p256_falconpadded512,"p256_falconpadded512","EC","P-256",                 \
      "falconpadded512", 1, "1.3.9999.3.17", "P-256+Falcon-padded-512", 0xfedd)       \
  X(rsa3072_falconpadded512,"rsa3072_falconpadded512","RSA",NULL,             \
      "falconpadded512", 1, "1.3.9999.3.18", "RSA3072+Falcon-padded-512", 0xfede)     \
  X(p521_falconpadded1024,"p521_falconpadded1024","EC","P-521",               \
      "falconpadded1024", 5, "1.3.9999.3.20", "P-521+Falcon-padded-1024", 0xfee0)     \
  /* --- MAYO hybrids --- */                                                  \
  X(p256_mayo1,     "p256_mayo1",     "EC",  "P-256", "mayo1", 1,             \
      "1.3.9999.8.1.4", "P-256+MAYO-1", 0xff36)                                       \
  X(p256_mayo2,     "p256_mayo2",     "EC",  "P-256", "mayo2", 1,             \
      "1.3.9999.8.2.4", "P-256+MAYO-2", 0xff37)                                       \
  X(p384_mayo3,     "p384_mayo3",     "EC",  "P-384", "mayo3", 3,             \
      "1.3.9999.8.3.4", "P-384+MAYO-3", 0xff38)                                       \
  X(p521_mayo5,     "p521_mayo5",     "EC",  "P-521", "mayo5", 5,             \
      "1.3.9999.8.5.4", "P-521+MAYO-5", 0xff39)                                       \
  /* --- OV (UOV) hybrids; all NIST level 1 --- */                            \
  X(p256_OV_Is_pkc, "p256_OV_Is_pkc", "EC",  "P-256", "OV_Is_pkc", 1,         \
      "1.3.9999.9.5.2", "P-256+OV-Is-pkc", 0xff1a)                                    \
  X(p256_OV_Ip_pkc, "p256_OV_Ip_pkc", "EC",  "P-256", "OV_Ip_pkc", 1,         \
      "1.3.9999.9.6.2", "P-256+OV-Ip-pkc", 0xff1b)                                    \
  X(p256_OV_Is_pkc_skc,"p256_OV_Is_pkc_skc","EC","P-256","OV_Is_pkc_skc", 1,  \
      "1.3.9999.9.9.2", "P-256+OV-Is-pkc-skc", 0xff1e)                                \
  X(p256_OV_Ip_pkc_skc,"p256_OV_Ip_pkc_skc","EC","P-256","OV_Ip_pkc_skc", 1,  \
      "1.3.9999.9.10.2", "P-256+OV-Ip-pkc-skc", 0xff1f)                               \
  /* --- SNOVA hybrids --- */                                                 \
  X(p256_snova2454, "p256_snova2454", "EC",  "P-256", "snova2454", 1,         \
      "1.3.9999.10.1.2", "P-256+SNOVA-24-5-4", 0xff3b)                                \
  X(p256_snova2454esk,"p256_snova2454esk","EC","P-256","snova2454esk", 1,     \
      "1.3.9999.10.3.2", "P-256+SNOVA-24-5-4-esk", 0xff3f)                            \
  X(p256_snova37172,"p256_snova37172","EC",  "P-256", "snova37172", 1,        \
      "1.3.9999.10.5.2", "P-256+SNOVA-37-17-2", 0xff43)                               \
  X(p384_snova2455, "p384_snova2455", "EC",  "P-384", "snova2455", 3,         \
      "1.3.9999.10.10.2", "P-384+SNOVA-24-5-5", 0xff4d)                               \
  X(p521_snova2965, "p521_snova2965", "EC",  "P-521", "snova2965", 5,         \
      "1.3.9999.10.12.2", "P-521+SNOVA-29-6-5", 0xff52)                               \
  /* --- MQOM2 hybrids (GF16 fast r5) --- */                                  \
  X(p256_mqom2cat1gf16fastr5,"p256_mqom2cat1gf16fastr5","EC","P-256",         \
      "mqom2cat1gf16fastr5", 1, "1.3.9999.11.1.2", "P-256+MQOM2-cat1", 0xff64)        \
  X(p384_mqom2cat3gf16fastr5,"p384_mqom2cat3gf16fastr5","EC","P-384",         \
      "mqom2cat3gf16fastr5", 3, "1.3.9999.11.3.2", "P-384+MQOM2-cat3", 0xff6c)        \
  X(p521_mqom2cat5gf16fastr5,"p521_mqom2cat5gf16fastr5","EC","P-521",         \
      "mqom2cat5gf16fastr5", 5, "1.3.9999.11.5.2", "P-521+MQOM2-cat5", 0xff74)

/* Generate the info table from the master list. */
#define HYBRID_SIG_ROW(cf, nm, a1, grp, a2, lvl, oid, ds, cp)                 \
    { nm, a1, grp, a2, lvl, oid, cp },
static const HYBRID_SIG_INFO hybrid_sig_table[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_ROW)
};
#undef HYBRID_SIG_ROW

/* Per-algorithm table index, in list order (used to bind keymgmt thunks). */
#define HYBRID_SIG_IDX_ROW(cf, ...) HYBRID_SIG_IDX_##cf,
enum { HYBRID_SIG_LIST(HYBRID_SIG_IDX_ROW) HYBRID_SIG_ALG_COUNT_ENUM };
#undef HYBRID_SIG_IDX_ROW

#define HYBRID_SIG_ALG_COUNT \
    (sizeof(hybrid_sig_table) / sizeof(hybrid_sig_table[0]))

/*
 * Constant component sizes, one row per hybrid signature in HYBRID_SIG_LIST
 * order (index = HYBRID_SIG_IDX_*). MACHINE-GENERATED — see hybrid_kem_sizes[].
 * Fields, in order: a1_pub,a1_prv,a1_ss(0),a1_ct(0),
 * a2_pub,a2_prv,a2_ss(0),a2_ct(0), a1_sig, a2_sig.
 */
static const HYBRID_SIZES hybrid_sig_sizes[HYBRID_SIG_ALG_COUNT] = {
    { 65,32,0,0, 1312,2560,0,0, 72,2420 },          /* p256_mldsa44 */
    { 398,384,0,0, 1312,2560,0,0, 384,2420 },       /* rsa3072_mldsa44 */
    { 97,48,0,0, 1952,4032,0,0, 104,3309 },         /* p384_mldsa65 */
    { 133,66,0,0, 2592,4896,0,0, 139,4627 },        /* p521_mldsa87 */
    { 65,32,0,0, 897,1281,0,0, 72,752 },            /* p256_falcon512 */
    { 398,384,0,0, 897,1281,0,0, 384,752 },         /* rsa3072_falcon512 */
    { 133,66,0,0, 1793,2305,0,0, 139,1462 },        /* p521_falcon1024 */
    { 65,32,0,0, 897,1281,0,0, 72,666 },            /* p256_falconpadded512 */
    { 398,384,0,0, 897,1281,0,0, 384,666 },         /* rsa3072_falconpadded512 */
    { 133,66,0,0, 1793,2305,0,0, 139,1280 },        /* p521_falconpadded1024 */
    { 65,32,0,0, 1420,24,0,0, 72,454 },             /* p256_mayo1 */
    { 65,32,0,0, 4912,24,0,0, 72,186 },             /* p256_mayo2 */
    { 97,48,0,0, 2986,32,0,0, 104,681 },            /* p384_mayo3 */
    { 133,66,0,0, 5554,40,0,0, 139,964 },           /* p521_mayo5 */
    { 65,32,0,0, 66576,348704,0,0, 72,96 },         /* p256_OV_Is_pkc */
    { 65,32,0,0, 43576,237896,0,0, 72,128 },        /* p256_OV_Ip_pkc */
    { 65,32,0,0, 66576,32,0,0, 72,96 },             /* p256_OV_Is_pkc_skc */
    { 65,32,0,0, 43576,32,0,0, 72,128 },            /* p256_OV_Ip_pkc_skc */
    { 65,32,0,0, 1016,48,0,0, 72,248 },             /* p256_snova2454 */
    { 65,32,0,0, 1016,36848,0,0, 72,248 },          /* p256_snova2454esk */
    { 65,32,0,0, 9842,48,0,0, 72,124 },             /* p256_snova37172 */
    { 97,48,0,0, 1579,48,0,0, 104,379 },            /* p384_snova2455 */
    { 133,66,0,0, 2716,48,0,0, 139,454 },           /* p521_snova2965 */
    { 65,32,0,0, 60,88,0,0, 72,3280 },              /* p256_mqom2cat1gf16fastr5 */
    { 97,48,0,0, 90,132,0,0, 104,7738 },            /* p384_mqom2cat3gf16fastr5 */
    { 133,66,0,0, 122,180,0,0, 139,13772 },         /* p521_mqom2cat5gf16fastr5 */
};

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
 * Size accessors read key->sizes (the constant sizes copied in at construction)
 * for both KEM and SIG keys.
 */
#define HYBRID_KEY_ALG1_PUBKEY_BYTES(k) ((k)->sizes->a1_pub)
#define HYBRID_KEY_ALG2_PUBKEY_BYTES(k) ((k)->sizes->a2_pub)
#define HYBRID_KEY_ALG1_PRVKEY_BYTES(k) ((k)->sizes->a1_prv)
#define HYBRID_KEY_ALG2_PRVKEY_BYTES(k) ((k)->sizes->a2_prv)

/* Total ciphertext / shared-secret sizes for a KEM key. */
static inline size_t hybrid_kem_ctext_bytes(const HYBRID_KEY *key)
{
    return key->sizes->a1_ct + key->sizes->a2_ct;
}

static inline size_t hybrid_kem_shsec_bytes(const HYBRID_KEY *key)
{
    return key->sizes->a1_ss + key->sizes->a2_ss;
}

/*
 * Maximum hybrid signature size:
 * ENCODE_UINT32(classical_len) + max classical sig + PQ sig.
 */
static inline size_t hybrid_sig_max_sig_bytes(const HYBRID_KEY *key)
{
    return sizeof(uint32_t) + key->sizes->a1_sig + key->sizes->a2_sig;
}

/* Generic total sizes via HYBRID_KEY. */
static inline size_t hybrid_key_pubkey_bytes(const HYBRID_KEY *key)
{
    return key->sizes->a1_pub + key->sizes->a2_pub;
}

static inline size_t hybrid_key_prvkey_bytes(const HYBRID_KEY *key)
{
    return key->sizes->a1_prv + key->sizes->a2_prv;
}

/* Extern declarations for dispatch tables */
extern const OSSL_DISPATCH hybrid_kem_functions[];
extern const OSSL_DISPATCH hybrid_sig_functions[];

/* Encoders (hybrid_encoder.c) */
extern const OSSL_DISPATCH hybrid_spki_der_encoder_functions[];
extern const OSSL_DISPATCH hybrid_spki_pem_encoder_functions[];
extern const OSSL_DISPATCH hybrid_pkcs8_der_encoder_functions[];
extern const OSSL_DISPATCH hybrid_pkcs8_pem_encoder_functions[];
extern const OSSL_DISPATCH hybrid_text_encoder_functions[];
int hybrid_encode_pub_blob(HYBRID_KEY *key, unsigned char **out,
                           size_t *outlen);
int hybrid_encode_priv_blob(HYBRID_KEY *key, unsigned char **out,
                            size_t *outlen);

/* Decoders (hybrid_decoder.c) */
extern const OSSL_DISPATCH hybrid_spki_der_decoder_functions[];
extern const OSSL_DISPATCH hybrid_pkcs8_der_decoder_functions[];

/*
 * Parse a SubjectPublicKeyInfo into its algorithm OID and raw public-key bits
 * WITHOUT the eager EVP_PKEY decode that d2i_X509_PUBKEY() performs — that eager
 * decode re-enters the provider decoder chain on the same bytes and crashes on
 * the X509_PUBKEY round-trip libcrypto does while writing a certificate. Shared
 * by the hybrid and composite decoders. On success returns a handle to release
 * with hybrid_spki_free(); *oid and *pub point into it and stay valid until the
 * handle is freed. Returns NULL if the input is not a SPKI. */
void *hybrid_spki_parse(const unsigned char *der, size_t derlen,
                        const ASN1_OBJECT **oid,
                        const unsigned char **pub, int *publen);
void hybrid_spki_free(void *handle);

/* Decoder support (hybrid_keymgmt.c) */
void hybrid_keymgmt_free(void *vkey);
void *hybrid_keymgmt_new_by_variant(void *provctx, int is_kem,
                                    unsigned int variant);
int hybrid_key_load_pub_components(HYBRID_KEY *key,
                                   const unsigned char *classic, size_t clen,
                                   const unsigned char *pq, size_t plen);
int hybrid_key_load_prv_components(HYBRID_KEY *key,
                                   const unsigned char *cder, size_t cderlen,
                                   const unsigned char *pqv, size_t pqvlen,
                                   const unsigned char *pqpub, size_t pqpublen);

/* TLS-GROUP capability advertising (hybrid_caps.c) */
int hybrid_get_capabilities(void *provctx, const char *capability,
                            OSSL_CALLBACK *cb, void *arg);

/*
 * Diagnostic log (hybrid_caps.c). Silent unless the environment variable
 * HYBRID_LOG is set, so normal runs stay quiet; when set, each call writes one
 * line to stderr. Used to record advertisement decisions the operator cannot
 * otherwise see — a hybrid dropped because a component is not fetchable, or an
 * advertisement dropped because the per-enumeration cap was hit (issue #45).
 */
void hybrid_log(const char *fmt, ...);

/*
 * Component extraction (work-items item 13). A hybrid/composite key composes a
 * classical component and a PQ component, each a real EVP_PKEY. These gettable,
 * provider-specific params expose each component's public half as a
 * SubjectPublicKeyInfo DER blob that is directly d2i_PUBKEY-able into a
 * standalone, usable EVP_PKEY — rather than only the opaque concatenated blob of
 * OSSL_PKEY_PARAM_PUB_KEY. Names are role-based and shared by both families.
 */
#define HYBRID_PKEY_PARAM_CLASSIC_PUB "hybrid-classic-pub-spki"
#define HYBRID_PKEY_PARAM_PQ_PUB      "hybrid-pq-pub-spki"

/*
 * Set OSSL_PARAM *p to the SubjectPublicKeyInfo DER of component |comp|, honuring
 * a size query (p->data == NULL). Returns 1 on success. Shared by the hybrid and
 * composite keymgmt get_params (hybrid_prov.c).
 */
int hybrid_component_spki_param(OSSL_PARAM *p, EVP_PKEY *comp);

/*
 * TLS code-point hygiene (issue #45).
 *
 * A provisional code point must never sit in IANA standards-track space, where
 * a later real allocation can overrun it and be silently shadowed by libssl's
 * dedup — as happened to the composite family when OpenSSL 4.1's native SLH-DSA
 * (0x0911-0x091C) collided with draft-reddy's 0x0912 (issue #38). So every code
 * point this provider uses must fall into one of the ranges below, classified by
 * VALUE alone (not by algorithm name), and hybrid_capability_test asserts that
 * for every table entry:
 *   - IANA-assigned span: the draft-ietf-tls-ecdhe-mlkem ML-KEM-hybrid
 *     NamedGroups, registered as the contiguous span 0x11EB..0x11ED. The only
 *     standards-track values we use; taken verbatim from the assignment.
 *   - Provisional: everything else, inherited from oqsprovider for on-the-wire
 *     interop — either oqsprovider's experimental ML-KEM-hybrid block
 *     (0x2F00..0x2FFF) or the TLS private-use range (0xFE00..0xFFFF, which
 *     RFC 8446 §11 reserves for both NamedGroup and SignatureScheme).
 * A value outside every range means a code point was invented in managed space;
 * the test fails so it cannot slip in unnoticed.
 */
#define HYBRID_TLS_PRIVATE_USE_MIN      0xFE00u
#define HYBRID_TLS_PRIVATE_USE_MAX      0xFFFFu
#define HYBRID_TLS_OQS_EXPERIMENTAL_MIN 0x2F00u
#define HYBRID_TLS_OQS_EXPERIMENTAL_MAX 0x2FFFu
#define HYBRID_TLS_IANA_ASSIGNED_MIN    0x11EBu   /* draft-ietf-tls-ecdhe-mlkem */
#define HYBRID_TLS_IANA_ASSIGNED_MAX    0x11EDu

static inline int hybrid_codepoint_is_provisional(unsigned int cp)
{
    return (cp >= HYBRID_TLS_PRIVATE_USE_MIN && cp <= HYBRID_TLS_PRIVATE_USE_MAX)
        || (cp >= HYBRID_TLS_OQS_EXPERIMENTAL_MIN
            && cp <= HYBRID_TLS_OQS_EXPERIMENTAL_MAX);
}

static inline int hybrid_codepoint_is_iana_assigned(unsigned int cp)
{
    return cp >= HYBRID_TLS_IANA_ASSIGNED_MIN
        && cp <= HYBRID_TLS_IANA_ASSIGNED_MAX;
}

/*
 * Upper bound on the number of TLS groups / sigalgs advertised into a single
 * capability enumeration (issue #45). An unbounded supported_groups /
 * signature_algorithms list bloats every ClientHello and can be rejected or
 * stall a handshake on strict peers, so the advertiser caps the count and logs
 * (via hybrid_log) any surplus. The bound is the exact number of algorithms
 * defined in each master list: the provider can never legitimately advertise
 * more distinct groups/sigalgs than it defines, so the count staying within the
 * table size is the invariant — hitting the cap means a bug (a duplicate or a
 * runaway loop), which is logged rather than emitted. No magic constant: the
 * bound tracks the master lists automatically as they grow.
 */
#define HYBRID_MAX_TLS_GROUPS   HYBRID_KEM_ALG_COUNT
#define HYBRID_MAX_TLS_SIGALGS  HYBRID_SIG_ALG_COUNT

/*
 * Buffer size for holding an algorithm name in tests (incl NUL). Larger than
 * the longest name any master list registers (currently 31 chars); the capture
 * collectors detect and flag truncation so this stays provably sufficient.
 */
#define HYBRID_ALG_NAME_MAX     64

/* Per-algorithm keymgmt dispatch — declared by macro in hybrid_keymgmt.c */
#define DECLARE_HYBRID_KMGMT_EXTERN(name) \
    extern const OSSL_DISPATCH hybrid_##name##_kmgmt_functions[];

/* KEM keymgmt — generated from the master list */
#define HYBRID_KEM_EXTERN_ROW(cf, ...) DECLARE_HYBRID_KMGMT_EXTERN(cf)
HYBRID_KEM_LIST(HYBRID_KEM_EXTERN_ROW)
#undef HYBRID_KEM_EXTERN_ROW

/* Signature keymgmt — generated from the master list */
#define HYBRID_SIG_EXTERN_ROW(cf, ...) DECLARE_HYBRID_KMGMT_EXTERN(cf)
HYBRID_SIG_LIST(HYBRID_SIG_EXTERN_ROW)
#undef HYBRID_SIG_EXTERN_ROW

#endif /* HYBRID_PROV_H */
