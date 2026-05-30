# Hybrid Provider Design

## Overview

An external OpenSSL 3.x provider that implements hybrid post-quantum KEM and
hybrid post-quantum signature algorithms using **only the public EVP API**. By
delegating all cryptographic operations to sub-algorithms fetched via EVP, the
provider can combine algorithms from any installed provider (default, oqsprovider,
or others) in arbitrary pairings.

## Goals

1. Implement hybrid KEM: combine a classical key-exchange/KEM with a PQ KEM
2. Implement hybrid signatures: combine a classical signature with a PQ signature
3. Use only the public EVP API — no internal OpenSSL headers
4. Support arbitrary algorithm pairings from any provider
5. Interoperate with OpenSSL default provider's built-in hybrid KEMs
   (X25519MLKEM768, SecP256r1MLKEM768, X448MLKEM1024, SecP384r1MLKEM1024)

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Application / TLS                  │
├─────────────────────────────────────────────────────┤
│                      EVP API                         │
├───────────┬───────────────────────┬─────────────────┤
│  default  │   hybrid-provider     │  oqsprovider    │
│  provider │                       │  (or any other) │
│           │  ┌─────────────────┐  │                 │
│  X25519   │  │ keymgmt:        │  │  ML-KEM-768    │
│  EC       │  │  HYBRID_KEY     │  │  ML-KEM-1024   │
│  Ed25519  │  │  {EVP_PKEY *a,  │  │  ML-DSA-65     │
│  RSA      │  │   EVP_PKEY *b}  │  │  ML-DSA-87     │
│  ML-KEM   │  │                 │  │  ...            │
│  ML-DSA   │  │ kem:            │  │                 │
│           │  │  encaps/decaps  │  │                 │
│           │  │  via EVP calls  │  │                 │
│           │  │                 │  │                 │
│           │  │ signature:      │  │                 │
│           │  │  sign/verify    │  │                 │
│           │  │  via EVP calls  │  │                 │
│           │  └─────────────────┘  │                 │
└───────────┴───────────────────────┴─────────────────┘
              ▲                   │
              │   EVP_PKEY_*()    │
              └───────────────────┘
           (calls back into EVP layer
            to reach sub-algorithms
            from ANY provider)
```

## Provider Initialization

```c
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx);
```

During init, the provider:
1. Extracts `OSSL_FUNC_core_get_libctx` from the `in` dispatch table
2. Obtains the application's `OSSL_LIB_CTX` — all subsequent EVP calls use this
3. Allocates a provider context holding `libctx` and configuration
4. Returns the provider dispatch table via `out`

The provider dispatch table exposes:
- `OSSL_FUNC_PROVIDER_TEARDOWN`
- `OSSL_FUNC_PROVIDER_GETTABLE_PARAMS` / `OSSL_FUNC_PROVIDER_GET_PARAMS`
- `OSSL_FUNC_PROVIDER_QUERY_OPERATION`
- `OSSL_FUNC_PROVIDER_GET_CAPABILITIES` (for TLS group/sigalg registration)

## Algorithm Configuration

Hybrid algorithm pairings are defined at compile time with a table-driven
approach. Each entry specifies:

```c
typedef struct {
    const char *hybrid_name;     /* e.g., "X25519MLKEM768" */
    const char *alg1_name;       /* e.g., "X25519" */
    const char *alg1_group;      /* e.g., NULL (or "P-256" for EC) */
    int         alg1_is_kem;     /* 0 = key-exchange, 1 = native KEM */
    const char *alg2_name;       /* e.g., "ML-KEM-768" */
    const char *alg2_group;      /* e.g., NULL */
    int         alg2_is_kem;     /* always 1 for PQ KEMs */
    int         alg1_slot;       /* 0 or 1: position in concatenation */
    size_t      alg1_pubkey_bytes;
    size_t      alg1_prvkey_bytes;
    size_t      alg1_shsec_bytes;
    size_t      alg1_ctext_bytes;  /* 0 if key-exchange (pubkey used) */
    size_t      alg2_pubkey_bytes;
    size_t      alg2_prvkey_bytes;
    size_t      alg2_shsec_bytes;
    size_t      alg2_ctext_bytes;
} HYBRID_KEM_INFO;
```

For signatures:

```c
typedef struct {
    const char *hybrid_name;     /* e.g., "ed25519_mldsa65" */
    const char *alg1_name;       /* e.g., "ED25519" */
    const char *alg2_name;       /* e.g., "ML-DSA-65" */
    size_t      alg1_pubkey_bytes;
    size_t      alg1_prvkey_bytes;
    size_t      alg1_sig_bytes;
    size_t      alg2_pubkey_bytes;
    size_t      alg2_prvkey_bytes;
    size_t      alg2_sig_bytes;
} HYBRID_SIG_INFO;
```

### Initial KEM algorithms (matching OpenSSL default provider wire format)

| Hybrid Name          | Component 1 | Component 2   | Slot Order         |
|----------------------|-------------|---------------|--------------------|
| X25519MLKEM768       | X25519 (KX) | ML-KEM-768    | ML-KEM first       |
| X448MLKEM1024        | X448 (KX)   | ML-KEM-1024   | ML-KEM first       |
| SecP256r1MLKEM768    | EC P-256    | ML-KEM-768    | EC first           |
| SecP384r1MLKEM1024   | EC P-384    | ML-KEM-1024   | EC first           |

### Initial Signature algorithms

OpenSSL has no built-in hybrid signatures, so the provider defines its own
naming (classical component first, PQ component second):

| Hybrid Name      | Component 1     | Component 2 |
|------------------|-----------------|-------------|
| ed25519mldsa44   | Ed25519         | ML-DSA-44   |
| ed25519mldsa65   | Ed25519         | ML-DSA-65   |
| ed448mldsa87     | Ed448           | ML-DSA-87   |
| p256mldsa44      | ECDSA P-256     | ML-DSA-44   |
| p256mldsa65      | ECDSA P-256     | ML-DSA-65   |
| p384mldsa87      | ECDSA P-384     | ML-DSA-87   |

## Hybrid Key Structure

```c
typedef struct hybrid_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const void *info;        /* HYBRID_KEM_INFO or HYBRID_SIG_INFO */
    EVP_PKEY *key1;          /* first component key */
    EVP_PKEY *key2;          /* second component key */
    unsigned int state;      /* HYBRID_HAVE_NOKEYS / PUBKEY / PRVKEY */
    int is_kem;              /* 1 = KEM hybrid, 0 = SIG hybrid */
} HYBRID_KEY;

#define HYBRID_HAVE_NOKEYS  0
#define HYBRID_HAVE_PUBKEY  1
#define HYBRID_HAVE_PRVKEY  2
```

Each `EVP_PKEY` is obtained via EVP and may come from any provider.

## Operation: keymgmt

The keymgmt implementation manages the hybrid `HYBRID_KEY`.

### Key Generation (`keymgmt_gen`)

```c
key->key1 = EVP_PKEY_Q_keygen(libctx, propq, info->alg1_name, info->alg1_group);
key->key2 = EVP_PKEY_Q_keygen(libctx, propq, info->alg2_name, info->alg2_group);
```

This pattern is identical to what OpenSSL's MLX keymgmt uses internally.

### Key Import (`keymgmt_import`)

Receives concatenated raw key bytes via `OSSL_PARAM`:
- `OSSL_PKEY_PARAM_PUB_KEY`: `pub1 || pub2` (slot-ordered)
- `OSSL_PKEY_PARAM_PRIV_KEY`: `prv1 || prv2` (slot-ordered)

Splits by known sizes and loads each component via `EVP_PKEY_fromdata()`:

```c
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq);
EVP_PKEY_fromdata_init(ctx);
/* set OSSL_PKEY_PARAM_PUB_KEY or PRIV_KEY + optional group */
EVP_PKEY_fromdata(ctx, &pkey, selection, params);
```

### Key Export (`keymgmt_export`)

Extracts raw bytes from each component via `EVP_PKEY_export()`, concatenates
in slot order, and delivers via the export callback.

### Other keymgmt functions

- `has`: checks `key->state`
- `match`: compares via `EVP_PKEY_eq()` on both components
- `dup`: uses `EVP_PKEY_dup()` on both components
- `get_params`: reports bits, security_bits, max_size from component info

## Operation: KEM

### Two sub-algorithm modes

The classical component may be either:

1. **Native KEM** (has `EVP_PKEY_encapsulate`/`EVP_PKEY_decapsulate`) — used
   directly.

2. **Key Exchange** (X25519, ECDH — has `EVP_PKEY_derive`) — wrapped as KEM:
   - **Encapsulate**: generate ephemeral keypair, extract its public key as
     "ciphertext", derive shared secret via `EVP_PKEY_derive`
   - **Decapsulate**: load peer's public key from "ciphertext", derive shared
     secret via `EVP_PKEY_derive`

### Encapsulate

```
1. If alg1 is key-exchange:
     ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, propq)
     EVP_PKEY_keygen_init(ctx) → EVP_PKEY_keygen(ctx, &ephemeral)
     Extract ephemeral public key → ctext[slot1]
     EVP_PKEY_derive_init(ctx) on ephemeral
     EVP_PKEY_derive_set_peer(ctx, key1)
     EVP_PKEY_derive(ctx, ...) → shsec[slot1]
   If alg1 is native KEM:
     ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, propq)
     EVP_PKEY_encapsulate_init(ctx, NULL)
     EVP_PKEY_encapsulate(ctx, ctext[slot1], shsec[slot1])

2. Same for alg2 (always native KEM for PQ):
     EVP_PKEY_encapsulate_init / EVP_PKEY_encapsulate

3. Output:
     ctext = ctext[slot0] || ctext[slot1]
     shsec = shsec[slot0] || shsec[slot1]
```

### Decapsulate

```
1. If alg1 is key-exchange:
     Load peer public key from ctext[slot1]
     EVP_PKEY_derive_init on own private key
     EVP_PKEY_derive_set_peer(ctx, peer_pub)
     EVP_PKEY_derive → shsec[slot1]
   If alg1 is native KEM:
     EVP_PKEY_decapsulate_init / EVP_PKEY_decapsulate

2. Same for alg2 (PQ KEM):
     EVP_PKEY_decapsulate_init / EVP_PKEY_decapsulate

3. Output:
     shsec = shsec[slot0] || shsec[slot1]
```

### Wire Format Compatibility

For interoperability with OpenSSL's built-in MLX KEM, the byte layout must match
exactly. From analysis of `mlx_kem.c`:

| Algorithm          | ml_kem_slot | Ciphertext layout              | Shared secret layout        |
|--------------------|-------------|--------------------------------|-----------------------------|
| X25519MLKEM768     | 0           | mlkem_ct ‖ x25519_pub          | mlkem_ss ‖ x25519_ss        |
| X448MLKEM1024      | 0           | mlkem_ct ‖ x448_pub            | mlkem_ss ‖ x448_ss          |
| SecP256r1MLKEM768  | 1           | ec_pub ‖ mlkem_ct              | ec_ss ‖ mlkem_ss            |
| SecP384r1MLKEM1024 | 1           | ec_pub ‖ mlkem_ct              | ec_ss ‖ mlkem_ss            |

## Operation: Signature

### Sign

```
1. sig1 = EVP_DigestSign(key1, tbs, tbslen)   (classical, slot 0)
2. sig2 = EVP_DigestSign(key2, tbs, tbslen)   (PQ, slot 1)
3. Output: sig = sig1 || sig2
```

Both sub-signatures are over the same `tbs` (to-be-signed) data. Unlike the KEM
hybrids, signature hybrids always use alg1-first ordering (no slot swapping).

The classical component's size in the concatenation is fixed at the maximum
signature length (`alg1_sig_bytes`). EdDSA signatures are constant-length and
fill it exactly. ECDSA signatures are variable-length DER, so the actual signature
is written into the slot and the remaining bytes are left zeroed.

### Verify

```
1. Split sig into sig1, sig2 by known sizes (sig1 = first alg1_sig_bytes)
2. For ECDSA, parse the real DER length from sig1 before verifying
   (the zero padding is ignored)
3. ok1 = EVP_DigestVerify(key1, sig1, tbs, tbslen)
4. ok2 = EVP_DigestVerify(key2, sig2, tbs, tbslen)
5. Return success only if BOTH pass
```

### One-shot vs streaming

The provider implements the one-shot `digest_sign` / `digest_verify` dispatch
functions. For algorithms that require streaming (multi-part digest), the
provider would need to buffer the data and call the one-shot EVP functions at
final. Initial implementation uses one-shot only.

## Provider Registration

### query_operation

```c
static const OSSL_ALGORITHM hybrid_kems[] = {
    { "X25519MLKEM768", "provider=hybrid", hybrid_kem_functions, "..." },
    { "SecP256r1MLKEM768", "provider=hybrid", hybrid_kem_functions, "..." },
    ...
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM hybrid_keymgmts[] = {
    { "X25519MLKEM768", "provider=hybrid", hybrid_x25519mlkem768_kmgmt_fns, "..." },
    ...
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM hybrid_signatures[] = {
    { "ed25519mldsa44", "provider=hybrid", hybrid_signature_functions, "..." },
    { "p256mldsa65", "provider=hybrid", hybrid_signature_functions, "..." },
    ...
    { NULL, NULL, NULL, NULL }
};
```

Each keymgmt entry has its own dispatch table (via macro) because `keymgmt_new`
must know which algorithm variant to create.

### get_capabilities

The provider reports `TLS-GROUP` capabilities (`hybrid_caps.c`) so its KEMs are
negotiable in a TLS handshake. Only the three MLX hybrids with standardized
codepoints (draft-ietf-tls-ecdhe-mlkem) are advertised — `X25519MLKEM768`
(0x11EC), `SecP256r1MLKEM768` (0x11EB), `SecP384r1MLKEM1024` (0x11ED);
`X448MLKEM1024` has no TLS codepoint and is reachable only via the KEM API.

The groups are advertised under their **canonical names and codepoints**,
identical to the default provider's. Because the default provider also
advertises them, both implementations collide on the group name. Selection is
therefore driven by property query: `?provider=hybrid` prefers the hybrid
implementation for the group while still resolving the X25519/EC/ML-KEM
*components* from the default provider (the `?` keeps the query optional so the
components fall back). This is the same lever intended for eventual config-only
switching between the default-provider and hybrid-provider implementations.

`test/hybrid_tls_test.c` exercises this end to end: an in-process TLS 1.3
handshake between two `OSSL_LIB_CTX`s connected by memory BIOs — one peer
sourcing the group from the hybrid provider, the other from the default
provider — asserting handshake success, matching negotiated group, and
identical exported keying material in both directions.

## Build System

CMake-based, linking against `libcrypto`:

```
hybrid-provider/
├── CMakeLists.txt
├── design.md
├── CLAUDE.md
├── openssl/              ← reference checkout (not built)
├── hybrid_prov.c         ← provider init, query_operation
├── hybrid_keymgmt.c      ← keymgmt dispatch (hybrid keys)
├── hybrid_kem.c          ← KEM dispatch (encaps/decaps)
├── hybrid_sig.c          ← signature dispatch (sign/verify)
├── hybrid_prov.h         ← shared types, HYBRID_KEY, info tables
└── test/
    ├── hybrid_test.c     ← interop tests against default provider
    └── hybrid_bench.c    ← keygen/encaps/decaps benchmark vs default provider
```

The build produces three artifacts: the `hybrid.so` provider module, the
`hybrid_test` interop test, and the `hybrid_bench` benchmark.

## Interoperability Testing

The provider MUST be tested against the default provider's built-in hybrids:

1. **Cross-encapsulate**: Generate keypair with hybrid-provider, encapsulate
   with default provider's X25519MLKEM768, decapsulate with hybrid-provider
   — shared secrets must match.

2. **Cross-decapsulate**: Generate keypair with default provider, encapsulate
   with hybrid-provider, decapsulate with default provider — shared secrets
   must match.

3. **Key export/import round-trip**: Export key from hybrid-provider, import
   into default provider (and vice versa) — keys must match.

4. **Self-consistency**: For signature hybrids (no default-provider counterpart),
   test sign/verify round-trip within the hybrid-provider itself.

Since OpenSSL 3.5 does NOT include hybrid signatures in the default provider,
signature interop testing is limited to self-consistency.

## Constraints and Limitations

- **TLS-specific**: The initial KEM hybrids follow the TLS wire format
  (draft-ietf-tls-ecdhe-mlkem). They concatenate shared secrets directly
  without an additional KDF — the TLS HKDF handles derivation.
- **No ASN.1 encoding**: Raw concatenated key format only (matching MLX).
  No X.509/PKCS#8 encoding in the initial version.
- **No encoder/decoder**: Key persistence via encode/decode is deferred.
  Keys are imported/exported via raw OSSL_PARAM octet strings.
- **Single library context**: The provider uses the caller's `OSSL_LIB_CTX`.
  Sub-algorithm providers must be loaded in that same context.

## References

- OpenSSL MLX KEM: `openssl/providers/implementations/kem/mlx_kem.c`
- OpenSSL MLX keymgmt: `openssl/providers/implementations/keymgmt/mlx_kmgmt.c`
- [provider-kem(7)](https://docs.openssl.org/3.5/man7/provider-kem/)
- [provider-keymgmt(7)](https://docs.openssl.org/3.5/man7/provider-keymgmt/)
- [provider-signature(7)](https://docs.openssl.org/3.5/man7/provider-signature/)
- [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [EVP_PKEY-MLX-KEM(7)](https://docs.openssl.org/master/man7/EVP_PKEY-MLX-KEM/)
