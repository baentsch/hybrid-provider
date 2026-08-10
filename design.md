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

## Design principles

Interoperability is the entire point of this work, split by algorithm family:

- **Hybrid family → interop with oqsprovider.** Names, TLS code points, X.509
  OIDs and wire formats are format-identical to upstream oqsprovider's GitHub
  `main`, exercised in-process (same OpenSSL libctx). The MLX KEM subset is the
  exception: it follows OpenSSL's default provider (IETF draft-ietf-tls-ecdhe-mlkem
  raw-concat), which is the interop peer for those three groups.
- **Composite family (LAMPS) → interop with external software** such as Bouncy
  Castle, out-of-process, validated via serialized DER/PEM artifacts and the
  draft's KAT vectors.
- **No self-contained / private OID formats, ever.** Matching an existing peer's
  assigned OIDs (oqsprovider's, or the LAMPS drafts') is interop, not a violation
  of this rule.

### Architecture constraint (both families)

The hybrid provider is a **composition layer only**, using the public EVP API. It
never assumes which provider supplies the PQ primitives:

- PQ primitives (ML-KEM/ML-DSA and the OQS research bases) come via EVP from
  **either oqsprovider or the default provider**, interchangeably — the default
  provider supplies ML-KEM/ML-DSA on OpenSSL 3.5+; oqsprovider supplies those plus
  FrodoKEM/BIKE/HQC/MAYO/… bases.
- **Classical crypto (ECDH/ECDSA/RSA/X25519/Ed25519) always comes from the
  default provider** via EVP.
- A combination is constructible as long as *some* loaded provider offers the
  named base PQ primitive.

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
3. Reads optional component property queries from its config section via
   `OSSL_FUNC_core_get_params` (see "Component provider selection")
4. Allocates a provider context holding `libctx` and configuration
5. Returns the provider dispatch table via `out`

### Component provider selection

By default the hybrid provider fetches its sub-algorithms with whatever
property query the caller passes (the key's `propq`, e.g. from
`EVP_PKEY_CTX_set_params(OSSL_PKEY_PARAM_PROPERTIES)`). In flows that expose
only a single property query — notably TLS, where the `SSL_CTX` query selects
the hybrid group but is not propagated into key generation — that is not enough
to independently steer the PQ and classical components to specific providers.

To make this configurable without any change to OpenSSL itself, the provider
reads two optional keys from its config section:

```ini
[hybrid_sect]
module            = /path/to/hybrid.so
activate          = 1
pq-propquery      = ?provider=oqsprovider   # ML-KEM / ML-DSA component
classic-propquery = ?provider=default       # X25519 / EC component
```

When set, `pq-propquery` is used for every fetch of the PQ component (alg2) and
`classic-propquery` for the classical component (alg1) — in key generation,
import, and the KEM/signature operations alike. Each falls back to the key's
`propq` when its config key is absent, so the default behaviour is unchanged.
Because the values come from configuration (not the per-operation query), they
also take effect on the TLS path. This is preferred over propagating the
selection query into key generation in libcrypto, which would change keygen
semantics for every provider and break callers that use a mandatory
`provider=` query to select a composing algorithm.

The provider dispatch table exposes:
- `OSSL_FUNC_PROVIDER_TEARDOWN`
- `OSSL_FUNC_PROVIDER_GETTABLE_PARAMS` / `OSSL_FUNC_PROVIDER_GET_PARAMS`
- `OSSL_FUNC_PROVIDER_QUERY_OPERATION`
- `OSSL_FUNC_PROVIDER_GET_CAPABILITIES` (for TLS group/sigalg registration)

## Algorithm Configuration

Hybrid algorithm pairings are defined at compile time with a table-driven
approach. Each entry specifies:

Component **sizes are not stored in the table** — they are discovered at runtime
from the actual component algorithms (`hybrid_ensure_sizes`), so a new hybrid
needs only its component identity, not hardcoded lengths. The table rows carry
only identity plus the parameters that fix the wire format:

```c
typedef struct {
    const char *hybrid_name;     /* e.g., "X25519MLKEM768" */
    const char *alg1_name;       /* e.g., "X25519" or "EC" */
    const char *alg1_group;      /* e.g., NULL (or "P-256" for EC) */
    int         alg1_is_kem;     /* 0 = key-exchange, 1 = native KEM */
    const char *alg2_name;       /* PQ KEM, e.g., "MLKEM768" */
    const char *alg2_group;      /* NULL */
    int         alg2_is_kem;     /* always 1 for PQ KEMs */
    int         alg2_slot;       /* 0 or 1: position of PQ share in concatenation */
    int         tls_codepoint;   /* TLS group code point, 0 if none */
    const char *oid;             /* X.509 OID, or NULL if not key-file encodable */
} HYBRID_KEM_INFO;
```

For signatures:

```c
typedef struct {
    const char *hybrid_name;     /* e.g., "p256_mldsa44" */
    const char *alg1_name;       /* "EC" or "RSA" (no EdDSA) */
    const char *alg1_group;      /* EC group (e.g. "P-256"), or NULL for RSA-3072 */
    const char *alg2_name;       /* PQ, e.g. "MLDSA44" */
    int         nist_level;      /* PQ NIST level -> classical digest choice */
    const char *oid;             /* X.509 OID (used by encoders/decoders) */
    int         tls_codepoint;   /* TLS SignatureScheme code point (0 if none) */
} HYBRID_SIG_INFO;
```

### KEM algorithms

The MLX hybrids below match the OpenSSL default provider's wire format
(draft-ietf-tls-ecdhe-mlkem) and are the interop baseline:

| Hybrid Name          | Component 1 | Component 2   | Slot Order         |
|----------------------|-------------|---------------|--------------------|
| X25519MLKEM768       | X25519 (KX) | ML-KEM-768    | ML-KEM first       |
| X448MLKEM1024        | X448 (KX)   | ML-KEM-1024   | ML-KEM first       |
| SecP256r1MLKEM768    | EC P-256    | ML-KEM-768    | EC first           |
| SecP384r1MLKEM1024   | EC P-384    | ML-KEM-1024   | EC first           |

Beyond these, the provider registers the full oqsprovider-compatible hybrid-KEM
matrix — ML-KEM (incl. brainpool curves), FrodoKEM, BIKE and HQC combinations —
matching oqsprovider's names, OIDs and TLS code points. The authoritative list
is `HYBRID_KEM_LIST` in `hybrid_prov.h`; the README enumerates them.

### Signature algorithms

OpenSSL has no built-in hybrid signatures, so the provider uses oqsprovider's
naming and wire format (classical component first, PQ component second). The
classical component is ECDSA on the named curve or RSA-3072 — there are **no**
EdDSA concatenation hybrids. The core ML-DSA set:

| Hybrid Name      | Component 1     | Component 2 |
|------------------|-----------------|-------------|
| p256_mldsa44     | ECDSA P-256     | ML-DSA-44   |
| rsa3072_mldsa44  | RSA-3072        | ML-DSA-44   |
| p384_mldsa65     | ECDSA P-384     | ML-DSA-65   |
| p521_mldsa87     | ECDSA P-521     | ML-DSA-87   |

The full matrix additionally pairs the same classical curves with the research
PQ signatures from oqsprovider — Falcon (incl. padded), MAYO, UOV, SNOVA and
MQOM2. The authoritative list is `HYBRID_SIG_LIST` in `hybrid_prov.h`.

### Composite signatures (LAMPS)

An optional, build-flag-gated (`-DHYBRID_COMPOSITE`, default on) capability *of
this same provider* implements composite ML-DSA
(draft-ietf-lamps-pq-composite-sigs). The **standardized** tier needs OpenSSL
3.5+ (it serializes the PQ private key as its ML-DSA/ML-KEM seed via the 3.5 seed
API); the **experimental** tier serializes the raw private key and so runs from
the oqsprovider floor (3.2+). Below 3.5 the standardized tiers self-deactivate at
registration (`COMPOSITE_SEED_AVAILABLE` in `composite_prov.h`), leaving only the
experimental composite signatures and KEMs (the composite ML-KEM family has the
same two-tier split — standardized ML-KEM 3.5+, experimental FrodoKEM/BIKE/HQC
3.2+). Unlike the concatenation hybrids, composite
uses the draft's message representative and raw-concat serialization, keyed off
`COMPOSITE_SIG_LIST` in `composite_prov.h`:

```
M' = Prefix || Label || len(ctx) || ctx || PH(M)
  Prefix = "CompositeAlgorithmSignatures2025"   (fixed ASCII, whole-scheme separator)
  Label  = per-combo, e.g. "COMPSIG-MLDSA44-ECDSA-P256-SHA256"
  PH     = per-combo prehash (SHA-256/512, SHAKE256, …)
mldsaSig = ML-DSA.Sign(mldsaSK, M', ctx=Label)   tradSig = Trad.Sign(tradSK, M')
pubkey = mldsaPK || tradPK   privkey = mldsaSeed || tradSK   sig = mldsaSig || tradSig
```

The whole concatenation is wrapped in a single SPKI BIT STRING /
`OneAsymmetricKey` OCTET STRING under one composite OID (component sizes are fixed
per OID, so the split is unambiguous). It implements the **full draft-19
standardized matrix** — 18 combos, OIDs `1.3.6.1.5.5.7.6.37`…`.54`: ML-DSA-44/65/87
paired with RSA-2048/3072/4096 (both RSA-PSS and RSA-PKCS#1 v1.5), ECDSA on
P-256/P-384/P-521 and brainpoolP256r1/P384r1, and Ed25519/Ed448.

**Generic over the PQ component, two-tier.** The combiner has zero ML-DSA
hardcoding — it reads a `COMPOSITE_SIG_LIST` row (label, prehash, PQ private-key
form, tier) and delegates to both components via EVP, exactly like the hybrid
master list. This lets the same machinery span research PQ signatures. The tiers
are never blurred:

| Tier | PQ component | OID arc | Wire contract |
| --- | --- | --- | --- |
| **standardized** | ML-DSA only | IANA/LAMPS registered (`…6.37`–`.54`) | byte-exact vs BouncyCastle / future OpenSSL-native; normative |
| **experimental** | any other PQ sig — one per NIST level per OQS family: Falcon (padded), MAYO, CROSS, UOV, SNOVA, MQOM2 | disjoint private arc `1.3.9999.99.*` (a leaf of the arc OQS uses for its own hybrids) | non-normative; interop only with this provider (oqsprovider supplies the PQ components but implements no composites) |

The split keeps *cede-to-default* symmetric with the hybrid family (see Future
work): when OpenSSL ships native composite (ML-DSA only), the standardized subset
can be ceded cleanly while the experimental arc stays, and no experimental combo
can ever be mistaken for a standards-track OID.

**Packaged as a capability, not a separate provider.** Composite ships inside
this provider behind a build flag rather than as its own `composite.so`, because
the spec is stabilizing (draft-19, past IETF Last Call), the matrix is bounded,
and deployment-surface isolation needs only a build flag (the `HYBRID_KEM_ENCODERS`
precedent) — a separate provider would just duplicate the shared two-`EVP_PKEY`
core. It is validated against the draft's published KAT vectors
(`composite_kat_test`). See `composite_prov.h`.

### Hybrid vs. composite: when to use which

Both families combine a classical and a PQ algorithm for the same reason —
defense-in-depth that is deployable now (if either component is later broken, the
other still holds). They are **not redundant**: they sit at different layers and
interoperate with different ecosystems, and neither is faster (both are
primitive-bound; composition glue ≈ 0 — see *Performance*).

| | Hybrid (concatenation) | Composite (LAMPS) |
| --- | --- | --- |
| **KEM role** | TLS 1.3 hybrid key exchange (`draft-ietf-tls-ecdhe-mlkem` / MLX); registered TLS named groups (`HYBRID_KEM_INFO.tls_codepoint`) | PKI / CMS only; SPKI OID, **no** TLS key-exchange codepoint (`COMPOSITE_KEM_INFO` has no `tls_codepoint`) |
| **Signature role** | oqsprovider-compatible concat sigs; any PQ family | X.509 / CMS certificate signatures; standardized tier is ML-DSA-only |
| **Binding** | two independent signatures with a length prefix (separable) | joint message representative `M'` — **non-separable** |
| **Interop peer** | default provider + oqsprovider (TLS wire, OQS ecosystem) | LAMPS implementations (BouncyCastle, future OpenSSL-native) in certificates |
| **Standardization** | MLX KEM is IETF-standard; concat sigs follow the oqsprovider convention | IETF/LAMPS standards-track (composite-sigs draft-19, composite-kem draft-18) |
| **Performance** | primitive-bound | primitive-bound + one SHA3-256 combiner pass (negligible) |

**Can the hybrids be dropped in favour of composites only? No.**

- **Hybrid KEMs cannot be dropped.** They are the standardized TLS 1.3 hybrid
  key-exchange mechanism; composite ML-KEM is a PKIX/S-MIME (LAMPS) mechanism with
  no TLS key-exchange role or codepoint. Removing them would remove interoperable
  TLS hybrid key exchange — this provider's baseline mandate.
- **Hybrid signatures are the droppable family** for PKI, where composite is both
  standardized and cryptographically stronger (non-separable binding). They are
  retained for oqsprovider wire-format interop and for PQ breadth (many families
  in one concat format vs. standardized composite's ML-DSA-only) — not for speed.

So the two families are a *layer / ecosystem* choice (TLS wire + OQS interop vs.
PKI/CMS + LAMPS interop), not duplication.

## Hybrid Key Structure

```c
typedef struct hybrid_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const void *info;        /* HYBRID_KEM_INFO or HYBRID_SIG_INFO */
    int is_kem;              /* 1 = KEM hybrid, 0 = SIG hybrid */
    EVP_PKEY *key1;          /* classical component key */
    EVP_PKEY *key2;          /* PQ component key */
    unsigned int state;      /* HYBRID_HAVE_NOKEYS / PUBKEY / PRVKEY */
    HYBRID_SIZES sizes;      /* KEM only: runtime-discovered component sizes */
    const char *pq_propq;      /* per-component propq for the PQ half (or NULL) */
    const char *classic_propq; /* per-component propq for the classical half */
} HYBRID_KEY;

#define HYBRID_HAVE_NOKEYS  0
#define HYBRID_HAVE_PUBKEY  1
#define HYBRID_HAVE_PRVKEY  2
```

Component sizes are discovered at runtime (`HYBRID_SIZES`, see
`hybrid_ensure_sizes`); `pq_propq`/`classic_propq` are borrowed pointers into the
provider context that steer per-component provider selection (see "Component
provider selection"), each falling back to `propq` when unset.

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

Wire format matches oqsprovider's hybrid signatures: a big-endian `uint32`
length of the classical signature, then the classical signature, then the PQ
signature (`ENCODE_UINT32(classical_len) || classical_sig || pq_sig`). This
length prefix (rather than a fixed maximum slot) accommodates ECDSA's
variable-length DER without padding. The classical component signs under a digest
selected by the PQ component's NIST level (1 → SHA-256, 2/3 → SHA-384, 4/5 →
SHA-512); the PQ component signs per its own scheme.

### Sign

```
1. sig1 = EVP_DigestSign(key1, tbs, tbslen)   (classical, alg1, digest per NIST level)
2. sig2 = EVP_DigestSign(key2, tbs, tbslen)   (PQ, alg2)
3. Output: sig = ENCODE_UINT32(len(sig1)) || sig1 || sig2
```

Both sub-signatures are over the same `tbs` (to-be-signed) data. Signature
hybrids always use alg1-first ordering (no slot swapping).

### Verify

```
1. Read the uint32 classical length prefix; split into sig1, sig2 accordingly
2. ok1 = EVP_DigestVerify(key1, sig1, tbs, tbslen)   (same digest as sign)
3. ok2 = EVP_DigestVerify(key2, sig2, tbs, tbslen)
4. Return success only if BOTH pass
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
    { "p256_mldsa44", "provider=hybrid", hybrid_signature_functions, "..." },
    { "p384_mldsa65", "provider=hybrid", hybrid_signature_functions, "..." },
    ...
    { NULL, NULL, NULL, NULL }
};
```

Each keymgmt entry has its own dispatch table (via macro) because `keymgmt_new`
must know which algorithm variant to create.

### get_capabilities

The provider reports `TLS-GROUP` capabilities (`hybrid_caps.c`) so its KEMs are
negotiable in a TLS handshake, and `TLS-SIGALG` capabilities so its hybrid (and,
when built, composite) signatures are usable for TLS authentication. Every hybrid
whose table row carries a non-zero `tls_codepoint` is advertised: the three MLX
groups with standardized codepoints (draft-ietf-tls-ecdhe-mlkem —
`X25519MLKEM768` 0x11EC, `SecP256r1MLKEM768` 0x11EB, `SecP384r1MLKEM1024`
0x11ED) plus the oqsprovider-assigned code points for the OQS-legacy KEM and
signature hybrids. `X448MLKEM1024` has no TLS codepoint and is reachable only via
the KEM API. The code points are kept in lockstep with their origins by
`hybrid_capability_test`, which compares them against the live default/oqsprovider
capabilities.

The **standardized composite signatures** (`composite_caps.c`) are the one
exception to "code points match their origin". `draft-reddy-tls-composite-mldsa`
(an individual draft, not WG-adopted, TBD in IANA) enumerates which composite
combos become TLS sigalgs, but its own code points sit in IANA-managed
SignatureScheme space — where a later real allocation can overrun a provisional
value. That happened: OpenSSL 4.1 added native SLH-DSA at `0x0911`–`0x091C`,
colliding with draft-reddy's `0x0912` for `mldsa87_ed448`; libssl's sigalg dedup
then silently shadowed the provider's advertisement, so a server holding an
`mldsa87_ed448` certificate could find no usable sigalg (issue #38). Because these
combos are provisional and only interoperate between peers that agree out of band,
we assign them **private-use** code points (RFC 8446 SignatureScheme
`0xFE00`–`0xFFFF`, sub-block `0xFFE0`..) like the hybrid families — collision-proof
against future IANA allocations. `composite_caps.c` enforces the private-use range
as a guard, refusing to advertise any composite code point outside it.

The MLX groups are advertised under their **canonical names and codepoints**,
identical to the default provider's. Because the default provider also
implements them, both would collide on the group name — so **by default the
provider cedes to the default provider** (see *Cede-to-default* below): it
detects the default provider's hybrids at load time and withdraws them, leaving
only what the default provider lacks. Ceding can be switched off, in which case
both implementations coexist under the same names and selection is driven by
property query: `?provider=hybrid` prefers the hybrid implementation for the
group while still resolving the X25519/EC/ML-KEM *components* from the default
provider (the `?` keeps the query optional so the components fall back). That
coexistence mode is what the interoperability tests use.

### Cede-to-default

Whatever the OpenSSL default provider already serves, this provider withdraws.
Those algorithms exist here only to be compared against that implementation for
interoperability; in production, running both is redundant. So on load
`hybrid_apply_cede()` works out which of this provider's algorithms the default
provider serves in the same library context and drops them from the query tables
(`hybrid_query`) and the TLS capabilities (`hybrid_caps.c`, `composite_caps.c`)
alike, leaving only what the default provider lacks.

Detection is **identifier-based, not a fixed algorithm list**, matching on any
of the identifiers the default provider may share with us:

- **name** — a direct `provider=default` fetch of each KEM / signature name (and,
  for signatures, of its OID); catches algorithms served without a TLS capability;
- **TLS code point** and **OID** — a scan of the default provider's live
  `TLS-GROUP` and `TLS-SIGALG` capabilities (`OSSL_PROVIDER_get_capabilities`),
  catching a shared code point or OID the default provider exposes under a
  *different* name.

This open-endedness is deliberate: it covers what the default provider serves
today (the standardized MLX KEM groups) and whatever it may add later — most
notably native composite signatures (openssl#26121), which are handled by the
same code path with no new logic. Detection runs at init — the provider is not
yet active in the store, so the probing fetches and capability queries cannot
recurse into its own `hybrid_query`. When the default provider is absent from the
context, or serves none of our identifiers, nothing is withdrawn.

The behaviour is switchable off (`cede-to-default = no` /
`HYBRID_CEDE_TO_DEFAULT=0`) to get the coexistence mode above; `hybrid_cede_test`
covers both states across the whole inventory. This is symmetric with the
`OQS_CEDE_HYBRIDS` lever that makes oqsprovider cede *its* hybrids to this
provider (see the drop-in work).

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
├── design.md / CLAUDE.md / README.md / USAGE.md / TESTING.md / CONTRIBUTING.md
├── openssl/              ← reference checkout (not built)
├── hybrid_prov.{c,h}     ← provider init, query_operation, shared types + tables
├── hybrid_keymgmt.c      ← keymgmt dispatch (hybrid keys)
├── hybrid_kem.c          ← KEM dispatch (encaps/decaps)
├── hybrid_sig.c          ← signature dispatch (sign/verify)
├── hybrid_caps.c         ← TLS-GROUP / TLS-SIGALG capability advertising
├── hybrid_encoder.c      ← SPKI / PKCS8 encoders (DER + PEM)
├── hybrid_decoder.c      ← SPKI / PKCS8 decoders
├── composite_*.{c,h}     ← composite (LAMPS) family — only with -DHYBRID_COMPOSITE
└── test/                 ← hybrid_test, hybrid_tls_test, hybrid_cert_tls_test,
                            hybrid_encode/param/coexist/cms/matrix/capability
                            tests, composite_* tests, hybrid_bench, and the
                            hybrid_scenarios.sh CLI harness
```

The build always produces the `hybrid.so` provider module and the test/benchmark
executables; with `-DHYBRID_COMPOSITE=ON` the composite family is compiled into
the same `hybrid.so` (no separate module) and its tests are added. `-DHYBRID_KEM_ENCODERS=ON`
adds the hybrid-KEM key-file encoders/decoders.

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

Beyond the MLX baseline, the suite proves drop-in parity with oqsprovider by
cross-version interop against a **pinned oqsprovider `main` peer** (built by
`test/setup_oqs_interop.sh` into gitignored `.local`/`.interop`), both directions,
over the entire hybrid KEM + SIG inventory (driven off the master tables so
nothing is silently omitted). Each KEM is crossed against whichever second peer
implements the name — oqsprovider for the OQS-legacy hybrids, the default provider
for the standardized MLX groups. The hybrid slice of oqsprovider's own e2e tests
maps onto this project's suite as follows (pure-PQ rows stay in oqsprovider and
are out of scope):

| oqsprovider test | hybrid slice | our equivalent |
| --- | --- | --- |
| `oqs_test_kems` | hybrid encaps/decaps | `hybrid_test`, `hybrid_oqs_test` |
| `oqs_test_groups` | hybrid TLS handshake | `hybrid_tls_test`, `hybrid_compctx_test`, `hybrid_scenarios.sh` |
| `oqs_test_signatures` | hybrid sign/verify | `hybrid_test` sig path |
| `oqs_test_tlssig` | hybrid sig cert auth in TLS | `hybrid_cert_tls_test` |
| `oqs_test_endecode` | hybrid key-file round-trip | `hybrid_encode_test`, `hybrid_kem_encode_test` (gated) |
| `oqs_test_evp_pkey_params` | hybrid key param get/set | `hybrid_param_test` |
| `oqs_test_alg_overlap` | provider coexistence | `hybrid_coexist_test` |
| `*cmssign`/`*cmsverify` | hybrid sig in CMS | `hybrid_cms_test` |
| `test_tls_full.py` | external s_client/s_server matrix | `hybrid_scenarios.sh`, `hybrid_matrix_test` |

### Continuous integration tiers

CI is split by a hard rule: **push/PR CI stays fast and deterministic; anything
expensive or dependent on upstream drift runs weekly.**

- **regular** (push / PR / manual) — a minimal *pinned* matrix (one pre-3.5 and
  one ≥3.5 OpenSSL release, fixed liboqs / oqs-provider refs). It deliberately
  does **not** scale with the number of OpenSSL releases and does **not** track
  upstream `main`, so contributors get fast, repeatable signal that is
  independent of what OpenSSL / liboqs / oqs-provider do upstream. A red push/PR
  run always means *this* change broke something, never that an upstream moved.
- **weekly** (schedule / manual) — the exhaustive, bleeding-edge tier: the full
  per-OpenSSL-version floor matrix built against liboqs and oqs-provider `main`.
  This is where the drop-in replacement contract (`hybrid_replace_test`: hybrid
  KEMs / signatures / composite each usable from their respective OpenSSL floor)
  is re-validated as upstream moves, and where drift of the in-repo
  `OQS_CEDE_HYBRIDS` patch against oqs-provider `main` surfaces early. A weekly
  failure never blocks a PR.

## Performance

The provider is a **near-zero-cost EVP composition layer**: its own glue adds
essentially nothing, and a hybrid runs only as fast as each component's EVP path.
The composition double-dispatch is negligible against both slow and fast PQ
primitives (a hybrid's sign time equals a hand-written inline composite doing the
identical EVP calls). Keygen is competitive; KEM encaps/decaps is at parity with
the default provider and oqsprovider.

The one non-obvious effect is a ~1.9× tax on *fast* PQ signatures (Falcon/MAYO/
SNOVA) when the PQ component is sourced from oqsprovider on OpenSSL ≥ 3.5. This is
**oqsprovider's, not OpenSSL's and not this provider's**: on ≥ 3.5 oqsprovider
returns `*no_cache = 1` for the whole provider (a side effect of its runtime
algorithm filter), so OpenSSL reconstructs the full method table on every
`EVP_DigestSignInit` instead of caching it. The delegated M8 path reproduces the
same number oqsprovider's own native hybrids already pay, so M8 introduces no new
regression; fixing the `no_cache` policy in oqsprovider speeds up both equally
(see `docs/oqsprovider-no-cache-issue.md`). The performance lever available here
is primitive sourcing: `pq-propquery` / `classic-propquery` steer each component
to the fastest provider exposing the standalone EVP algorithm. Run
`test/hybrid_bench.c` in your own environment for numbers.

## Future work

- **M8 — become oqsprovider's hybrid backend.** The endgame is for oqsprovider to
  delete its own hybrid KEM/SIG logic and delegate to this provider (it keeps the
  base PQ primitives). Because this provider already matches oqsprovider's names,
  code points, OIDs and wire formats byte-for-byte, that is a drop-in replacement;
  it also dissolves the group-name collision that today forces the private
  component context for Frodo/BIKE/HQC (see Constraints). Validation is the
  cross-version interop sweep above against the pinned pre-removal peer.
- **Native composite in the default provider.** When OpenSSL ships native
  composite ML-DSA (openssl#26121), the standardized composite tier cedes to it
  automatically — `hybrid_apply_cede()` already matches by name / code point /
  OID across the composite table (see *Cede-to-default*), so the standardized
  combos drop out and only the experimental arc remains, with no code change.
- **oqsprovider `no_cache` fix** (see Performance) — a separate, pre-existing
  oqsprovider issue tracked for a later upstream code review, not a blocker.

## Constraints and Limitations

- **TLS-specific**: The initial KEM hybrids follow the TLS wire format
  (draft-ietf-tls-ecdhe-mlkem). They concatenate shared secrets directly
  without an additional KDF — the TLS HKDF handles derivation.
- **Key serialization**: Signature keys encode/decode as X.509
  SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo (DER + PEM), byte-compatible
  with oqsprovider (`hybrid_encoder.c` / `hybrid_decoder.c`). KEM key files are
  supported behind the `HYBRID_KEM_ENCODERS` build option (off by default,
  mirroring oqsprovider's `OQS_KEM_ENCODERS`); only the few hybrid KEMs with an
  assigned OID are encodable. Keys can still be imported/exported via raw
  `OSSL_PARAM` octet strings for the runtime KEM/TLS paths.
- **Library context**: By default the provider uses the caller's `OSSL_LIB_CTX`,
  so sub-algorithm providers must be loaded there. Optionally, the
  `component-providers` config key makes the provider load its component
  providers into its own private context, so the application context need not
  hold them (used for Frodo/BIKE/HQC over TLS).

## References

- OpenSSL MLX KEM: `openssl/providers/implementations/kem/mlx_kem.c`
- OpenSSL MLX keymgmt: `openssl/providers/implementations/keymgmt/mlx_kmgmt.c`
- [provider-kem(7)](https://docs.openssl.org/3.5/man7/provider-kem/)
- [provider-keymgmt(7)](https://docs.openssl.org/3.5/man7/provider-keymgmt/)
- [provider-signature(7)](https://docs.openssl.org/3.5/man7/provider-signature/)
- [draft-ietf-tls-ecdhe-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [EVP_PKEY-MLX-KEM(7)](https://docs.openssl.org/master/man7/EVP_PKEY-MLX-KEM/)
