# hybrid-provider

An external OpenSSL 3.x provider implementing **hybrid post-quantum KEM** and
**hybrid post-quantum signature** algorithms using only the public EVP API.

> ⚠️ **AI-generated — not for production use.** This provider was written by an
> AI coding assistant. Like
> [oqsprovider](https://github.com/open-quantum-safe/oqs-provider), it is a
> vehicle for experimentation, prototyping and interoperability research — it has
> **not** been developed, reviewed or audited to the standard required for
> productive use, and must not be relied upon to protect sensitive data.
> AI-assisted contributions are explicitly welcome; see
> [CONTRIBUTING.md](CONTRIBUTING.md#ai-contributions).

## Motivation

Post-quantum algorithms like ML-KEM and ML-DSA are standardized, but the
transition demands hybrid constructions that combine classical and PQ
algorithms for defense-in-depth. This provider implements such hybrids as a
drop-in OpenSSL provider, composing sub-algorithms from *any* installed
provider (default,
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider), etc.) without
relying on internal OpenSSL headers.

## Supported Algorithms

The full inventory is table-driven (`HYBRID_KEM_LIST` / `HYBRID_SIG_LIST` in
`hybrid_prov.h`, `COMPOSITE_SIG_LIST` in `composite_prov.h`) — those tables are
the single source of truth. Names, OIDs and TLS code points match their origins:
the MLX hybrids follow the OpenSSL default provider, and every OQS-legacy hybrid
follows [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
byte-for-byte (verified by the interop tests).

A hybrid is only usable when *both* components resolve: ML-KEM/ML-DSA from the
default provider (OpenSSL 3.5+) or
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) (3.4.x), and the
research bases (FrodoKEM, eFrodoKEM, BIKE, HQC, Falcon, MAYO, UOV, SNOVA, MQOM2)
from [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) only.

### Hybrid KEMs

**MLX — byte-compatible with OpenSSL's built-in MLX KEM**
(draft-ietf-tls-ecdhe-mlkem), interoperable with the default provider:

| Algorithm | Components |
|---|---|
| `X25519MLKEM768` | X25519 + ML-KEM-768 |
| `X448MLKEM1024` | X448 + ML-KEM-1024 |
| `SecP256r1MLKEM768` | ECDH P-256 + ML-KEM-768 |
| `SecP384r1MLKEM1024` | ECDH P-384 + ML-KEM-1024 |

Whatever the OpenSSL default provider already serves, this provider **cedes to
it by default**: on load it detects every algorithm the default provider
provides in the same library context — by name, TLS code point or OID — and
withdraws its own copies, so it only adds what the default provider lacks. That
is identifier-based rather than a fixed list, so it covers what the default
provider serves today (the standardized hybrid KEM groups above) and whatever it
may add later (e.g. native composite signatures). Ceding is switchable off
(`cede-to-default = no` / `HYBRID_CEDE_TO_DEFAULT=0`) to run both implementations
under the same identifiers for interoperability — see [USAGE.md](USAGE.md).

**OQS-legacy hybrids** —
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) naming/wire
format. ML-KEM variants compose from the default provider or
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider);
FrodoKEM/eFrodoKEM/BIKE/HQC need
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider):

| Family | Algorithms |
|---|---|
| ML-KEM | `x25519_mlkem512`, `p256_mlkem512`, `bp256_mlkem512`, `p384_mlkem768`, `x448_mlkem768`, `bp384_mlkem768`, `p521_mlkem1024`, `bp512_mlkem1024` |
| FrodoKEM | `p256_frodo640aes`, `x25519_frodo640aes`, `p256_frodo640shake`, `x25519_frodo640shake`, `p384_frodo976aes`, `x448_frodo976aes`, `p384_frodo976shake`, `x448_frodo976shake`, `p521_frodo1344aes`, `p521_frodo1344shake` |
| eFrodoKEM | `p256_efrodo640aes`, `x25519_efrodo640aes`, `p256_efrodo640shake`, `x25519_efrodo640shake`, `p384_efrodo976aes`, `x448_efrodo976aes`, `p384_efrodo976shake`, `x448_efrodo976shake`, `p521_efrodo1344aes`, `p521_efrodo1344shake` |
| BIKE | `p256_bikel1`, `x25519_bikel1`, `p384_bikel3`, `x448_bikel3`, `p521_bikel5` |
| HQC | `p256_hqc1`, `x25519_hqc1`, `p384_hqc3`, `x448_hqc3`, `p521_hqc5` |

### Hybrid Signatures

Classical component first (ECDSA on the named curve, or RSA-3072), PQ component
second; wire format matches
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) (`uint32`
classical-length prefix, classical signature, PQ signature). The ML-DSA hybrids
compose from the default provider or
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider); the research
families need [oqsprovider](https://github.com/open-quantum-safe/oqs-provider).

| Family | Algorithms |
|---|---|
| ML-DSA | `p256_mldsa44`, `rsa3072_mldsa44`, `p384_mldsa65`, `p521_mldsa87` |
| Falcon | `p256_falcon512`, `rsa3072_falcon512`, `p521_falcon1024` |
| Falcon-padded | `p256_falconpadded512`, `rsa3072_falconpadded512`, `p521_falconpadded1024` |
| MAYO | `p256_mayo1`, `p256_mayo2`, `p384_mayo3`, `p521_mayo5` |
| UOV | `p256_OV_Is_pkc`, `p256_OV_Ip_pkc`, `p256_OV_Is_pkc_skc`, `p256_OV_Ip_pkc_skc` |
| SNOVA | `p256_snova2454`, `p256_snova2454esk`, `p256_snova37172`, `p384_snova2455`, `p521_snova2965` |
| MQOM2 | `p256_mqom2cat1gf16fastr5`, `p384_mqom2cat3gf16fastr5`, `p521_mqom2cat5gf16fastr5` |

### Composite signatures (LAMPS) — optional, `-DHYBRID_COMPOSITE`

An implementation of composite ML-DSA
(draft-ietf-lamps-pq-composite-sigs), built as a **capability of this provider**
(not a separate module) when configured with `-DHYBRID_COMPOSITE=ON`. Unlike the
concatenation hybrids above, composite uses the draft's message-representative
construction (`M' = prefix || label || len(ctx) || ctx || PH(M)`) and raw-concat
serialization, and is validated against the draft's reference test vectors
(`composite_kat_test`).

The **full draft-19 standardized matrix** (18 combos, OIDs `1.3.6.1.5.5.7.6.37`
… `.54`) is implemented and each combo is verified against the draft's reference
test vectors:

| Tier | Algorithms |
|---|---|
| ML-DSA-44 | `mldsa44_rsa2048_pss`, `mldsa44_rsa2048_pkcs15`, `mldsa44_ed25519`, `mldsa44_ecdsa_p256` |
| ML-DSA-65 | `mldsa65_rsa3072_pss`, `mldsa65_rsa3072_pkcs15`, `mldsa65_rsa4096_pss`, `mldsa65_rsa4096_pkcs15`, `mldsa65_ecdsa_p256`, `mldsa65_ecdsa_p384`, `mldsa65_ecdsa_bp256`, `mldsa65_ed25519` |
| ML-DSA-87 | `mldsa87_ecdsa_p384`, `mldsa87_ecdsa_bp384`, `mldsa87_ed448`, `mldsa87_rsa3072_pss`, `mldsa87_rsa4096_pss`, `mldsa87_ecdsa_p521` |
| Experimental (other PQ) | `exp_mayo2_ecdsa_p256` |

Traditional components span RSA-2048/3072/4096 (both PSS and PKCS#1 v1.5), ECDSA
on P-256/P-384/P-521 and brainpoolP256r1/P384r1, and Ed25519/Ed448.

### Composite ML-KEM (LAMPS) — optional, `-DHYBRID_COMPOSITE`

An implementation of composite ML-KEM
(draft-ietf-lamps-pq-composite-kem), built into the same `hybrid.so` under the
same `-DHYBRID_COMPOSITE` flag. The KEM combiner is a single fixed KDF —
`ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)` — with raw-concat
serialization (`mlkemPK || tradPK`, `mlkemSeed || tradSK`, `mlkemCT || tradCT`).

The **full draft-18 standardized matrix** (12 combos, OIDs `1.3.6.1.5.5.7.6.55`
… `.66`) is implemented, verified against the draft's reference test vectors
(`composite_kem_kat_test`) and interop-tested end-to-end against the LAMPS
composite-KEM reference implementation (see
[docs/pqc-kem-certificates-interop.md](docs/pqc-kem-certificates-interop.md)):

| ML-KEM level | Algorithms |
|---|---|
| ML-KEM-768 | `mlkem768_rsa2048`, `mlkem768_rsa3072`, `mlkem768_rsa4096`, `mlkem768_x25519`, `mlkem768_p256`, `mlkem768_p384`, `mlkem768_bp256` |
| ML-KEM-1024 | `mlkem1024_rsa3072`, `mlkem1024_p384`, `mlkem1024_bp384`, `mlkem1024_x448`, `mlkem1024_p521` |

Traditional components are RSA-OAEP-2048/3072/4096 (SHA-256), ECDH on
P-256/P-384/P-521 and brainpoolP256r1/P384r1, and X25519/X448.

## Key Principles

- **EVP-only** — all cryptographic operations delegate to sub-algorithms via
  the public EVP API. No internal OpenSSL headers are used.
- **Provider-agnostic composition** — sub-algorithms can come from any provider.
- **Interoperability** — verified, as applicable, against the OpenSSL default
  provider's hybrid KEMs, every hybrid KEM and signature supported by
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider), the
  composite draft-19 signature and draft-18 ML-KEM known-answer tests (KATs), and
  the LAMPS composite-KEM reference implementation.

## Prerequisites

- OpenSSL **3.0+**. The provider itself uses only 3.0-era EVP; the *effective*
  floor is set by where each component comes from:
  - **Hybrid KEMs** — OpenSSL **3.0+** (the EVP KEM API is 3.0). The PQ half
    (ML-KEM, FrodoKEM, …) resolves from
    [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) on 3.0–3.4,
    or from the default provider natively on 3.5+ (ML-KEM landed in 3.5.0).
  - **Hybrid signatures** — OpenSSL **3.2+** (the oqsprovider hybrid-signature
    floor); the PQ half resolves as above (ML-DSA natively from 3.5+).
  - **Composite signatures** and any use of the **default provider's native
    ML-KEM/ML-DSA** — OpenSSL **3.5+** only (composite needs the 3.5 ML-DSA seed
    API; native ML-KEM/ML-DSA did not exist before 3.5.0).
- CMake 3.16+
- C11 compiler

## Build

```sh
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
make
```

This produces `hybrid.so` in the build directory.

### Build options

| Option | Default | Effect |
|--------|---------|--------|
| `HYBRID_KEM_ENCODERS` | `OFF` | Build encoders/decoders for hybrid **KEM** key files (SPKI + PKCS8) |
| `HYBRID_COMPOSITE` | `ON` | Build the composite (LAMPS) ML-DSA signature **and** ML-KEM families into the provider (needs OpenSSL 3.5+; auto-disabled below) |

`HYBRID_COMPOSITE` compiles the composite signature and ML-KEM families (see
[above](#composite-signatures-lamps--optional--dhybrid_composite)) into the same
`hybrid.so` — there is no separate composite module. It is **on by default**:
carrying pre-standardization algorithms is the point of this provider, so the
composite families ship by default (adding the composite keymgmt, signer, KEM,
encoders/decoders and TLS-SIGALG capability, plus the `composite_*` tests) and are
expected to be turned off once OpenSSL's default provider offers native composite
algorithms. Configure with `-DHYBRID_COMPOSITE=OFF` to exclude them. It requires
OpenSSL 3.5+ (for the ML-DSA/ML-KEM seed APIs); on OpenSSL 3.4.x the build
auto-disables it regardless of this flag.

`HYBRID_KEM_ENCODERS` mirrors
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)'s
`OQS_KEM_ENCODERS` option, and off for the same reasons: KEM keys are usually
ephemeral, and only the hybrid KEMs that
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) assigns an OID
are key-file encodable (`p256_mlkem512`, `x25519_mlkem512`; `SecP384r1MLKEM1024`
on OpenSSL < 3.5). The MLX KEMs the default provider implements are TLS groups
with no key-file encoders on either side, so they are not serializable as key
files. Signature key files (needed for certificates) are always built. When
enabled, `hybrid_kem_encode_test` round-trips KEM SPKI/PKCS8 key files against
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) (built with
`OQS_KEM_ENCODERS=ON`); it self-skips otherwise.

Once built, verify with `ctest` from the `build` directory. See
[TESTING.md](TESTING.md) for the full suite.

## Documentation

| Document | Contents |
|---|---|
| [USAGE.md](USAGE.md) | Loading the provider, calling the algorithms, mixing components across providers, and `openssl.cnf` configuration |
| [TESTING.md](TESTING.md) | Test suite, cross-provider interop matrix, CLI harness, benchmark |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Code conventions, project layout, how to add a hybrid, coverage invariants |
| [design.md](design.md) | Full architecture and design decisions |

## License

Apache-2.0
