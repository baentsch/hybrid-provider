# Hybrid Provider

An external OpenSSL 3.x provider implementing hybrid PQ KEM and hybrid PQ
signature algorithms using only the public EVP API.

## Design

See [design.md](design.md) for the full architecture and design decisions.

## Key Principles

- **EVP-only**: All cryptographic operations delegate to sub-algorithms via the
  public EVP API. No internal OpenSSL headers are used.
- **Provider-agnostic composition**: Sub-algorithms can come from any provider
  (default, oqsprovider, or others). The hybrid provider does not care which
  provider implements the components.
- **Wire-format compatibility**: KEM hybrids match the byte layout of OpenSSL's
  built-in MLX KEM (draft-ietf-tls-ecdhe-mlkem) for interoperability.

## Build

```sh
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
make
```

Requires OpenSSL 3.0+ (3.0-era EVP only). Effective floor is per component:
hybrid KEMs 3.0+, hybrid sigs 3.2+ (oqsprovider floor), experimental composite
signatures and KEMs 3.2+ (raw private key, no seed API), standardized composite
(ML-DSA/ML-KEM) and any use of the default provider's native ML-KEM/ML-DSA 3.5+
(seed API; native PQ landed in 3.5.0). On 3.0–3.4 the PQ half comes from
oqsprovider; on 3.5+ from the default provider. The standardized composite tiers
self-deactivate below 3.5 (only the experimental composite signatures and KEMs
are served there). Interop tests against default provider hybrid KEMs require 3.5+.

## Testing Requirements

**Baseline requirement**: The provider MUST be functionally tested for
interoperability with the default provider's already present hybrid algorithms:

- `X25519MLKEM768`
- `SecP256r1MLKEM768`
- `X448MLKEM1024`
- `SecP384r1MLKEM1024`

Specifically, the following interop tests MUST pass:

1. **Cross-encapsulate/decapsulate**: Generate a keypair with the hybrid
   provider, export it, import into the default provider's MLX KEM, encapsulate
   with the default provider, and decapsulate with the hybrid provider. The
   shared secrets must be identical. And vice versa.

2. **Key material round-trip**: Export raw key bytes from the hybrid provider,
   import into the default provider (and vice versa). The key material must
   match byte-for-byte.

3. **Self-consistency for signatures**: Since OpenSSL 3.5 does not include
   hybrid signatures in the default provider, signature algorithms are tested
   for sign/verify round-trip within the hybrid provider itself.

## Project Structure

```
hybrid-provider/
├── CMakeLists.txt
├── CLAUDE.md              ← this file
├── design.md              ← full architecture, design decisions + future work
├── README.md              ← landing page: motivation, algorithm inventory, build
├── USAGE.md               ← loading, calling, mixing components, cnf configuration
├── TESTING.md             ← test suite, CLI harness, benchmarking
├── CONTRIBUTING.md        ← code conventions, layout, adding a hybrid (contributor doc)
├── openssl/               ← reference OpenSSL checkout (not built)
├── hybrid_prov.c          ← provider init, query_operation, capabilities
├── hybrid_keymgmt.c       ← keymgmt dispatch (hybrid keys)
├── hybrid_kem.c           ← KEM dispatch (encaps/decaps)
├── hybrid_sig.c           ← signature dispatch (sign/verify)
├── hybrid_caps.c          ← TLS-GROUP + TLS-SIGALG capability advertising
├── hybrid_encoder.c       ← SPKI/PKCS8 key encoders (DER + PEM + text)
├── hybrid_decoder.c       ← SPKI/PKCS8 key decoders
├── hybrid_prov.h          ← shared types, HYBRID_KEY, info tables
├── composite_*.{c,h}      ← composite (LAMPS) family — only with -DHYBRID_COMPOSITE
│                            (keymgmt, sig, caps, encoder, decoder, prov.h)
└── test/
    ├── hybrid_test.c              ← interop tests against default provider
    ├── hybrid_tls_test.c          ← in-process TLS 1.3 handshake interop (dual libctx)
    ├── hybrid_cert_tls_test.c     ← signature certs over TLS 1.3
    ├── hybrid_encode_test.c       ← SPKI/PKCS8 key round-trips vs oqsprovider
    ├── hybrid_kem_encode_test.c   ← KEM key-file round-trips (HYBRID_KEM_ENCODERS)
    ├── hybrid_param_test.c        ← raw-param (OSSL_PARAM) round-trips
    ├── hybrid_cms_test.c          ← CMS SignedData
    ├── hybrid_capability_test.c   ← TLS code-point parity vs default/oqsprovider
    ├── hybrid_config_test.c       ← cnf-driven component selection
    ├── hybrid_compctx_test.c      ← private component context (Frodo/BIKE/HQC)
    ├── hybrid_coexist_test.c      ← provider coexistence
    ├── hybrid_threads_test.c      ← concurrency/fork/teardown stress (ASan/TSan)
    ├── hybrid_matrix_test.c       ← full cross-version matrix vs oqsprovider
    ├── hybrid_replace_test.c      ← drop-in replacement over PQ-only oqsprovider (OQS_CEDE_HYBRIDS)
    ├── patches/                   ← in-repo oqsprovider patches (cede-hybrids lever)
    ├── composite_*_test.c         ← composite combiner/provider/draft-19 KAT
    ├── composite_sig_bench.c      ← composite cert size + cert-gen/verify benchmark
│   ├── composite_kem_bench.c      ← composite KEM keygen/encaps/decaps + pk/ct/sk sizes
    ├── hybrid_bench.c             ← keygen/encaps/decaps benchmark vs default provider
    └── hybrid_scenarios.sh        ← CLI (s_server/s_client) TLS interop harness
```

## Code Conventions

- C11, targeting Linux
- OpenSSL coding style (4-space indent, K&R braces)
- All public symbols prefixed with `hybrid_`
- Error handling via `ERR_raise` / `ERR_raise_data`
