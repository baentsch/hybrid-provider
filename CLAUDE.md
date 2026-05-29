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

Requires OpenSSL 3.4+ (ML-KEM/ML-DSA support). Interop tests against default
provider hybrid KEMs require OpenSSL 3.5+.

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
├── design.md              ← full design document
├── openssl/               ← reference OpenSSL checkout (not built)
├── hybrid_prov.c          ← provider init, query_operation
├── hybrid_keymgmt.c       ← keymgmt dispatch (composite keys)
├── hybrid_kem.c           ← KEM dispatch (encaps/decaps)
├── hybrid_sig.c           ← signature dispatch (sign/verify)
├── hybrid_prov.h          ← shared types, HYBRID_KEY, info tables
└── test/
    └── hybrid_test.c      ← interop tests against default provider
```

## Code Conventions

- C11, targeting Linux
- OpenSSL coding style (4-space indent, K&R braces)
- All public symbols prefixed with `hybrid_`
- Error handling via `ERR_raise` / `ERR_raise_data`
