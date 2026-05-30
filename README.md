# hybrid-provider

An external OpenSSL 3.x provider implementing **hybrid post-quantum KEM** and
**hybrid post-quantum signature** algorithms using only the public EVP API.

## Motivation

Post-quantum algorithms like ML-KEM and ML-DSA are standardized, but the
transition demands hybrid constructions that combine classical and PQ
algorithms for defense-in-depth. This provider implements such hybrids as a
drop-in OpenSSL provider, composing sub-algorithms from *any* installed
provider (default, oqsprovider, etc.) without relying on internal OpenSSL
headers.

## Supported Algorithms

### Hybrid KEMs

| Algorithm | Components | Wire-format compatible with |
|---|---|---|
| `X25519MLKEM768` | X25519 + ML-KEM-768 | OpenSSL default provider |
| `X448MLKEM1024` | X448 + ML-KEM-1024 | OpenSSL default provider |
| `SecP256r1MLKEM768` | ECDH P-256 + ML-KEM-768 | OpenSSL default provider |
| `SecP384r1MLKEM1024` | ECDH P-384 + ML-KEM-1024 | OpenSSL default provider |

KEM hybrids match the byte layout of OpenSSL's built-in MLX KEM
(draft-ietf-tls-ecdhe-mlkem) for full interoperability.

### Hybrid Signatures

| Algorithm | Components |
|---|---|
| `ed25519mldsa44` | Ed25519 + ML-DSA-44 |
| `ed25519mldsa65` | Ed25519 + ML-DSA-65 |
| `ed448mldsa87` | Ed448 + ML-DSA-87 |
| `p256mldsa44` | ECDSA P-256 + ML-DSA-44 |
| `p256mldsa65` | ECDSA P-256 + ML-DSA-65 |
| `p384mldsa87` | ECDSA P-384 + ML-DSA-87 |

## Key Principles

- **EVP-only** — all cryptographic operations delegate to sub-algorithms via
  the public EVP API. No internal OpenSSL headers are used.
- **Provider-agnostic composition** — sub-algorithms can come from any provider.
- **Wire-format compatibility** — KEM hybrids interoperate with OpenSSL's
  built-in hybrid KEMs.

## Prerequisites

- OpenSSL 3.4+ (ML-KEM/ML-DSA support)
- OpenSSL 3.5+ for KEM interop tests against the default provider
- CMake 3.16+
- C11 compiler

## Build

```sh
mkdir build && cd build
cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl
make
```

This produces `hybrid.so` in the build directory.

## Test

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_test
```

The test suite verifies:

- **KEM self-consistency** — generate, encapsulate, decapsulate within the
  hybrid provider
- **KEM cross-provider interop** — encapsulate/decapsulate across hybrid and
  default providers (both directions)
- **Key round-trip** — export/import public keys, verify byte-for-byte match
- **Signature self-consistency** — keygen, sign, verify within the hybrid
  provider
- **Signature wrong-message rejection** — verify fails on tampered messages

## Benchmark

`hybrid_bench` times `X25519MLKEM768` (keygen, encapsulate, decapsulate) across
three configurations, skipping any the running OpenSSL/provider mix can't
satisfy:

1. **default provider** — OpenSSL's native MLX hybrid (needs 3.5+)
2. **hybrid provider** — both components (X25519 + ML-KEM) from the default
   provider (needs 3.5+)
3. **hybrid provider** — X25519 from the default provider, ML-KEM from
   [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) (needs
   OpenSSL 3.4.x + oqsprovider)

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_bench [iterations]
```

The optional `iterations` argument sets the number of operations to time
(default 1000). Set `BENCH_DEBUG=1` to print errors for skipped configurations.

### Why configuration 3 needs a different OpenSSL version

oqsprovider intentionally disables its standalone ML-KEM when the default
provider already ships it (OpenSSL 3.5+), so configuration 3 must run against an
OpenSSL **3.4.x** build (where the default provider has no ML-KEM and
oqsprovider supplies it). Conversely, configurations 1 and 2 require the native
MLX hybrid and ML-KEM that only exist in 3.5+. No single OpenSSL version can
host all three, so the benchmark is run once per version and the results are
combined.

### Sample results (3000 iterations, ms/op)

| Configuration | OpenSSL | keygen | encaps | decaps |
|---|---|---|---|---|
| default provider (native MLX) | 3.5.6 | 0.058 | 0.072 | 0.054 |
| hybrid provider (X25519 + ML-KEM from default) | 3.5.6 | 0.056 | 0.072 | 0.054 |
| hybrid provider (X25519 default, ML-KEM oqsprovider) | 3.4.2 | 0.041 | 0.066 | 0.040 |

Configurations 1 and 2 are statistically identical: the hybrid provider's
EVP-based composition adds **no measurable overhead** over OpenSSL's built-in
MLX hybrid. Configuration 3 is *not* directly comparable — it runs on a
different OpenSSL version with a different ML-KEM implementation (liboqs) — but
demonstrates that the hybrid provider transparently composes sub-algorithms
sourced from *different* providers into a single key.

## Usage

Load the provider alongside the default provider:

```c
OSSL_PROVIDER_load(libctx, "default");
OSSL_PROVIDER_set_default_search_path(libctx, "/path/to/hybrid.so/dir");
OSSL_PROVIDER_load(libctx, "hybrid");

/* KEM */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "X25519MLKEM768", NULL);

/* Signature */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "ed25519mldsa44", NULL);
```

### Mixing sub-algorithms from different providers

The hybrid provider fetches sub-algorithms through the EVP layer, so they can
come from any loaded provider. For example, to compose X25519 from the default
provider with ML-KEM-768 from [oqsprovider](https://github.com/open-quantum-safe/oqs-provider):

```c
OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

/* Load all three providers */
OSSL_PROVIDER_load(libctx, "default");    /* provides X25519 */
OSSL_PROVIDER_load(libctx, "oqsprovider"); /* provides ML-KEM-768 */
OSSL_PROVIDER_set_default_search_path(libctx, "/path/to/hybrid.so/dir");
OSSL_PROVIDER_load(libctx, "hybrid");     /* composes them */

/* Generate a hybrid keypair — the hybrid provider will internally call
 * EVP_PKEY_Q_keygen for X25519 (resolved by default provider) and
 * ML-KEM-768 (resolved by oqsprovider) */
EVP_PKEY *key = NULL;
EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(libctx,
                          "X25519MLKEM768", "provider=hybrid");
EVP_PKEY_keygen_init(gctx);
EVP_PKEY_keygen(gctx, &key);

/* Encapsulate / decapsulate as usual */
EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid");
EVP_PKEY_encapsulate_init(ectx, NULL);
/* ... */
```

The hybrid provider itself never touches the raw cryptography — it only
orchestrates the sub-algorithms via EVP, making it agnostic to which provider
implements them.

## Design

See [design.md](design.md) for the full architecture and design decisions.

## License

Apache-2.0
