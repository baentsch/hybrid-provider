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
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_tls_test
```

(Both run under `ctest` as well.)

`hybrid_test` verifies:

- **KEM self-consistency** — generate, encapsulate, decapsulate within the
  hybrid provider
- **KEM cross-provider interop** — encapsulate/decapsulate across hybrid and
  default providers (both directions)
- **Key round-trip** — export/import public keys, verify byte-for-byte match
- **Signature self-consistency** — keygen, sign, verify within the hybrid
  provider
- **Signature wrong-message rejection** — verify fails on tampered messages
- **Cross-provider ML-KEM composition** — if `bcrust_provider` is on the module
  path, the suite additionally composes each hybrid's ML-KEM component from
  [bcrust-provider](https://github.com/baentsch/bcrustprovider) (via the
  `?provider=bcrust` component query) and verifies both self-consistency and
  interop with the default provider's native MLX hybrid. This proves a
  bcrust-sourced ML-KEM is wire-compatible.
- **Cross-provider ML-DSA composition** — likewise, the ML-DSA component of each
  hybrid signature is composed from `bcrust_provider` and/or `oqsprovider` (when
  present) and verified for sign/verify round-trip. The default provider has no
  hybrid signatures, so there is no native counterpart to interop against —
  these are self-consistency checks. Note oqsprovider exposes its standalone
  ML-DSA on OpenSSL 3.5+ (unlike its ML-KEM, which it disables there), so the
  oqs ML-DSA composition runs on 3.5.6.

Each cross-provider block is skipped (not failed) when its provider is not on
the module path, so the baseline suite is 28/28; it grows to 42/42 with
bcrust-provider and 48/48 with both bcrust-provider and oqsprovider. To enable a
block, symlink the provider's `.so` into the module directory.

`hybrid_tls_test` verifies **TLS 1.3 handshake interop**: an in-process
handshake between two `OSSL_LIB_CTX`s connected by memory BIOs, with one peer
sourcing the hybrid MLX group from the hybrid provider (via `?provider=hybrid`)
and the other from the default provider. For each of the three groups with a
standardized TLS codepoint (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`SecP384r1MLKEM1024`), in both directions, it asserts the handshake completes,
the negotiated group matches, and both peers derive identical exported keying
material — proving wire compatibility end to end (12/12). `X448MLKEM1024` has no
TLS codepoint and is covered only via the KEM API in `hybrid_test`.

To exercise the same interop through the `openssl` command line — and to select
component providers by **configuration alone** (no code), via the hybrid
provider's `pq-propquery` / `classic-propquery` config keys — see the
[CLI harness](#cli-harness-testhybrid_scenariossh) and
[Selecting component providers](#selecting-component-providers-pq-propquery--classic-propquery)
sections below.

### CLI harness (`test/hybrid_scenarios.sh`)

A configurable shell harness drives the same TLS interop through the `openssl`
command-line tool, with provider selection via flags or a config file:

```sh
test/hybrid_scenarios.sh all                       # info + TLS handshakes
test/hybrid_scenarios.sh --hybrid-provider hybrid tls
test/hybrid_scenarios.sh --extra-provider bcrust_provider --pq-provider bcrust info
test/hybrid_scenarios.sh --use-config tls          # drive via generated openssl.cnf
test/hybrid_scenarios.sh config > my.cnf           # emit the openssl.cnf
test/hybrid_scenarios.sh --config settings.conf all
```

It selects the **hybrid** provider (`hybrid` vs `default`) per peer and runs
`s_server`/`s_client` handshakes for each group, both directions plus
hybrid↔hybrid. `--pq-provider`/`--classic-provider` (property names) and
`--extra-provider` (module name) configure component sourcing for the
`info`/`config` views. Run `test/hybrid_scenarios.sh --help` for all options.

Independent PQ/classic component provider selection is available via the
provider's **config keys** `pq-propquery` / `classic-propquery` (see below) —
including on the TLS path, where a single CLI `-propquery` cannot express it.
File-based KEM/signature round-trips remain **not** reproducible on the CLI (the
provider has no encoder, so hybrid keys can't be serialized); those stay covered
by `hybrid_test`.

### Selecting component providers (`pq-propquery` / `classic-propquery`)

The hybrid provider reads two optional keys from its config section to steer
which provider supplies each sub-algorithm, independently of how the hybrid
algorithm itself is selected:

```ini
[hybrid_sect]
module            = /path/to/hybrid.so
activate          = 1
pq-propquery      = ?provider=bcrust   # ML-KEM / ML-DSA component
classic-propquery = ?provider=default  # X25519 / EC / Ed component
```

Each defaults to the key's normal property query when unset, so behaviour is
unchanged without them. Because they come from configuration, they also take
effect in TLS (where only one property query is otherwise exposed) — no OpenSSL
core change required. `hybrid_config_test` verifies that each key independently
governs its component.

## Benchmark

`hybrid_bench` times `X25519MLKEM768` (keygen, encapsulate, decapsulate) across
four configurations, skipping any the running OpenSSL/provider mix can't
satisfy:

1. **default provider** — OpenSSL's native MLX hybrid (needs 3.5+)
2. **hybrid provider** — both components (X25519 + ML-KEM) from the default
   provider (needs 3.5+)
3. **hybrid provider** — X25519 from the default provider, ML-KEM from
   [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) (needs
   OpenSSL 3.4.x + oqsprovider)
4. **hybrid provider** — X25519 from the default provider, ML-KEM from
   [bcrust-provider](https://github.com/baentsch/bcrustprovider) (any OpenSSL
   3.2+, since bcrust-provider ships its own ML-KEM)

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_bench [iterations]
```

The optional `iterations` argument sets the number of operations to time
(default 1000). Set `BENCH_DEBUG=1` to print errors for skipped configurations.
The benchmark loads `oqsprovider` and `bcrust_provider` from the module search
path if present, so symlink their `.so` files into the module directory to
enable configurations 3 and 4. Note that bcrust-provider's algorithms advertise
the property `provider=bcrust` even though the module loads as `bcrust_provider`.

### Why the configurations span two OpenSSL versions

oqsprovider intentionally disables its standalone ML-KEM when the default
provider already ships it (OpenSSL 3.5+), so configuration 3 must run against an
OpenSSL **3.4.x** build (where the default provider has no ML-KEM and
oqsprovider supplies it). Configurations 1 and 2 conversely require the native
MLX hybrid and ML-KEM that only exist in 3.5+. bcrust-provider implements its
own ML-KEM, so configuration 4 runs on either. The benchmark is therefore run
once per OpenSSL version and the results combined; on 3.4.x, configurations 3
and 4 give a head-to-head ML-KEM comparison in the same environment.

### Sample results (3000 iterations, ms/op)

| Configuration | OpenSSL | keygen | encaps | decaps |
|---|---|---|---|---|
| default provider (native MLX) | 3.5.6 | 0.062 | 0.072 | 0.055 |
| hybrid provider (X25519 + ML-KEM from default) | 3.5.6 | 0.056 | 0.071 | 0.055 |
| hybrid provider (X25519 default, ML-KEM **bcrust**) | 3.5.6 | 0.061 | 0.085 | 0.063 |
| hybrid provider (X25519 default, ML-KEM **oqsprovider**) | 3.4.2 | 0.041 | 0.067 | 0.041 |
| hybrid provider (X25519 default, ML-KEM **bcrust**) | 3.4.2 | 0.061 | 0.087 | 0.065 |

Configurations 1 and 2 are statistically identical: the hybrid provider's
EVP-based composition adds **no measurable overhead** over OpenSSL's built-in
MLX hybrid. The cleanest ML-KEM-implementation comparison is the third row
versus the second, both on 3.5.6 in the same process: bcrust-provider's
pure-Rust ML-KEM (auto-vectorised bc-rust) trails OpenSSL's native ML-KEM
(hand-written AVX2 NTT) by ~20% on encapsulate and ~15% on decapsulate, with
keygen within noise. On 3.4.2, oqsprovider (liboqs, hand-tuned AVX2) and bcrust
run side-by-side, with liboqs fastest. In all cases the hybrid provider
transparently composes sub-algorithms sourced from *different* providers into a
single key.

### Hybrid signatures

`hybrid_bench` also times all six hybrid signatures (keygen / sign / verify),
with the ML-DSA component sourced from the default provider and, when present,
from bcrust-provider and oqsprovider. The classical half always comes from the
default provider, so each group of rows isolates the ML-DSA implementation.

Sample results on OpenSSL 3.5.6 (2000 iterations, ms/op):

| Hybrid | ML-DSA source | keygen | sign | verify |
|---|---|---|---|---|
| ed25519mldsa44 | default | 0.111 | 0.516 | 0.182 |
| | bcrust | 0.093 | 0.145 | 0.134 |
| | oqsprovider | 0.054 | 0.087 | 0.110 |
| ed25519mldsa65 | default | 0.171 | 0.802 | 0.231 |
| | bcrust | 0.133 | 0.218 | 0.173 |
| | oqsprovider | 0.073 | 0.125 | 0.128 |
| ed448mldsa87 | default | 0.380 | 1.083 | 0.404 |
| | bcrust | 0.348 | 0.426 | 0.323 |
| | oqsprovider | 0.240 | 0.300 | 0.243 |
| p256mldsa44 | default | 0.101 | 0.507 | 0.151 |
| | bcrust | 0.083 | 0.143 | 0.106 |
| | oqsprovider | 0.043 | 0.083 | 0.080 |
| p256mldsa65 | default | 0.163 | 0.831 | 0.207 |
| | bcrust | 0.130 | 0.221 | 0.144 |
| | oqsprovider | 0.061 | 0.122 | 0.096 |
| p384mldsa87 | default | 0.879 | 1.624 | 0.801 |
| | bcrust | 0.847 | 0.959 | 0.723 |
| | oqsprovider | 0.737 | 0.809 | 0.638 |

Unlike its ML-KEM, oqsprovider keeps its ML-DSA enabled on 3.5+, so all three
sources run in the same 3.5.6 process. The ordering is consistent — oqsprovider
(hand-tuned AVX2) fastest, bcrust (auto-vectorised pure Rust) next, default
slowest — with the gap largest on **sign** (rejection sampling dominates) and
smaller on keygen/verify. This inverts the ML-KEM picture, because OpenSSL 3.5.6
has an optimised ML-KEM but a still-scalar ML-DSA signing path. The bcrust and
oqsprovider figures are essentially OpenSSL-version-independent (the same on
3.4.2 within noise, since each uses its own ML-DSA); only the default-provider
rows are 3.5.6-specific, as 3.4.x has no ML-DSA at all.

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
