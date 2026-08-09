# Testing and benchmarking

The test suite, the cross-provider interop matrix, the CLI harness and the
benchmark. Build the provider first as described in the
[README](README.md#build), then run everything from the `build` directory.

## Test

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_test
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_tls_test
```

(Both run under `ctest` as well; `ctest` runs the whole suite.)

`hybrid_test` verifies:

- **KEM self-consistency** — generate, encapsulate, decapsulate within the
  hybrid provider
- **KEM cross-provider interop** — encapsulate/decapsulate across hybrid and
  default providers (both directions)
- **Key round-trip** — export/import public keys, verify byte-for-byte match
- **Signature self-consistency** — keygen, sign, verify within the hybrid
  provider
- **Signature wrong-message rejection** — verify fails on tampered messages
- **Cross-provider ML-KEM composition** — when
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) is on the
  module path, the suite additionally composes each hybrid's ML-KEM component
  from it (via the `?provider=oqsprovider` component query) and verifies both
  self-consistency and interop with the default provider's native MLX hybrid,
  proving the oqsprovider-sourced ML-KEM is wire-compatible.
- **Cross-provider ML-DSA composition** — likewise, the ML-DSA component of each
  hybrid signature is composed from
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) (when present)
  and verified for sign/verify round-trip. The default provider has no hybrid
  signatures, so there is no native counterpart to interop against — these are
  self-consistency checks.
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) keeps its
  standalone ML-DSA enabled on OpenSSL 3.5+ (unlike its ML-KEM, which it disables
  there), so the oqs ML-DSA composition runs on 3.5.

Each cross-provider block is skipped (not failed) when
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) is not on the
module path, so the suite passes with the default provider alone and gains the
oqsprovider composition checks when it is present. To enable those, symlink
`oqsprovider.so` into the module directory (see `test/setup_oqs_interop.sh`).

Beyond `hybrid_test`, `ctest` runs the rest of the suite: signature certificates
over TLS 1.3 (`hybrid_cert_tls_test`), config-driven component selection
(`hybrid_config_test`), private component contexts for Frodo/BIKE/HQC
(`hybrid_compctx_test`), SPKI/PKCS8 and raw-param round-trips
(`hybrid_encode_test`, `hybrid_param_test`), CMS SignedData (`hybrid_cms_test`),
TLS code-point parity (`hybrid_capability_test`), provider coexistence
(`hybrid_coexist_test`), cede-to-default withdrawal of the default provider's
hybrids (`hybrid_cede_test`), the full cross-version matrix vs
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
(`hybrid_matrix_test`), the coverage guard asserting every hybrid
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) advertises is
also served here (`hybrid_coverage_test`), the drop-in replacement test over a
PQ-only [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
(`hybrid_replace_test`, below), and — with `-DHYBRID_COMPOSITE` — the composite
combiner, provider and draft-19 KAT tests (`composite_sig_test`,
`composite_test`, `composite_kat_test`). Each self-skips cleanly when its
prerequisites are absent.

### Drop-in replacement over a PQ-only oqsprovider (`hybrid_replace_test`)

This ascertains that hybrid-provider can **fully replace**
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)'s hybrids while
composing over it for the PQ primitives. It sets `OQS_CEDE_HYBRIDS` before
loading providers, so
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) withdraws every
hybrid KEM/signature (keeping the standalone PQ + classical components), then
asserts the version contract per running OpenSSL:

- **hybrid KEMs** — OpenSSL **3.0+** (always exercised),
- **hybrid signatures** — OpenSSL **3.2+** (skipped below),
- **composite** — OpenSSL **3.5+**, and only when built with the composite family.

The Frodo/BIKE/HQC hybrids make the "PQ from
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)" claim concrete
(their PQ base exists nowhere else). The `OQS_CEDE_HYBRIDS` lever is carried as
`test/patches/oqsprovider-cede-hybrids.patch` until it lands upstream;
`test/setup_oqs_interop.sh` applies it automatically (a no-op once upstream
carries it). In CI (`.github/workflows/ci.yml`) the weekly job runs this across
OpenSSL 3.0 / 3.2 / latest / master (against liboqs/oqs-provider `main`), and the
fast push/PR job also exercises it on 3.4 + latest — so the contract is proven
per regime. The test self-skips only when
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) is absent; if it
is present but not honoring the lever (patch missing or drifted), the test
**fails** rather than skipping, so the weekly drift watcher goes red.

`hybrid_coverage_test` guards against drift at *test* time (against a built
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)); a lightweight
companion, `scripts/check-oqs-hybrid-drift.sh`, does the same as a buildless
source diff against any
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) ref. A scheduled
workflow (`.github/workflows/oqs-hybrid-drift.yml`) runs it weekly against
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) `main` and opens
a tracking issue if upstream adds a hybrid this provider does not yet serve.

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
[CLI harness](#cli-harness-testhybrid_scenariossh) below and
[Selecting component providers](USAGE.md#selecting-component-providers-pq-propquery--classic-propquery)
in the usage guide.

### CLI harness (`test/hybrid_scenarios.sh`)

A configurable shell harness drives the same TLS interop through the `openssl`
command-line tool, with provider selection via flags or a config file:

```sh
test/hybrid_scenarios.sh all                       # info + TLS handshakes
test/hybrid_scenarios.sh --hybrid-provider hybrid tls
test/hybrid_scenarios.sh --extra-provider oqsprovider --pq-provider oqsprovider info
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
provider's **config keys** `pq-propquery` / `classic-propquery` (see
[Selecting component providers](USAGE.md#selecting-component-providers-pq-propquery--classic-propquery))
— including on the TLS path, where a single CLI `-propquery` cannot express it.
Signature key files serialize as SPKI/PKCS#8 (always built), and hybrid-KEM key
files when `HYBRID_KEM_ENCODERS=ON` for the few KEMs with an assigned OID; those
round-trips are covered by `hybrid_encode_test` / `hybrid_kem_encode_test`. Only
the MLX KEM groups (which have no key-file encoders anywhere) stay non-reproducible
as CLI key files.

The hybrid provider is configured exclusively through an `openssl.cnf` (see
[Configuration](USAGE.md#configuration) in the usage guide), so the CLI harness
always drives the hybrid side via `OPENSSL_CONF` and passes no `-provider` flags
for it.

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

It additionally times a representative slice of the wider inventory — ML-KEM,
FrodoKEM and HQC hybrid KEMs, and ML-DSA, Falcon, MAYO and SNOVA hybrid
signatures — with the PQ component sourced from the default provider and, when
present, [oqsprovider](https://github.com/open-quantum-safe/oqs-provider). The
classical half always comes from the default provider, so paired rows isolate the
PQ implementation.

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_bench [iterations]
```

The optional `iterations` argument sets the number of operations to time
(default 1000). Set `BENCH_DEBUG=1` to print errors for skipped configurations.
The benchmark loads
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) from the module
search path if present, so symlink its `.so` into the module directory to enable
configuration 3 and the oqsprovider PQ rows.

### Why the configurations span two OpenSSL versions

[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) intentionally
disables its standalone ML-KEM when the default provider already ships it
(OpenSSL 3.5+), so configuration 3 must run against an OpenSSL **3.4.x** build
(where the default provider has no ML-KEM and
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) supplies it).
Configurations 1 and 2 conversely require the native MLX hybrid and ML-KEM that
only exist in 3.5+. The benchmark is therefore run once per OpenSSL version and
the results combined.
([oqsprovider](https://github.com/open-quantum-safe/oqs-provider) keeps its
standalone *ML-DSA* enabled on 3.5+, unlike ML-KEM, so the default-vs-oqs
signature comparison runs in a single 3.5+ process.)

Comparing configurations 1 and 2 isolates the composition cost: the hybrid
provider's EVP-based composition adds no measurable overhead over OpenSSL's
built-in MLX hybrid — the time is spent in the underlying primitives, not the
glue. The remaining configurations compare component implementations (e.g.
default-provider vs
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) ML-KEM/ML-DSA)
in the same process. Run `hybrid_bench` in your own environment for numbers.

### Composite certificate benchmark

`composite_bench` (built only with `-DHYBRID_COMPOSITE`) reports, for **every**
composite signature — the standardized ML-DSA combos *and* the experimental
OQS-family combos — the three quantities that matter for a PKI deployment:

- **cert size** — DER length of a self-signed X.509 certificate
- **cert-gen** — keypair-generation time and `X509_sign` time (reported
  separately, in ms)
- **cert-verify** — `X509_verify` time (ms)

Rows are grouped by NIST security level (L1/L3/L5) so the standardized ML-DSA
composites sit side-by-side with the experimental OQS-family composites at the
same level. A few single-algorithm reference rows (pure ML-DSA / Ed25519 from
the default provider) are included so the composite "tax" is readable. The experimental
rows need [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) on
the module search path; combos whose components are unavailable are skipped, not
failed.

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./composite_bench [budget_ms]
```

The optional `budget_ms` argument is the per-operation wall-clock budget: each
measurement loops until that budget (or an iteration cap) is reached, so slow
keygens (UOV/MQOM/CROSS) don't dominate while fast verifies still get enough
samples. It defaults to 1000; `ctest` runs it with a short budget as a smoke
test, so pass a larger value (e.g. `./composite_bench 2000`) for stable numbers.

An illustrative results snapshot and the deployment recommendations that follow
from it are in [composite-bench-results.md](composite-bench-results.md) (numbers
are hardware-specific — regenerate for your own environment).
