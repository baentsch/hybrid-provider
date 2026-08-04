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

The full inventory is table-driven (`HYBRID_KEM_LIST` / `HYBRID_SIG_LIST` in
`hybrid_prov.h`, `COMPOSITE_SIG_LIST` in `composite_prov.h`) — those tables are
the single source of truth. Names, OIDs and TLS code points match their origins:
the MLX hybrids follow the OpenSSL default provider, and every OQS-legacy hybrid
follows [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
byte-for-byte (verified by the interop tests).

A hybrid is only usable when *both* components resolve: ML-KEM/ML-DSA from the
default provider (OpenSSL 3.5+) or oqsprovider (3.4.x), and the research bases
(FrodoKEM, BIKE, HQC, Falcon, MAYO, UOV, SNOVA, MQOM2) from oqsprovider only.

### Hybrid KEMs

**MLX — byte-compatible with OpenSSL's built-in MLX KEM**
(draft-ietf-tls-ecdhe-mlkem), interoperable with the default provider:

| Algorithm | Components |
|---|---|
| `X25519MLKEM768` | X25519 + ML-KEM-768 |
| `X448MLKEM1024` | X448 + ML-KEM-1024 |
| `SecP256r1MLKEM768` | ECDH P-256 + ML-KEM-768 |
| `SecP384r1MLKEM1024` | ECDH P-384 + ML-KEM-1024 |

**OQS-legacy hybrids** — oqsprovider naming/wire format. ML-KEM variants compose
from the default provider or oqsprovider; FrodoKEM/BIKE/HQC need oqsprovider:

| Family | Algorithms |
|---|---|
| ML-KEM | `x25519_mlkem512`, `p256_mlkem512`, `bp256_mlkem512`, `p384_mlkem768`, `x448_mlkem768`, `bp384_mlkem768`, `p521_mlkem1024`, `bp512_mlkem1024` |
| FrodoKEM | `p256_frodo640aes`, `x25519_frodo640aes`, `p256_frodo640shake`, `x25519_frodo640shake`, `p384_frodo976aes`, `x448_frodo976aes`, `p384_frodo976shake`, `x448_frodo976shake`, `p521_frodo1344aes`, `p521_frodo1344shake` |
| BIKE | `p256_bikel1`, `x25519_bikel1`, `p384_bikel3`, `x448_bikel3`, `p521_bikel5` |
| HQC | `p256_hqc1`, `x25519_hqc1`, `p384_hqc3`, `x448_hqc3`, `p521_hqc5` |

### Hybrid Signatures

Classical component first (ECDSA on the named curve, or RSA-3072), PQ component
second; wire format matches oqsprovider (`uint32` classical-length prefix,
classical signature, PQ signature). The ML-DSA hybrids compose from the default
provider or oqsprovider; the research families need oqsprovider.

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

### Build options

| Option | Default | Effect |
|--------|---------|--------|
| `HYBRID_KEM_ENCODERS` | `OFF` | Build encoders/decoders for hybrid **KEM** key files (SPKI + PKCS8) |
| `HYBRID_COMPOSITE` | `ON` | Build the composite (LAMPS) ML-DSA signature family into the provider |

`HYBRID_COMPOSITE` compiles the composite signatures (see
[above](#composite-signatures-lamps--optional--dhybrid_composite)) into the same
`hybrid.so` — there is no separate composite module. It is **on by default**:
carrying pre-standardization algorithms is the point of this provider, so the
composite family ships by default (adding the composite keymgmt, signer,
encoders/decoders and TLS-SIGALG capability, plus the `composite_*` tests) and is
expected to be turned off once OpenSSL's default provider offers native composite
signatures. Configure with `-DHYBRID_COMPOSITE=OFF` to exclude it.

`HYBRID_KEM_ENCODERS` mirrors oqsprovider's `OQS_KEM_ENCODERS` option, and off for
the same reasons: KEM keys are usually ephemeral, and only the hybrid KEMs that
oqsprovider assigns an OID are key-file encodable (`p256_mlkem512`,
`x25519_mlkem512`; `SecP384r1MLKEM1024` on OpenSSL < 3.5). The MLX KEMs the
default provider implements are TLS groups with no key-file encoders on either
side, so they are not serializable as key files. Signature key files (needed for
certificates) are always built. When enabled, `hybrid_kem_encode_test`
round-trips KEM SPKI/PKCS8 key files against oqsprovider (built with
`OQS_KEM_ENCODERS=ON`); it self-skips otherwise.

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
- **Cross-provider ML-KEM composition** — when `oqsprovider` is on the module
  path, the suite additionally composes each hybrid's ML-KEM component from it
  (via the `?provider=oqsprovider` component query) and verifies both
  self-consistency and interop with the default provider's native MLX hybrid,
  proving the oqsprovider-sourced ML-KEM is wire-compatible.
- **Cross-provider ML-DSA composition** — likewise, the ML-DSA component of each
  hybrid signature is composed from `oqsprovider` (when present) and verified for
  sign/verify round-trip. The default provider has no hybrid signatures, so there
  is no native counterpart to interop against — these are self-consistency
  checks. oqsprovider keeps its standalone ML-DSA enabled on OpenSSL 3.5+ (unlike
  its ML-KEM, which it disables there), so the oqs ML-DSA composition runs on 3.5.

Each cross-provider block is skipped (not failed) when oqsprovider is not on the
module path, so the suite passes with the default provider alone and gains the
oqsprovider composition checks when it is present. To enable those, symlink
`oqsprovider.so` into the module directory (see `test/setup_oqs_interop.sh`).

Beyond `hybrid_test`, `ctest` runs the rest of the suite: signature certificates
over TLS 1.3 (`hybrid_cert_tls_test`), config-driven component selection
(`hybrid_config_test`), private component contexts for Frodo/BIKE/HQC
(`hybrid_compctx_test`), SPKI/PKCS8 and raw-param round-trips
(`hybrid_encode_test`, `hybrid_param_test`), CMS SignedData (`hybrid_cms_test`),
TLS code-point parity (`hybrid_capability_test`), provider coexistence
(`hybrid_coexist_test`), the full cross-version matrix vs oqsprovider
(`hybrid_matrix_test`), and — with `-DHYBRID_COMPOSITE` — the composite combiner,
provider and draft-19 KAT tests (`composite_sig_test`, `composite_test`,
`composite_kat_test`). Each self-skips cleanly when its prerequisites are absent.

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
provider's **config keys** `pq-propquery` / `classic-propquery` (see below) —
including on the TLS path, where a single CLI `-propquery` cannot express it.
File-based KEM/signature round-trips remain **not** reproducible on the CLI (the
provider has no encoder, so hybrid keys can't be serialized); those stay covered
by `hybrid_test`.

### Configuration is cnf-only, never command line

The hybrid provider is configured **exclusively through an `openssl.cnf`**, never
by loading it with `openssl -provider hybrid` on the command line. All of its
component-steering keys — `pq-propquery`, `classic-propquery`,
`component-providers`, `component-path` — live in the provider's config section
and have **no command-line equivalent**. Loading the module with `-provider
hybrid` gives it none of these keys, so it cannot compose anything, and the
private component context that sources Frodo/BIKE/HQC (below) never gets built.
Application code selects the provider by property query (`?provider=hybrid`) once
the cnf has activated it; the CLI harness always drives the hybrid side via
`OPENSSL_CONF` and passes no `-provider` flags for it.

Two distinct limitations sit behind this, with different lifespans:

- **The private component context** (`component-providers` / `component-path`,
  below) is cnf-only and is what forces the Frodo/BIKE/HQC tests through a cnf.
  It exists solely because oqsprovider advertises the *same* TLS group names as
  this provider, so the two can't coexist in one application context. **Once
  oqsprovider drops its hybrid combinations (redesign.md M8), leaving it to
  supply only the base FrodoKEM/BIKE/HQC KEMs, that collision — and this
  requirement — disappears:** all three providers can then be loaded on the
  command line and those groups become ordinary CLI-usable groups.
- **Independent per-component steering** (`pq-propquery` / `classic-propquery`,
  below) stays cnf-only, but that is an OpenSSL TLS-plumbing constraint (only a
  single `-propquery` is exposed on the TLS path), not an oqsprovider one, and
  M8 does not change it. It only matters when you need to source the PQ and
  classic halves from *different* providers; the common case (let each component
  resolve normally, or force one provider globally with `-propquery`) needs no
  cnf.

### Selecting component providers (`pq-propquery` / `classic-propquery`)

The hybrid provider reads two optional keys from its config section to steer
which provider supplies each sub-algorithm, independently of how the hybrid
algorithm itself is selected:

```ini
[hybrid_sect]
module            = /path/to/hybrid.so
activate          = 1
pq-propquery      = ?provider=oqsprovider   # ML-KEM / ML-DSA component
classic-propquery = ?provider=default       # X25519 / EC component
```

Each defaults to the key's normal property query when unset, so behaviour is
unchanged without them. Because they come from configuration, they also take
effect in TLS (where only one property query is otherwise exposed) — no OpenSSL
core change required. `hybrid_config_test` verifies that each key independently
governs its component.

### Private component context (`component-providers` / `component-path`)

Some PQ bases (FrodoKEM, BIKE, HQC) exist only in
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider), which also
registers its **own** competing hybrid TLS groups (`p256_frodo640aes`, …) under
the same names. Loading oqsprovider into the application context would therefore
collide with the hybrid provider's groups. To avoid this, the hybrid provider can
build a **private component library context** and source its PQ base from there:

```ini
[hybrid_sect]
module              = /path/to/hybrid.so
activate            = 1
component-providers = default oqsprovider   # loaded into the provider's OWN ctx
component-path      = /path/to/modules       # where to find oqsprovider.so
```

The application context then loads only `default` + `hybrid`, so the Frodo/BIKE/
HQC hybrid groups resolve unambiguously to the hybrid provider while their PQ
components come from oqsprovider privately. `component-path` is required so the
provider can locate the component modules in its private context. This is
verified in-process by `hybrid_compctx_test` and over separate-process `openssl`
`s_server`/`s_client` handshakes (both directions, against a pure-oqsprovider
peer) by `test/hybrid_scenarios.sh tls-compctx`.

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
present, oqsprovider. The classical half always comes from the default provider,
so paired rows isolate the PQ implementation.

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./hybrid_bench [iterations]
```

The optional `iterations` argument sets the number of operations to time
(default 1000). Set `BENCH_DEBUG=1` to print errors for skipped configurations.
The benchmark loads `oqsprovider` from the module search path if present, so
symlink its `.so` into the module directory to enable configuration 3 and the
oqsprovider PQ rows.

### Why the configurations span two OpenSSL versions

oqsprovider intentionally disables its standalone ML-KEM when the default
provider already ships it (OpenSSL 3.5+), so configuration 3 must run against an
OpenSSL **3.4.x** build (where the default provider has no ML-KEM and
oqsprovider supplies it). Configurations 1 and 2 conversely require the native
MLX hybrid and ML-KEM that only exist in 3.5+. The benchmark is therefore run
once per OpenSSL version and the results combined. (oqsprovider keeps its
standalone *ML-DSA* enabled on 3.5+, unlike ML-KEM, so the default-vs-oqs
signature comparison runs in a single 3.5+ process.)

Comparing configurations 1 and 2 isolates the composition cost: the hybrid
provider's EVP-based composition adds no measurable overhead over OpenSSL's
built-in MLX hybrid — the time is spent in the underlying primitives, not the
glue. The remaining configurations compare component implementations (e.g.
default-provider vs oqsprovider ML-KEM/ML-DSA) in the same process. Run
`hybrid_bench` in your own environment for numbers.

## Usage

Load the provider alongside the default provider:

```c
OSSL_PROVIDER_load(libctx, "default");
OSSL_PROVIDER_set_default_search_path(libctx, "/path/to/hybrid.so/dir");
OSSL_PROVIDER_load(libctx, "hybrid");

/* KEM */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "X25519MLKEM768", NULL);

/* Signature */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "p256_mldsa44", NULL);

/* Composite signature (only when built with -DHYBRID_COMPOSITE) */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "mldsa44_ecdsa_p256", NULL);
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
