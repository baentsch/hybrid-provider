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

`hybrid_test` checks a fixed interop set — the four MLX hybrid KEMs mandated as
the default-provider interop baseline (`X25519MLKEM768`, `SecP256r1MLKEM768`,
`X448MLKEM1024`, `SecP384r1MLKEM1024`; see "Testing Requirements" in `CLAUDE.md`)
plus a hybrid-signature sampler spanning each ML-DSA level and classical family
(`p256_mldsa44`, `rsa3072_mldsa44`, `p384_mldsa65`, `p521_mldsa87`). It is the
focused cross-provider set, not the whole inventory; the in-provider round-trip
(keygen + encaps/decaps with shared-secret match, and sign/verify) is exercised
across the **entire** inventory — every `HYBRID_KEM_LIST`/`HYBRID_SIG_LIST` row
(and the composite families) — by `hybrid_leakcheck_test` (below), which asserts
functional correctness, not just leak-freedom, as it drives each path.

Each cross-provider block is skipped (not failed) when
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) is not on the
module path, so the suite passes with the default provider alone and gains the
oqsprovider composition checks when it is present. To enable those, symlink
`oqsprovider.so` into the module directory (see `test/setup_oqs_interop.sh`).

Beyond `hybrid_test`, `ctest` runs the rest of the suite: signature certificates
over TLS 1.3 (`hybrid_cert_tls_test`), config-driven component selection
(`hybrid_config_test`), private component contexts for Frodo/BIKE/HQC
(`hybrid_compctx_test`), SPKI/PKCS8 and raw-param round-trips
(`hybrid_encode_test`, `hybrid_param_test` — which also asserts that keygen,
encapsulate and sign draw randomness from the provider's own library-context
DRBG, by installing a deterministic test RAND in a private libctx), CMS
SignedData (`hybrid_cms_test`),
TLS code-point parity (`hybrid_capability_test`), provider coexistence
(`hybrid_coexist_test`), cede-to-default withdrawal of the default provider's
hybrids (`hybrid_cede_test`), robustness under adverse load and query/init
ordering (`hybrid_adverse_test` — merely activating the provider must not break
`SSL_CTX_new`; init tolerates being loaded before the default provider, being
activated twice, and a pre-registered colliding OID; the first fetch after load
resolves so the provider is never cached-disabled; retained algorithms never
overlap the default by name/OID/code point and ceding withdraws only what the
default actually serves; foreign key I/O is not shadowed; and repeated load
failure returns rather than hanging), concurrency / `fork()` / teardown stress
(`hybrid_threads_test`, below), the full cross-version matrix vs
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
(`hybrid_matrix_test`), the coverage guard asserting every hybrid
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) advertises is
also served here (`hybrid_coverage_test`), the X-Wing KAT interop check that
decapsulates the `draft-connolly-cfrg-xwing-kem` reference ciphertexts and
matches the draft's shared secret (`xwing_kat_test`, vectors vendored in
`test/xwing_kat.txt` with the draft's expanded decapsulation keys in
`test/xwing_kat_keys.txt` — raw-imported with no seed API, so the check runs
wherever ML-KEM-768 resolves, not only on 3.5+), the drop-in replacement test
over a
PQ-only [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
(`hybrid_replace_test`, below), and — with `-DHYBRID_COMPOSITE` — the composite
combiner, provider and draft-19 KAT tests (`composite_sig_test`,
`composite_test`, `composite_kat_test`) plus composite CMS `SignedData`
(`composite_cms_test`, below). Each self-skips cleanly when its prerequisites are
absent.

### Cross-provider methodology (`hybrid_methodology_test`)

Most of the suite pins `provider=hybrid` on every fetch. Two things a provider
that composes components from *whichever* provider supplies them must also
support are checked here (work-items item 15):

- **Pinned *and* unpinned resolution.** Each functional round-trip runs twice —
  once with the property query pinned to `provider=hybrid`, once with **no**
  property query — and both must pass, proving the provider's algorithms resolve
  through OpenSSL's normal implementation store, not only when explicitly pinned.
  Hybrid signatures are used, since the default provider ships no hybrid
  signatures and an unpinned fetch therefore resolves unambiguously here.
- **Config parameters without a `.cnf`.** The provider's configuration keys are
  set programmatically through `OSSL_PROVIDER_load_ex()`'s parameter array rather
  than a config-file section: the test loads with `cede-to-default=no` and
  confirms the provider then serves an MLX KEM it withdraws by default — the
  parameter was read and applied at init with no config file involved.

It draws all components from the default provider, so it needs no oqsprovider.

### Concurrency, fork and teardown (`hybrid_threads_test`)

Stresses the provider's shared/cached state (issue #43): the per-instance
cede-to-default runtime tables, the per-key size cache, and the provider
load/unload path. Four legs — many threads running keygen/encaps/decaps and
sign/verify with their own keys on one shared libctx; many threads operating on
the **same** key object (racing the first-use per-key size-cache fill); many
threads loading the provider into their own libctx, operating, and unloading; and
a `fork()`-then-operate leg. It uses `X25519MLKEM768` + `p256_mldsa44`, both
resolvable from the default provider on OpenSSL ≥ 3.5, so it needs no
oqsprovider. Run it under sanitizers:

```sh
# ThreadSanitizer (data races). setarch -R (wired into ctest) disables ASLR.
cmake -S . -B build-tsan -DOPENSSL_ROOT_DIR=/path/to/openssl -DHYBRID_TSAN=ON
cmake --build build-tsan --target hybrid-provider hybrid_threads_test
( cd build-tsan && ctest -R hybrid_threads_test --output-on-failure )

# It also runs in the full ASan/UBSan/LSan suite (-DHYBRID_SANITIZE=ON).
```

### Leak detection with teeth (`hybrid_leakcheck_test`)

The general `-DHYBRID_SANITIZE` leg runs LeakSanitizer with the fast unwinder, so
every leak stack is captured only as `[malloc, CRYPTO_malloc]`; the suite-wide
`test/lsan.supp` then matches that `libcrypto` frame and masks essentially any
leak — including a **future** unfreed allocation in the provider's own code
(all provider heap goes through `OPENSSL_malloc`). That leg therefore cannot, by
itself, catch a newly introduced provider leak (it still catches use-after-free /
overflow / double-free, which suppressions do not affect).

`hybrid_leakcheck_test` closes that gap. It exercises **and frees** every
provider allocation path — keygen/free, raw import/export, `match`, sign/verify,
encaps/decaps, encode/decode — across the whole inventory (hybrid + composite,
each algorithm self-skipping when inoperable), then **unloads every provider
before freeing the libctx** so teardown runs before LSan's check. Because it is
unload-clean it is pinned (via CMake `ENVIRONMENT`) to run against
`test/lsan_leakcheck.supp`, which suppresses only the un-instrumented PQ
dependencies and deliberately **omits** `leak:libcrypto`. A leak newly introduced
in any exercised provider path therefore surfaces unmasked and fails this test —
verified by injecting a deliberate leak, which this test catches while the
suite-wide leg masks it.

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
- **composite signatures** — standardized (ML-DSA) tier OpenSSL **3.5+** (the
  draft mandates a *seed* private key, which needs the 3.5 seed API); experimental
  (Falcon/MAYO/CROSS/UOV/SNOVA/MQOM2) tier **3.2+** (raw private key, no seed API),
- **composite KEMs** — standardized (ML-KEM) tier OpenSSL **3.5+** (seed private
  key); experimental (FrodoKEM/BIKE/HQC) tier **3.2+** (raw private key, no seed
  API). Below 3.5 the standardized ML-KEM combos self-deactivate and only the
  experimental composite KEMs are served; `composite_kem_prov_test` self-skips the
  rows it cannot serve on a given version.

The provider's encodable KEMs are also exercised as CMS `EnvelopedData` KEMRI
recipients (RFC 9629, `hybrid_cms_kem_test`): per composite combo, an in-process
encrypt → DER → decrypt round-trip plus a wrong-key negative, with the recipient
cert issued under a default-provider Ed25519 signer (a KEM key cannot self-sign).
No provider change is needed — OpenSSL's CMS layer auto-selects the KEM recipient
by probing `EVP_PKEY_encapsulate_init`. That auto-selection shipped with KEMRI in
OpenSSL **3.6.0** (3.5's CMS defaults a KEM key to key transport), so the whole
suite self-skips below 3.6 via a runtime capability probe rather than a version
check. KEMRI is **KEM-generic**, not composite- or ML-KEM-specific: any KEM with an
X.509 SPKI encoding can be a CMS recipient — plain native ML-KEM is the simplest
case (and is what the capability probe uses). The test therefore runs **both**
composite tiers to prove the path is primitive-generic: the standardized ML-KEM
combos (OIDs `.55..66`, PQ from the default provider on 3.5+) **and** the
experimental Frodo/BIKE/HQC combos (private OID arc, PQ from oqsprovider — loaded
optionally, so they self-skip when it is absent), exercising the same SPKI + KEMRI
path over non-ML-KEM PQ. Our MLX/X-Wing/SM2 TLS-group hybrids are excluded only
because they have no standalone X.509 key encoding (a serialization limit, not a
KEM one).

The composite **signature** family gets the `SignedData` counterpart in
`composite_cms_test` (issue #109, the sibling of `hybrid_cms_test` for the
concat family and of the KEMRI test above): per composite combo — both the
standardized ML-DSA tier and the experimental tier — a self-signed cert →
`SignedData` sign → verify round-trip plus a tampered-content negative, in **both**
SignerInfo modes (signed attributes and `-noattr`). Unlike KEMRI, this needed a
small provider addition: the composite signer now implements the
message-signature EVP API (`sign_message`/`verify_message_*`), which is what
OpenSSL's md-less CMS content-signing (`cms -sign -noattr`) drives — mirroring the
concat family's wiring. The `-noattr` cases self-skip below the base library's
md-less CMS content-signing floor (native ML-DSA fails identically on 3.5.x; the
path works from **3.6.0**), probed at runtime rather than by version; the provider
entry points themselves are proven regardless by a direct streaming round-trip, so
there is real coverage on 3.5.x too. Signing binds to the composite key
(`provider=hybrid` at keygen), so a co-loaded oqsprovider cannot shadow it.

Cross-implementation interop for the composite KEM lives in **opt-in harnesses**
— not wired into `ctest`, because each needs resources `ctest` cannot assume (a
peer binary, network access, an external corpus, and — for the CMS harnesses —
OpenSSL **3.6.0+**). Each self-skips cleanly (exit 0) when its prerequisites are
absent, and FAILs only on a real mismatch:

- **`test/pqc_kem_cms_interop.sh`** — **both-way** CMS KEMRI interop against
  [kemri_toy](https://github.com/carl-wallace/kemri_toy) (an independent
  RustCrypto RFC 9629 tool), fully local. It drives the **full standardized matrix
  that the provider serves** (discovered at run time — no frozen combo list that
  could go stale as kemri_toy evolves), handing kemri_toy our cert/key so it needs
  no `--kem` name: per combo kemri_toy encrypts → we decrypt, and we encrypt →
  kemri_toy decrypts. kemri_toy pins composite-kem **draft-12** vs our **-18**, so
  it classifies honestly: `OK` (both agree), `SKEW` (differ yet our output is
  re-checked self-valid, so a real regression still fails), `SKIP` (kemri_toy
  errors on the combo — `*` if its `--help` advertises the combo yet it still
  errored, so the discrepancy stays visible). Representative run: 7 OK, 1 SKEW
  (`.56`), 4 SKIP (`.61`/`.64` absent; `.58`/`.65` advertised-but-errored), 0 FAIL.
- **`test/pqc_kem_cms_certificates_interop.sh`** — multi-peer read of the IETF
  Hackathon pqc-certificates **`cms_v3`** EnvelopedData corpus: per peer it
  downloads `artifacts_cms_v3.zip` and, for every composite-KEM OID shipping a
  KEMRI blob (HKDF-SHA256, draft-18, arc `.55..66`), decrypts it with
  hybrid-provider and checks the recovered plaintext equals the peer's
  `expected_plaintext.txt` — "third party generated, we read", including the
  brainpool combos (`.61`/`.64`) kemri_toy cannot produce. Representative run:
  **12/12 from each of two independent draft-18 impls** (`composite-crypto`,
  `bc`), 0 FAIL. Like the decaps companion it also has a `generate` mode that
  emits our own `cms_v3` artifacts (+ self-verify) for a potential
  `providers/hybrid-provider/` submission (none made yet).
- **`test/pqc_kem_certificates_interop.sh`** — the KEM-decapsulation companion to
  the two above: reads the corpus's raw composite-KEM decaps vectors
  (`_ciphertext.bin` + `_ss.bin`) instead of CMS (3.5+; details in
  [docs/pqc-kem-certificates-interop.md](docs/pqc-kem-certificates-interop.md)).

All composite tests run only when built with the composite family
(`-DHYBRID_COMPOSITE`).

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
provider's EVP-based composition tracks OpenSSL's built-in MLX hybrid closely —
the time is spent in the underlying primitives, and the glue is small (see the
guard below). The remaining configurations compare component implementations (e.g.
default-provider vs
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) ML-KEM/ML-DSA)
in the same process. Run `hybrid_bench` in your own environment for numbers.

**Machine-checked composition-overhead guard.** After the informational report,
`hybrid_bench` runs the **same sum-of-components guard** as the composite benches
(shared code in `test/bench_util.c`): a hybrid IS its two constituent components
plus a small combiner glue, so the guard asserts each hybrid's steady-state ops
stay within **1.4×** the *sum of its components* measured standalone, exiting
non-zero (gating the `hybrid_bench` ctest) on breach. It iterates the provider's
**own** `hybrid_{kem,sig}_table`, so the peer fetches each component by the exact
name the provider composes with — same implementation by construction. That single
property removes everything the old native-peer model needed: no native peer, no
`FAIR`/`UNFAIR` matching, and **no version-gating** — because the peer literally
is the two components, any per-component cost (including oqsprovider's `no_cache`
tax) cancels in the ratio on every OpenSSL version.

Measured this way the glue is small: **~1.0× for signatures** and **up to ~1.2×
for the fastest KEMs** (the SHA3-256 combiner pass / provider dispatch on a
~0.07 ms base), and a hybrid is at **parity with oqsprovider's own hybrid** for the
same algorithm. Three things keep the tight bound sound:

- **Keygen is excluded** — randomised (rejection sampling, fresh entropy), a
  heavy-tailed variable whose ratio measures keygen's variance, not glue.
- **Minimum per-op latency, no harness churn** — the reported per-op figure is the
  *minimum* over a budgeted run (noise only adds time, so the ratio stays stable; a
  batch/chunk mean was tried and flaked the fast standardized-composite signatures
  to 1.3–1.65× on ≥3.5). The output buffer and size query are set up once and reused
  and the clock is read once per op, so per-op `malloc`/`free` and timer calls are
  not charged to the crypto (they dominated the fast primitives at the short ctest
  budget). What is deliberately **not** hoisted is the per-op EVP context creation +
  operation `_init` — a composed op re-inits its two components on every call
  (re-paying oqsprovider's per-op `no_cache` fetch on ≥3.5, and a composite's
  combiner setup), so the standalone components re-init per op too and that cost
  cancels in the ratio; hoisting it made fast oqsprovider KEMs read 2–7×.
- **The composed op is measured with its provider's property query** (as real
  callers / libssl do). Signing a provider-native key with a *NULL* propq instead
  forces a per-op cross-provider resolution that can dwarf the crypto for fast
  primitives — an early version of this guard did that and mis-measured fast-UOV
  and RSA hybrids by up to ~18×; with the explicit propq every hybrid, RSA
  included, sits at ~1.0×.

Validated ~1.0–1.2× across the full provider table on the OpenSSL versions CI
covers (a pre-3.5 release, a current &ge;3.5 release, and `master`). Under a
**sanitizer** (ASan/TSan) the assertion is **skipped** — the
instrumentation's large, uneven slowdown inflates the ratios and would flake the
guard — while the informational report still runs. The guard runs with
cede-to-default off so it measures the hybrid provider's own MLX implementation.

### Composite signature benchmark

`composite_sig_bench` (built only with `-DHYBRID_COMPOSITE`) reports, for **every**
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
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./composite_sig_bench [budget_ms]
```

The optional `budget_ms` argument is the per-operation wall-clock budget: each
measurement loops until that budget (or an iteration cap) is reached, so slow
keygens (UOV/MQOM/CROSS) don't dominate while fast verifies still get enough
samples. It defaults to 1000; `ctest` runs it with a short budget as a smoke
test, so pass a larger value (e.g. `./composite_sig_bench 2000`) for stable numbers.

**Machine-checked composition-overhead guard.** After the report, the bench
asserts (and exits non-zero on breach, gating the `composite_sig_bench` ctest)
that each composite's **sign/verify** stays within **1.4×** the *sum of its two
standalone components* — the shared sum-of-components model used by all three
benches (`test/bench_util.c`; the hybrid family uses the identical guard). A
composite signature is one PQ signature plus one classical signature over the same
message, and because the peer literally *is* the two components, any per-component
cost (including oqsprovider's `no_cache` tax) cancels; what remains is the
combiner's own glue, observed at ~1.0× (composite signatures sit right at parity).
Keygen is excluded (randomised, heavy-tailed); timings reuse their buffers and take
the per-op minimum so scheduler spikes don't flake the ratio of two small numbers;
and the assertion is skipped under a sanitizer (timing is unreliable there). See the
`hybrid_bench` section above for the shared timing model.

An illustrative results snapshot and the deployment recommendations that follow
from it are in [composite-sig-bench-results.md](composite-sig-bench-results.md)
(numbers are hardware-specific — regenerate for your own environment).

### Composite KEM benchmark

`composite_kem_bench` is the KEM analogue: for **every** composite ML-KEM — the
standardized combos *and* the experimental FrodoKEM/BIKE/HQC combos — plus a few
pure-ML-KEM reference rows, it reports

- **keygen / encaps / decaps** time (ms),
- **pk** (SubjectPublicKeyInfo DER length), **ct** (composite ciphertext length)
  and **sk** (PKCS8 private-key DER length) in bytes.

Same grouping (by NIST level), budget argument and skip-on-unavailable behaviour
as `composite_sig_bench`; the experimental rows need
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider).

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./composite_kem_bench [budget_ms]
```

It carries the same **sum-of-components guard** as `composite_sig_bench`: after the
report it asserts each composite's **encaps/decaps** within **1.4×** the sum of its
ML-KEM component and its classical KEM (DHKEM = ephemeral keygen + derive, or
RSA-OAEP), gating the `composite_kem_bench` ctest. The component contexts are set
up per-op (as the combiner does internally), so oqsprovider's per-op `no_cache` tax
cancels symmetrically rather than inflating fast Frodo/BIKE rows. Observed
~1.0×, rising to ~1.2× only for the fastest combo (`mlkem768_p256`), where the
combiner's SHA3-256 KDF is a fixed cost on a ~0.07 ms base.

An illustrative snapshot and per-axis analysis are in
[composite-kem-bench-results.md](composite-kem-bench-results.md).

### Cross-provider interop + performance matrix

`provider_matrix` (CMake target `provider_matrix`) is a manual tool — not a
ctest — that loads the default provider alongside every sibling provider found
on the module path (wolfProvider `libwolfprov.so`, mldsa-native-provider
`mldsanative.so`, oqsprovider) plus the hybrid provider, then:

1. proves cross-provider interop — ML-DSA sign×verify and ML-KEM encaps/decaps
   across every provider pair, and hybrid-KEM wire compatibility (the hybrid
   provider's composed key vs the native MLX groups, both directions, via
   public-key export/import);
2. tabulates performance — the "naked" ML-DSA/ML-KEM primitives of each provider
   side by side, then the hybrid/composite figures with the PQ component sourced
   from each provider in turn (classical half pinned to default via
   `classic-propquery`).

It needs the sibling modules symlinked onto `OPENSSL_MODULES` (an absolute path,
since the generated cnf's `module=` is relative to it). Run with a per-op budget
in ms:

```sh
LD_LIBRARY_PATH=/path/to/openssl/lib64 OPENSSL_MODULES=$PWD ./provider_matrix 300
```

Build and run instructions for the external providers, and a captured result
set, are in [provider-interop-results.md](provider-interop-results.md).
