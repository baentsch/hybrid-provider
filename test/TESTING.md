# Test inventory, redundancy review, and per-algorithm coverage

This file inventories every test in `test/`, records a redundancy review, and
tabulates how many tests each of the provider's 138 algorithms is actually
exercised by. The root [TESTING.md](../TESTING.md) remains the how-to-run guide;
this file is the *what-covers-what* map.

> **Note on the path:** the request asked for `tests/TESTING.md`; this project's
> test directory is `test/` (singular), so the file lives at `test/TESTING.md`.

## How the counts were produced

- Build: `build-exp-kemenc` — OpenSSL **4.2.0-dev**, `-DHYBRID_COMPOSITE=ON`,
  `-DHYBRID_KEM_ENCODERS=ON`, with `oqsprovider.so` (GitHub main) on the module
  path. This is the **maximal-coverage** configuration: native ML-KEM/ML-DSA
  from the default provider (3.5+), the composite tiers, the KEM key-file
  encoders, and the oqsprovider-sourced research families are all live, so the
  fewest rows self-skip. Counts on 3.0–3.4 or without oqsprovider are strictly
  lower (more skips).
- Command: `ctest -V` (full suite, 40 tests, all passed).
- Attribution: each algorithm's public name was matched as a whole token in the
  per-test verbose output and classified **run** (appears on at least one
  non-SKIP line) vs **skipped** (appears only on SKIP lines). Nine tests report
  aggregate results instead of per-algorithm lines; their coverage was attributed
  from the summary line + source (see the table footnote).

## Redundancy review

**Verdict: no test is removable; all 40 survive.** The suite is deliberately
layered and the overlaps are complementary, not duplicative:

- **Different oracle.** `hybrid_test` crosses KEMs against the *default*
  provider's built-in MLX groups; `hybrid_oqs_test`/`hybrid_matrix_test` cross
  against *oqsprovider*; the two peers implement disjoint name sets.
- **Different layer.** `composite_sig_test`/`composite_kem_test` drive the
  combiners (`composite_sig.c` / `composite_kem.c`) directly as unit tests;
  `composite_test` drives the same algorithms through EVP by name at the
  provider boundary.
- **Different transport.** `hybrid_cert_tls_test` runs signature certs over an
  in-process TLS handshake; `hybrid_scenarios_sig_certs` runs the same families
  through the `openssl` CLI in separate processes.
- **Different surface.** `hybrid_param_test` (raw `OSSL_PARAM`),
  `hybrid_encode_test` (SPKI/PKCS8 DER), `hybrid_text_test` (`-text`),
  `hybrid_extract_test` (component split), and `hybrid_decode_neg_test`
  (malformed input) each hit a distinct serialization/decode path.
- **KAT vs self-consistency.** `*_kat_test` / `xwing_kat_test` pin behaviour to
  external draft vectors; the interop/round-trip tests only prove internal
  consistency.

**Closest real overlap (flagged, retained):** `hybrid_matrix_test` (#21) is a
table-complete superset of `hybrid_oqs_test` (#5) for KEM interop. #5 is kept
because it is the named **M3 acceptance** test and specifically exercises the
TLS-share `ENCODED_PUBLIC_KEY` exchange path for the OQS-legacy ML-KEM hybrids;
#21 is positioned as the full-matrix drift guard. Both are small and fast.

## Test purposes (two lines each)

### In-process functional (`ctest` #1–#30, #37–#40)

#### 1. hybrid_interop_test

(`hybrid_test.c`) — Baseline KEM interop vs the default provider's built-in MLX groups, plus KEM/sig self-consistency, key round-trip and negative paths; under composite it also drives the composite ML-KEMs.
#### 2. hybrid_tls_test

— In-process TLS 1.3 handshake over dual libctx/memory BIOs, negotiating hybrid KEM groups between a hybrid peer and a default/oqs peer, plus hybrid↔hybrid self-handshakes for the hybrid-only draft-preussmattsson HQC groups (no external peer serves those names).
#### 3. hybrid_config_test

— cnf/propquery-driven component selection: pq-/classic- propquery route each half to the right provider; keygen succeeds/fails as set.
#### 4. hybrid_methodology_test

— Unpinned (store) property-query resolution and programmatic config via `OSSL_PROVIDER_load_ex()` with no `.cnf` (3.5+).
#### 5. hybrid_oqs_test

— M3 acceptance: cross-encap/decap of the OQS-legacy ML-KEM hybrids vs oqsprovider via `ENCODED_PUBLIC_KEY`, both directions; skips if absent.
#### 6. hybrid_replace_test

— Drop-in proof: with oqsprovider in PQ-only mode (`OQS_CEDE_HYBRIDS`), hybrid must serve every hybrid; fails if oqs present but not ceding.
#### 7. hybrid_compctx_test

— Private component context so Frodo/BIKE/HQC bases come from hybrid's own libctx (no app group collision) and work over TLS; needs oqs.
#### 8. hybrid_encode_test

— SPKI/PKCS8 key-encoder interop: hybrid-written DER decoded and verified by oqsprovider and vice versa (signature families).
#### 9. hybrid_extract_test

— Component extraction/recompose: pull each public+private component out of a hybrid/composite key, assert its inner encoding == the standalone component. Self-skips a row only when a *standalone* component genuinely cannot be serialized — the research KEMs (Frodo/BIKE/HQC) and `curveSM2`, whose encoder is registered but **has no assigned X.509 OID**, so `i2d_PUBKEY`/`EVP_PKEY2PKCS8` errors (not a missing encoder, not an `OQS_KEM_ENCODERS` build gap — the flag is on here; upstream OID gap). An otherwise-serializable component that fails to extract is a hard FAIL, never a skip.
#### 10. hybrid_capability_test

— TLS-GROUP/TLS-SIGALG code-point parity: our code points vs the live default/oqsprovider advertisement (drift guard).
#### 11. hybrid_log_test

— `hybrid_log()` diagnostics: `HYBRID_LOG=1` reports the drop of an inoperable hybrid (a Frodo group in a default-only ctx); silent when unset.
#### 12. hybrid_cert_tls_test

— End-to-end hybrid-signature X.509 cert over an in-process TLS 1.3 handshake; per-algorithm self-skip when components absent.
#### 13. hybrid_kem_encode_test

— KEM key-file SPKI+PKCS8 round-trip vs oqsprovider (`HYBRID_KEM_ENCODERS`); under composite also self-round-trips composite KEM files.
#### 14. hybrid_coexist_test

— Fetch-only coexistence over the whole hybrid inventory (M8 drop-in contract); proves hybrid↔default/oqs coexistence without a PQ base.
#### 15. hybrid_param_test

— Raw `EVP_PKEY` `OSSL_PARAM` export/import round-trip and gettable-param parity across the full tables (distinct from the DER encoders).
#### 16. hybrid_text_test

— `pkey -text` coverage: every key type prints a named, two-component, non-truncated text form (hybrid + composite families).
#### 17. hybrid_decode_neg_test

— Decoder robustness: multi-object PEM (target not first) and malformed/truncated/garbage SPKI must fail cleanly, no crash (ASan).
#### 18. hybrid_cms_test

— CMS SignedData with hybrid signatures (signed-attr and `-noattr`); `OQS_CEDE_HYBRIDS` so our names aren't shadowed; per-alg self-skip.
#### 19. hybrid_threads_test

— Concurrency/fork/teardown stress (X25519MLKEM768 + p256_mldsa44): shared-key threads, concurrent load/unload, fork-then-operate.
#### 20. hybrid_sizes_test

— Component-size constant-table verifier: re-derives the compile-time per-component sizes from live keygens and fails on drift (86 hybrids).
#### 21. hybrid_matrix_test

— Full-matrix cross-version interop vs oqsprovider driven by the master tables, so EVERY hybrid KEM+SIG is crossed; nothing silently omitted.
#### 22. hybrid_coverage_test

— Coverage guard (inverse of #21): every hybrid oqs advertises must appear in our tables; catches whole families omitted.
#### 23. xwing_kat_test

— X-Wing KAT interop: decapsulate the draft's reference ciphertexts under its decap keys; on 3.5+ also re-derives keys from seeds.
#### 24. composite_sig_test

— Composite combiner self-consistency, driving `composite_sig.c` directly (unit level, below the provider).
#### 25. composite_test

— Provider-level composite signatures through EVP by name (`provider=hybrid`): keygen/sign/verify per combo.
#### 26. composite_cms_test

— Composite signatures as CMS SignedData (signed attrs + `-noattr`) per combo, plus the direct message-signature API round-trip.
#### 27. composite_kat_test

— draft-19 reference KAT interop for composite signatures (cross-impl vs lamps-wg/draft-composite-sigs); 3.5+ only.
#### 28. composite_kem_test

— Composite KEM combiner self-consistency + draft X25519 combiner KAT, driving `composite_kem.c` directly over EVP-generated components. Covers **both** tiers — standardized ML-KEM from the default provider (3.5+) and experimental Frodo/BIKE/HQC from oqsprovider (best-effort loaded; combos self-skip only if their PQ provider is absent).
#### 29. composite_kem_kat_test

— draft-18 composite ML-KEM KAT interop: decapsulate reference ciphertexts and recover the reference shared secret; 3.5+ only.
#### 30. hybrid_cms_kem_test

— Composite KEM as CMS EnvelopedData KEMRI recipient (RFC 9629): encrypt→DER→decrypt + wrong-key negative per combo, both tiers; 3.5+.
#### 37. hybrid_cede_test

— cede-to-default lever, table-driven over the whole inventory: resolves with ceding off, and only when default doesn't serve it with ceding on.
#### 38. hybrid_adverse_test

— Provider robustness under adverse load/coexistence/init ordering (issue #47): activation must not break `SSL_CTX_new`; a TIMEOUT fails hangs.
#### 39. hybrid_leakcheck_test

— Leak-check with teeth: exercise+free every allocation path across all 138 algorithms, unload-clean before LSan (no broad libcrypto catch-all).

### Benchmarks (guard-only smoke under `ctest`)

"Smoke" here means *few iterations + guard-only*, not a reduced algorithm set.
Under `ctest` these run with a tiny budget (`hybrid_bench 10`, `composite_*_bench
100`ms/op) and `HYBRID_BENCH_GUARD_ONLY=1`, which suppresses the informational
per-combo report and keeps only the composition-overhead guard (min-latency of
the composed op vs the sum of its components, asserted within a ceiling). The
guard covers every combo it can decompose into a *native component baseline*;
rows with no such baseline are skipped — the RSA-wrapped composite KEMs
(`mlkem*_rsa*`, keygen/latency variance) and the provider-private PQ/PQ hybrid
sigs (`mldsa65_falcon1024`, `mldsa44_mayo1`, `mldsa65_p256`, no native-peer sum).
The full per-combo report (every algorithm) prints when run with a larger budget,
e.g. `hybrid_bench 1000` / `composite_sig_bench 2000`. Correctness for every
combo is covered elsewhere (#1/#21 hybrids, #24–#30 composite).

All three carry the ctest label **`bench`** and are `RUN_SERIAL` (their
min-latency guard skews under concurrent load). They are therefore kept off the
fast PR gate — the regular and sanitize CI legs run `ctest -LE bench` (functional
only) — and run as a group, `ctest -L bench`, in a dedicated **post-merge** CI job
where a composition-overhead regression surfaces as a red build tied to the merge
commit. Locally: `ctest -L bench` runs just these three; `ctest -LE bench` runs
the functional suite without them (the fast inner loop). See design.md
"Continuous integration tiers" (the *bench* leg) for the rationale.

#### 31. composite_sig_bench

— Composite cert size + cert-gen/verify benchmark; under ctest a guard-only smoke asserting composition overhead stays within ceiling.
#### 32. composite_kem_bench

— Composite KEM keygen/encaps/decaps timing + pk/ct/sk sizes; guard-only smoke under ctest (RUN_SERIAL), guard excludes the 4 RSA combos.
#### 40. hybrid_bench

— Hybrid vs native (default/oqs) benchmark; under ctest a guard-only smoke asserting the composition min-latency ratio stays within ceiling.

### Build-count guard

#### 33. hybrid_count_test

— Guards the README "Algorithms served:" headline: recomputes the counts from the source-of-truth tables and asserts the number matches.

### Separate-process CLI harnesses (`test/hybrid_scenarios.sh`)

#### 34. hybrid_scenarios_tls_compctx

— CLI (`s_server`/`s_client`) TLS interop for Frodo/BIKE/HQC hybrids via the private component context vs a pure-oqs peer.
#### 35. hybrid_scenarios_sig_certs

— CLI end-to-end for hybrid + composite sigs: `genpkey` → self-signed cert → verify → `x509 -text` → CMS sign/verify.
#### 36. hybrid_scenarios_sig_interop

— Cross-provider private-key-file interop for hybrid signatures: hybrid-written key read back by oqs and vice versa (composite excluded).

### Not wired into `ctest` (manual tools / fixtures)

- **provider_matrix** (`provider_matrix.c`) — Cross-provider interop + performance
  matrix vs wolfProvider/mldsa-native-provider/OpenSSL-master; needs sibling modules symlinked.
- **hybrid_decode_fuzz** (`-DHYBRID_FUZZ`) — libFuzzer / corpus-replay harness for the
  untrusted SPKI/PKCS8 decode surface under ASan (becomes a ctest only in corpus mode).
- **probe_oqs_hybrid.c** — Small helper that probes which hybrids a given oqsprovider serves.
- **pqc_*_interop.sh** (4 scripts) + **setup_oqs_interop.sh** — External-corpus / oqs
  build-and-link harnesses used by CI and by hand, not registered as ctests.
- **KAT fixtures + regen scripts** — `*_kat*.txt`, `xwing_kat*.txt`, `regen_*.py`
  (vectors and their offline regenerators); `bench_util.{c,h}` (shared bench helpers).

## Per-algorithm coverage

`#tests run` = ctest tests that exercised the algorithm on a non-SKIP path;
`#tests skipped` = tests that iterated it but skipped. Totals reflect the
maximal-coverage build above. Each cell lists the contributing test ids (linked
to their descriptions above).

**Skip-reason legend** — why a given test-id appears in a *skipped* cell (every
skip in the tables below is one of these, all structural, none a failure):

| id | test | a skip here means |
|--:|---|---|
| [5](#5-hybrid_oqs_test)  | hybrid_oqs_test       | oqsprovider doesn't serve this name here — it covers only the OQS-legacy ML-KEM hybrids, so X-Wing-style / HQC-KEM-draft / `exphyb` rows self-skip. |
| [8](#8-hybrid_encode_test) | hybrid_encode_test  | no cross-provider peer owns the identifier — the provider-private PQ/PQ sigs have no oqsprovider counterpart to round-trip SPKI against. |
| [9](#9-hybrid_extract_test) | hybrid_extract_test | the standalone component has **no assigned X.509 OID**, so its SPKI/PKCS8 encode errors (research KEMs Frodo/BIKE/HQC; `curveSM2`). Encoder is registered and `OQS_KEM_ENCODERS` is on — it is an upstream OID gap, not a build gap. |
| [21](#21-hybrid_matrix_test) | hybrid_matrix_test | no second provider implements the name to cross against (X-Wing / experimental KEM rows; provider-private PQ/PQ sigs). |
| [35](#35-hybrid_scenarios_sig_certs) | hybrid_scenarios_sig_certs | the experimental composite sigs' PQ base is unavailable to the CLI provider config on this leg (`keygen unavailable`). |

Three whole-inventory tests are attributed to every algorithm they cover from
their aggregate summary lines rather than per-name output:
`hybrid_coexist_test` (#14), `hybrid_sizes_test` (#20) and `hybrid_cede_test`
(#37) over the 86 hybrids; `hybrid_leakcheck_test` (#39) over all 138. Single-
target summary tests are likewise attributed: `hybrid_config_test` (#3) and
`hybrid_threads_test` (#19) → X25519MLKEM768; #19 → p256_mldsa44;
`hybrid_log_test` (#11) → p256_frodo640aes. `hybrid_adverse_test` (#38) and
`hybrid_count_test` (#33) touch no specific inventory algorithm and are omitted.

### Hybrid KEMs (56)

| Algorithm | #tests run (ids) | #tests skipped (ids) | total |
|---|---|---|--:|
| `X25519MLKEM768` | 16 ([1](#1-hybrid_interop_test), [2](#2-hybrid_tls_test), [3](#3-hybrid_config_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [19](#19-hybrid_threads_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 16 |
| `X448MLKEM1024` | 13 ([1](#1-hybrid_interop_test), [2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 13 |
| `SecP256r1MLKEM768` | 14 ([1](#1-hybrid_interop_test), [2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `SecP384r1MLKEM1024` | 15 ([1](#1-hybrid_interop_test), [2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [13](#13-hybrid_kem_encode_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 15 |
| `curveSM2MLKEM768` | 13 ([1](#1-hybrid_interop_test), [2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x25519_mlkem512` | 15 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [13](#13-hybrid_kem_encode_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 15 |
| `SecP256r1MLKEM512` | 15 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [13](#13-hybrid_kem_encode_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 15 |
| `bp256_mlkem512` | 14 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `p384_mlkem768` | 14 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `x448_mlkem768` | 14 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `bp384_mlkem768` | 14 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `p521_mlkem1024` | 14 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `bp512_mlkem1024` | 14 ([2](#2-hybrid_tls_test), [5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 14 |
| `p256_frodo640aes` | 15 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [11](#11-hybrid_log_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 16 |
| `x25519_frodo640aes` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `p256_frodo640shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x25519_frodo640shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p384_frodo976aes` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `x448_frodo976aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p384_frodo976shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x448_frodo976shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p521_frodo1344aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p521_frodo1344shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p256_efrodo640aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x25519_efrodo640aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p256_efrodo640shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x25519_efrodo640shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p384_efrodo976aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x448_efrodo976aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p384_efrodo976shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x448_efrodo976shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p521_efrodo1344aes` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p521_efrodo1344shake` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p256_bikel1` | 12 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 13 |
| `x25519_bikel1` | 12 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 13 |
| `p384_bikel3` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `x448_bikel3` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `p521_bikel5` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `p256_hqc1` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `x25519_hqc1` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p384_hqc3` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `x448_hqc3` | 13 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 14 |
| `p521_hqc5` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [7](#7-hybrid_compctx_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [34](#34-hybrid_scenarios_tls_compctx), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([9](#9-hybrid_extract_test)) | 15 |
| `X-Wing` | 9 ([9](#9-hybrid_extract_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [23](#23-xwing_kat_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([21](#21-hybrid_matrix_test)) | 10 |
| `xwing_x25519_mlkem1024` | 8 ([9](#9-hybrid_extract_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([21](#21-hybrid_matrix_test)) | 9 |
| `xwing_p256_mlkem768` | 8 ([9](#9-hybrid_extract_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([21](#21-hybrid_matrix_test)) | 9 |
| `xwing_x448_mlkem1024` | 8 ([9](#9-hybrid_extract_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 1 ([21](#21-hybrid_matrix_test)) | 9 |
| `xwing_x25519_efrodo640aes` | 7 ([14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 2 ([9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 9 |
| `xwing_mlkem768_hqc3` | 7 ([14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 2 ([9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 9 |
| `exphyb_p256_frodo640aes` | 10 ([6](#6-hybrid_replace_test), [13](#13-hybrid_kem_encode_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [30](#30-hybrid_cms_kem_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |
| `HQCKEM192X25519` | 10 ([2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |
| `HQCKEM256X448` | 10 ([2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |
| `HQCKEM192MLKEM768` | 10 ([2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |
| `HQCKEM256MLKEM1024` | 10 ([2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |
| `HQCKEM192MLKEM768X25519` | 10 ([2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |
| `HQCKEM256MLKEM1024X448` | 10 ([2](#2-hybrid_tls_test), [6](#6-hybrid_replace_test), [10](#10-hybrid_capability_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [20](#20-hybrid_sizes_test), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 3 ([5](#5-hybrid_oqs_test), [9](#9-hybrid_extract_test), [21](#21-hybrid_matrix_test)) | 13 |

### Hybrid signatures (30)

| Algorithm | #tests run (ids) | #tests skipped (ids) | total |
|---|---|---|--:|
| `p256_mldsa44` | 21 ([1](#1-hybrid_interop_test), [4](#4-hybrid_methodology_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [19](#19-hybrid_threads_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 21 |
| `rsa3072_mldsa44` | 19 ([1](#1-hybrid_interop_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p384_mldsa65` | 20 ([1](#1-hybrid_interop_test), [4](#4-hybrid_methodology_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 20 |
| `p521_mldsa87` | 19 ([1](#1-hybrid_interop_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_falcon512` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `rsa3072_falcon512` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p521_falcon1024` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_falconpadded512` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `rsa3072_falconpadded512` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p521_falconpadded1024` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_mayo1` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_mayo2` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p384_mayo3` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p521_mayo5` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_OV_Is_pkc` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_OV_Ip_pkc` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_OV_Is_pkc_skc` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_OV_Ip_pkc_skc` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_snova2454` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_snova2454esk` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_snova37172` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p384_snova2455` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p521_snova2965` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p256_mqom2cat1gf16fastr5` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p384_mqom2cat3gf16fastr5` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `p521_mqom2cat5gf16fastr5` | 19 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [8](#8-hybrid_encode_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [21](#21-hybrid_matrix_test), [22](#22-hybrid_coverage_test), [35](#35-hybrid_scenarios_sig_certs), [36](#36-hybrid_scenarios_sig_interop), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 0 | 19 |
| `mldsa65_falcon1024` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [35](#35-hybrid_scenarios_sig_certs), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test)) | 2 ([8](#8-hybrid_encode_test), [21](#21-hybrid_matrix_test)) | 16 |
| `mldsa44_mayo1` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [35](#35-hybrid_scenarios_sig_certs), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test)) | 2 ([8](#8-hybrid_encode_test), [21](#21-hybrid_matrix_test)) | 16 |
| `falcon512_mayo1` | 15 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [35](#35-hybrid_scenarios_sig_certs), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test), [40](#40-hybrid_bench)) | 2 ([8](#8-hybrid_encode_test), [21](#21-hybrid_matrix_test)) | 17 |
| `mldsa65_p256` | 14 ([5](#5-hybrid_oqs_test), [6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [10](#10-hybrid_capability_test), [12](#12-hybrid_cert_tls_test), [14](#14-hybrid_coexist_test), [15](#15-hybrid_param_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [18](#18-hybrid_cms_test), [20](#20-hybrid_sizes_test), [35](#35-hybrid_scenarios_sig_certs), [37](#37-hybrid_cede_test), [39](#39-hybrid_leakcheck_test)) | 2 ([8](#8-hybrid_encode_test), [21](#21-hybrid_matrix_test)) | 16 |

### Composite signatures (31)

| Algorithm | #tests run (ids) | #tests skipped (ids) | total |
|---|---|---|--:|
| `mldsa44_rsa2048_pss` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa44_rsa2048_pkcs15` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa44_ed25519` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa44_ecdsa_p256` | 12 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [12](#12-hybrid_cert_tls_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 12 |
| `mldsa65_rsa3072_pss` | 12 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [12](#12-hybrid_cert_tls_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 12 |
| `mldsa65_rsa3072_pkcs15` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa65_rsa4096_pss` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa65_rsa4096_pkcs15` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa65_ecdsa_p256` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa65_ecdsa_p384` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa65_ecdsa_bp256` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa65_ed25519` | 12 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [12](#12-hybrid_cert_tls_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 12 |
| `mldsa87_ecdsa_p384` | 12 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [12](#12-hybrid_cert_tls_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 12 |
| `mldsa87_ecdsa_bp384` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa87_ed448` | 12 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [12](#12-hybrid_cert_tls_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 12 |
| `mldsa87_rsa3072_pss` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa87_rsa4096_pss` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `mldsa87_ecdsa_p521` | 11 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [27](#27-composite_kat_test), [31](#31-composite_sig_bench), [35](#35-hybrid_scenarios_sig_certs), [39](#39-hybrid_leakcheck_test)) | 0 | 11 |
| `exp_falconpadded512_ecdsa_p256` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_falconpadded1024_ecdsa_p521` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_mayo2_ecdsa_p256` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_mayo3_ecdsa_p384` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_mayo5_ecdsa_p521` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_cross128bal_ecdsa_p256` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_ovIspkc_ecdsa_p256` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_snova2454_ecdsa_p256` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_snova2455_ecdsa_p384` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_snova2965_ecdsa_p521` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_mqom2cat1_ecdsa_p256` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_mqom2cat3_ecdsa_p384` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |
| `exp_mqom2cat5_ecdsa_p521` | 9 ([6](#6-hybrid_replace_test), [9](#9-hybrid_extract_test), [16](#16-hybrid_text_test), [17](#17-hybrid_decode_neg_test), [24](#24-composite_sig_test), [25](#25-composite_test), [26](#26-composite_cms_test), [31](#31-composite_sig_bench), [39](#39-hybrid_leakcheck_test)) | 1 ([35](#35-hybrid_scenarios_sig_certs)) | 10 |

### Composite KEMs (21)

| Algorithm | #tests run (ids) | #tests skipped (ids) | total |
|---|---|---|--:|
| `mlkem768_rsa2048` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `mlkem768_rsa3072` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `mlkem768_rsa4096` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `mlkem768_x25519` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem768_p256` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem768_p384` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem768_bp256` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem1024_rsa3072` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `mlkem1024_p384` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem1024_bp384` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem1024_x448` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `mlkem1024_p521` | 8 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [29](#29-composite_kem_kat_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 8 |
| `exp_frodo640aes_p256` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_frodo976aes_p384` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_frodo1344aes_p521` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_bikel1_p256` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_bikel3_p384` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_bikel5_p521` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_hqc1_p256` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_hqc3_p384` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
| `exp_hqc5_p521` | 7 ([1](#1-hybrid_interop_test), [13](#13-hybrid_kem_encode_test), [16](#16-hybrid_text_test), [28](#28-composite_kem_test), [30](#30-hybrid_cms_kem_test), [32](#32-composite_kem_bench), [39](#39-hybrid_leakcheck_test)) | 0 | 7 |
