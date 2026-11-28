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
  built-in MLX KEM (RFC 10024, ex draft-ietf-tls-ecdhe-mlkem) for interoperability.

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
├── test/
    ├── hybrid_test.c              ← interop tests against default provider
    ├── hybrid_tls_test.c          ← in-process TLS 1.3 handshake interop (dual libctx)
    ├── hybrid_cert_tls_test.c     ← signature certs over TLS 1.3
    ├── hybrid_encode_test.c       ← SPKI/PKCS8 key round-trips vs oqsprovider
    ├── hybrid_kem_encode_test.c   ← KEM key-file round-trips: hybrid↔oqs (HYBRID_KEM_ENCODERS) + composite self (HYBRID_COMPOSITE)
    ├── hybrid_param_test.c        ← raw-param (OSSL_PARAM) round-trips
    ├── hybrid_op_neg_test.c       ← sign/verify + encaps/decaps misuse negatives (all families)
    ├── hybrid_dispatch_test.c     ← dup / ctx-dup / introspection / set_params entry points
    ├── hybrid_alloc_fail_test.c   ← fail each provider allocation in turn: fail closed, no leak
    ├── hybrid_cms_test.c          ← CMS SignedData
    ├── hybrid_cms_kem_test.c      ← composite KEM (both tiers) as CMS KEMRI recipient (RFC 9629)
    ├── hybrid_capability_test.c   ← TLS code-point parity vs default/oqsprovider
    ├── hybrid_coverage_test.c     ← name coverage: every origin (oqs/default) hybrid is in our tables
    ├── hybrid_count_test.c        ← README "Algorithms served:" headline == table counts
    ├── hybrid_sizes_test.c        ← component-size tables vs live components (verify/generate)
    ├── hybrid_cede_test.c         ← cede-to-default: withdraw what the default provider serves
    ├── hybrid_log_test.c          ← HYBRID_LOG diagnostics for dropped (inoperable) groups
    ├── hybrid_adverse_test.c      ← load/coexistence/init-ordering robustness
    ├── hybrid_methodology_test.c  ← unpinned (store) resolution + explicit activation paths
    ├── hybrid_leakcheck_test.c    ← reach every path under LSan (leak detection with teeth)
    ├── hybrid_oqs_test.c          ← KEM interop vs oqsprovider for OQS-legacy ML-KEM hybrids
    ├── hybrid_extract_test.c      ← component extraction/composition as standalone EVP_PKEYs
    ├── hybrid_text_test.c         ← `pkey -text` encoder output for all families
    ├── hybrid_decode_neg_test.c   ← decoder robustness: multi-object PEM, malformed DER
    ├── hybrid_decode_fuzz.c       ← OSSL_DECODER fuzz harness (SPKI/PKCS8 import surface)
    ├── corpus/                    ← decoder fuzz seed corpus (gen_decode_corpus.sh)
    ├── xwing_kat_test.c           ← X-Wing KEM KAT vs draft-connolly-cfrg-xwing-kem
    ├── hybrid_config_test.c       ← cnf-driven component selection
    ├── hybrid_compctx_test.c      ← private component context (Frodo/BIKE/HQC)
    ├── hybrid_coexist_test.c      ← provider coexistence
    ├── hybrid_threads_test.c      ← concurrency/fork/teardown stress (ASan/TSan)
    ├── hybrid_matrix_test.c       ← full cross-version matrix vs oqsprovider
    ├── hybrid_replace_test.c      ← drop-in replacement over PQ-only oqsprovider (OQS_CEDE_HYBRIDS)
    ├── patches/                   ← in-repo oqsprovider patches (cede-hybrids lever)
    ├── composite_test.c           ← composite sig provider via EVP: keygen/sign/verify/tamper
    ├── composite_sig_test.c       ← composite sig combiner self-consistency (no provider)
    ├── composite_kat_test.c       ← composite sig KAT vs draft-ietf-lamps-pq-composite-sigs
    ├── composite_kem_test.c       ← composite KEM combiner KAT + encaps/decaps self-consistency
    ├── composite_kem_kat_test.c   ← composite KEM KAT vs draft-ietf-lamps-pq-composite-kem
    ├── composite_cms_test.c       ← composite signatures as CMS SignedData (attr + -noattr)
    ├── composite_sig_bench.c      ← composite cert size + cert-gen/verify benchmark
│   ├── composite_kem_bench.c      ← composite KEM keygen/encaps/decaps + pk/ct/sk sizes
    ├── hybrid_bench.c             ← keygen/encaps/decaps benchmark vs default provider
    ├── bench_util.c               ← shared benchmark/perf-guard helpers (min single-op latency)
    ├── provider_matrix.c          ← cross-provider interop + perf matrix (wolf/mldsa-native/oqs)
    ├── probe_oqs_hybrid.c         ← probe oqsprovider hybrid KEM raw/wire layout
    ├── pqc_corpus_interop.py      ← one capability-driven tool vs the IETF Hackathon pqc-certificates corpus: sig certs + composite KEM decaps + composite KEM CMS/KEMRI, verify/generate (see docs/pqc-corpus-interop.md)
    ├── pqc_corpus_common.py       ← shared OID/helper funcs for the corpus tool + check-pqc-certs-drift.sh
    ├── pqc_kem_cms_interop.sh     ← both-way composite KEM CMS interop vs kemri_toy
    ├── setup_oqs_interop.sh       ← (re)build the from-source liboqs + oqsprovider interop peer
    └── hybrid_scenarios.sh        ← CLI (s_server/s_client) TLS interop harness
└── integrations/          ← downstream integration demos (Docker; not built by CMake)
    └── curl-nginx-3alg/   ← curl↔nginx TLS 1.3: interop vs oqsprovider's own hybrids
                             (interop.sh) + a 3-provider hybrid KEM (X25519+ML-KEM-768+
                             HQC-192); see its README.md, USAGE.md, THREE-PROVIDERS.md
```

## Code Conventions

- C11, targeting Linux
- OpenSSL coding style (4-space indent, K&R braces)
- All public symbols prefixed with `hybrid_`
- Error handling via `ERR_raise` / `ERR_raise_data`
- Secure-coding principles: follow the OpenSSF [Security-Focused Guide for AI
  Code Assistant Instructions](https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions).
  See CONTRIBUTING.md "Security conventions" for the concrete rules (validate
  untrusted wire lengths, wipe secret buffers on every path, no secrets in error
  strings, constant-time secret compares, negative/fuzz tests).
