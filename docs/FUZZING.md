# Fuzzing the hybrid provider

The decode path — turning attacker-supplied DER into a key — is the highest-value
fuzz target in this provider. Any application that imports an untrusted public
key or PKCS#8 private key (PKI enrollment, key upload, CMS key import, a CLI run
over an untrusted file) reaches `hybrid_decode()` (SubjectPublicKeyInfo) and
`hybrid_decode_p8()` (PKCS#8 `PrivateKeyInfo`) in `hybrid_decoder.c`, and the
component sub-key loading they drive. This is a classic memory-safety surface:
a length or size taken from attacker-controlled DER, or a serialization call
that writes into a fixed-size key buffer, must be bounded *before* the write —
not checked afterwards.

The harness is `test/hybrid_decode_fuzz.c`. It loads the `default` and `hybrid`
providers, then hands raw bytes to `OSSL_DECODER` as DER with no keytype or
structure constraint, so every registered decoder — including both hybrid
decoders — is offered the input. It is always built with AddressSanitizer, and
so is the provider module it loads (an OOB access inside uninstrumented provider
code would otherwise go unreported).

## Build

Enable with `-DHYBRID_FUZZ=ON`. The shape depends on the compiler:

- **clang** (has `-fsanitize=fuzzer`) → a coverage-guided libFuzzer binary.
- **gcc** (no libFuzzer) → a standalone corpus runner, wired into `ctest` so the
  committed seed corpus is replayed under ASAN on every `ctest` run.

```sh
mkdir build && cd build
CC=clang cmake .. -DOPENSSL_ROOT_DIR=/path/to/openssl-3.5+ -DHYBRID_FUZZ=ON
make hybrid-provider hybrid_decode_fuzz
```

OpenSSL 3.5+ lets the PQ components come from the default provider, so no
oqsprovider is needed; on 3.0–3.4 also load oqsprovider (the harness loads it if
present). `OPENSSL_MODULES` must point at the directory holding `hybrid.so`.

## Run

Coverage-guided (clang build), seeded from the corpus:

```sh
export OPENSSL_MODULES=$PWD HYBRID_CEDE_TO_DEFAULT=0
./hybrid_decode_fuzz -max_len=65536 ../test/corpus/decode
```

Standalone (gcc build) — replay a corpus or individual files once each; a
non-zero exit / ASAN abort is the failure signal:

```sh
export OPENSSL_MODULES=$PWD HYBRID_CEDE_TO_DEFAULT=0
./hybrid_decode_fuzz ../test/corpus/decode        # or: ctest -R hybrid_decode_fuzz
```

## Seed corpus

`test/corpus/decode/` holds valid hybrid keys (PKCS#8 + SPKI DER for a few
signature algorithms, exercising the success path) plus malformed/truncated
inputs. Regenerate the valid seeds with `test/corpus/gen_decode_corpus.sh`
against a built provider.

## OSS-Fuzz

The libFuzzer entry point (`LLVMFuzzerTestOneInput`) is OSS-Fuzz-ready: a project
`build.sh` need only compile `test/hybrid_decode_fuzz.c` with
`-DHYBRID_FUZZ_LIBFUZZER` and `$LIB_FUZZING_ENGINE`, link the provider, and ship
`test/corpus/decode` as the seed corpus.
