cmake_minimum_required(VERSION 3.16)
project(hybrid-provider C)

set(CMAKE_C_STANDARD 11)

# Treat use of deprecated OpenSSL APIs as a hard error, for the provider and
# every test target in this directory. Rationale: OpenSSL 4.1 deprecates the
# int-typed ASN.1 string accessors (ASN1_STRING_set/_length) in favour of the
# size_t _ex variants; we want that (and any future deprecation) to fail the
# build here rather than slip by as a warning the way it does upstream. GCC/Clang
# only — MSVC spells this differently and Linux is the target platform.
if(NOT MSVC)
    add_compile_options(-Werror=deprecated-declarations)
endif()

# Memory-safety audit automation (issue #42). When ON, instrument the provider
# module AND every test target with AddressSanitizer + UndefinedBehaviorSanitizer
# (LeakSanitizer rides along with ASan on Linux), so a plain `ctest` run exercises
# the whole in-process suite under the sanitizers. Set before any target is
# defined so the flags apply globally. OpenSSL/liboqs/oqsprovider are NOT
# instrumented; their library-init leaks are filtered in CI via test/lsan.supp.
# Note test/lsan.supp's leak:libcrypto rule is a broad catch-all (all provider
# heap routes through CRYPTO_malloc), so the general leg proves absence of UB /
# use-after-free / overflow but does NOT by itself catch a provider LEAK — that is
# the job of hybrid_leakcheck_test (below), which runs without leak:libcrypto. See
# the header of test/lsan.supp for the full rationale. The CLI scenario tests
# shell out to the (uninstrumented) openssl binary, which cannot dlopen an
# instrumented provider, so CI excludes them from this leg.
option(HYBRID_SANITIZE "Build provider + tests with ASan/UBSan/LSan (issue #42)" OFF)
if(HYBRID_SANITIZE)
    if(MSVC)
        message(FATAL_ERROR "HYBRID_SANITIZE is GCC/Clang only")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all
                        -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# Thread-safety audit automation (issue #43): build the provider + tests with
# ThreadSanitizer to catch data races on the provider's shared/cached state.
# Mutually exclusive with HYBRID_SANITIZE (ASan and TSan cannot be combined).
# The tsan CI leg runs only hybrid_threads_test under this build, since races
# internal to (uninstrumented) libcrypto/liboqs would otherwise dominate the
# report; test/tsan.supp suppresses any that still surface from library frames.
option(HYBRID_TSAN "Build provider + tests with ThreadSanitizer (issue #43)" OFF)
if(HYBRID_TSAN)
    if(MSVC)
        message(FATAL_ERROR "HYBRID_TSAN is GCC/Clang only")
    endif()
    if(HYBRID_SANITIZE)
        message(FATAL_ERROR "HYBRID_TSAN and HYBRID_SANITIZE are mutually exclusive")
    endif()
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=thread)
endif()

# Allow pointing to a local OpenSSL build:
#   cmake .. -DOPENSSL_ROOT_DIR=../.local
if(DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    list(INSERT CMAKE_PREFIX_PATH 0 "${OPENSSL_ROOT_DIR}")
endif()

# 3.0 is the real floor: the provider uses only 3.0-era EVP (EVP_PKEY_encapsulate,
# EVP_PKEY_Q_keygen, fromdata, OSSL_PARAM_BLD). Hybrid sigs need a 3.2+ oqsprovider
# and composite needs 3.5+ (gated below), but neither raises the compile floor.
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION} from ${OPENSSL_INCLUDE_DIR}")

# OpenSSL 4.1 deprecated the int-typed ASN1_STRING_set()/ASN1_STRING_length() in
# favour of the size_t ASN1_STRING_set_data()/ASN1_STRING_length_ex(). Detect the
# new API by feature test, NOT by version: 4.1.0-dev reports the same version both
# before and after the symbols landed, so OPENSSL_VERSION_NUMBER cannot tell them
# apart. hybrid_asn1_compat.h selects on the resulting define.
#
# The probe is compile-only (STATIC_LIBRARY try-compile, so no link step) and
# treats an implicit declaration as an error: that way it keys purely off whether
# the OpenSSL *headers* declare the new symbol, independent of which libcrypto the
# link resolves to (find_package can pick a mismatched system library).
include(CheckCSourceCompiles)
set(_hp_saved_ttype "${CMAKE_TRY_COMPILE_TARGET_TYPE}")
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
set(CMAKE_REQUIRED_INCLUDES "${OPENSSL_INCLUDE_DIR}")
if(NOT MSVC)
    set(CMAKE_REQUIRED_FLAGS "-Werror=implicit-function-declaration")
endif()
check_c_source_compiles("
#include <openssl/asn1.h>
size_t hp_probe(const ASN1_STRING *s) { return ASN1_STRING_length_ex(s); }
" HAVE_ASN1_STRING_LENGTH_EX)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_FLAGS)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "${_hp_saved_ttype}")
if(HAVE_ASN1_STRING_LENGTH_EX)
    add_compile_definitions(HAVE_ASN1_STRING_LENGTH_EX)
endif()

# Locate the matching `openssl` CLI (next to the OpenSSL we build against), used
# by the separate-process shell scenario tests. Derived from the crypto lib's
# location so it tracks OPENSSL_ROOT_DIR rather than any system install.
get_filename_component(_ossl_libdir "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
get_filename_component(_ossl_prefix "${_ossl_libdir}" DIRECTORY)
find_program(OPENSSL_CLI openssl
    HINTS "${_ossl_prefix}/bin" "${_ossl_prefix}/apps"
    NO_DEFAULT_PATH)
if(NOT OPENSSL_CLI)
    find_program(OPENSSL_CLI openssl)   # fall back to PATH
endif()

# KEM key-file encoders/decoders. Off by default, mirroring oqsprovider's
# OQS_KEM_ENCODERS option: KEM keys are usually ephemeral, only a few hybrid
# KEMs have an assigned OID, and the format uses OQS's private OID arc.
option(HYBRID_KEM_ENCODERS "Build encoders/decoders for hybrid KEM key files" OFF)

# Composite (LAMPS) signature family. A build-flag-gated *capability of the hybrid
# provider* (not a separate module). Default ON: this provider exists to carry
# pre-standardization algorithms, so the composite family ships by default and is
# expected to be turned off (or removed) once OpenSSL's default provider offers
# native composite signatures.
option(HYBRID_COMPOSITE "Build the composite (LAMPS) signature family" ON)
# Composite tiers have different OpenSSL floors:
#   - standardized (ML-DSA / ML-KEM): 3.5+. draft-19 mandates the composite private
#     key BE the ML-DSA/ML-KEM seed, and serializing that seed uses OpenSSL's seed
#     API (OSSL_PKEY_PARAM_ML_DSA_SEED / _ML_KEM_SEED), added in 3.5. The header
#     names those macros, but composite_prov.h provides a compile fallback and the
#     provider does not *register* the standardized tiers below 3.5 (see
#     hybrid_prov.c / COMPOSITE_SEED_AVAILABLE).
#   - experimental (Falcon/MAYO/CROSS/UOV/SNOVA/MQOM2): serialize the RAW private
#     key (OSSL_PKEY_PARAM_PRIV_KEY, present since 3.0) and take their PQ half from
#     oqsprovider, so they run on the oqsprovider floor (3.2+) — no seed API needed.
# So the composite family builds on 3.2+; the standardized tiers self-activate at
# runtime on 3.5+. Below 3.2 (no TLS-SIGALG advertising) force off.
if(HYBRID_COMPOSITE AND OPENSSL_VERSION VERSION_LESS 3.2)
    message(STATUS "HYBRID_COMPOSITE needs OpenSSL 3.2+ (oqsprovider floor); disabling on ${OPENSSL_VERSION}")
    set(HYBRID_COMPOSITE OFF)
endif()
# Whether the standardized (seed-based) composite tiers are usable here (3.5+).
# Gates the standardized-only tests below; the experimental tier runs regardless.
if(OPENSSL_VERSION VERSION_GREATER_EQUAL 3.5)
    set(COMPOSITE_SEED ON)
else()
    set(COMPOSITE_SEED OFF)
endif()

# Provider shared library
add_library(hybrid-provider MODULE
    hybrid_prov.c
    hybrid_keymgmt.c
    hybrid_kem.c
    hybrid_sig.c
    hybrid_caps.c
    hybrid_encoder.c
    hybrid_decoder.c
)
target_include_directories(hybrid-provider PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(hybrid-provider PRIVATE OpenSSL::Crypto)
if(HYBRID_KEM_ENCODERS)
    target_compile_definitions(hybrid-provider PRIVATE HYBRID_KEM_ENCODERS)
endif()
if(HYBRID_COMPOSITE)
    target_sources(hybrid-provider PRIVATE
        composite_keymgmt.c
        composite_sig.c
        composite_encoder.c
        composite_decoder.c
        composite_caps.c
        composite_kem.c
        composite_kem_keymgmt.c
        composite_kem_encoder.c
        composite_kem_decoder.c
    )
    target_compile_definitions(hybrid-provider PRIVATE HYBRID_COMPOSITE)
endif()
# No SUFFIX override: an OpenSSL provider is a CMake MODULE library, whose
# default suffix is already the right one per platform (.so on Linux/macOS,
# .dll on Windows) — matching what OpenSSL's loader looks for. PREFIX "" just
# drops the "lib" so the module is hybrid.so, not libhybrid.so.
set_target_properties(hybrid-provider PROPERTIES
    PREFIX ""
    OUTPUT_NAME "hybrid"
)

# Test executable
enable_testing()
add_executable(hybrid_test test/hybrid_test.c)
target_include_directories(hybrid_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_interop_test COMMAND hybrid_test)

# Ensure test can find the provider and the right libcrypto
set_tests_properties(hybrid_interop_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# TLS handshake interop test (in-process, dual libctx via memory BIOs)
add_executable(hybrid_tls_test test/hybrid_tls_test.c)
target_include_directories(hybrid_tls_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_tls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME hybrid_tls_test COMMAND hybrid_tls_test)
set_tests_properties(hybrid_tls_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Config-driven component selection test (pq-propquery / classic-propquery)
add_executable(hybrid_config_test test/hybrid_config_test.c)
target_include_directories(hybrid_config_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_config_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_config_test COMMAND hybrid_config_test)
set_tests_properties(hybrid_config_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Cross-provider interop test against oqsprovider (built from GitHub main via
# test/setup_oqs_interop.sh, which symlinks oqsprovider.so into the build dir).
# Self-skips when oqsprovider is not on the module path.
add_executable(hybrid_oqs_test test/hybrid_oqs_test.c)
target_include_directories(hybrid_oqs_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_oqs_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_oqs_test COMMAND hybrid_oqs_test)
set_tests_properties(hybrid_oqs_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Drop-in replacement test: with oqsprovider in PQ-only mode (OQS_CEDE_HYBRIDS,
# applied via test/patches/oqsprovider-cede-hybrids.patch until it lands
# upstream), hybrid-provider must serve every hybrid — KEMs on OpenSSL 3.0+,
# sigs on 3.2+, composite on 3.5+. Self-skips only when oqsprovider is absent;
# FAILS if oqsprovider is present but not honoring the cede lever, so patch drift
# turns the (weekly) run red instead of silently passing. The test also setenv()s
# OQS_CEDE_HYBRIDS itself before loading providers; it is set here too for visibility.
add_executable(hybrid_replace_test test/hybrid_replace_test.c)
target_include_directories(hybrid_replace_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_replace_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_replace_test COMMAND hybrid_replace_test)
set_tests_properties(hybrid_replace_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR};OQS_CEDE_HYBRIDS=1"
)

# Private component-context test: hybrid sources Frodo/BIKE/HQC base from its
# own libctx (default + oqsprovider), so the app context has no group collision
# and these hybrids work over TLS. Self-skips when oqsprovider is unavailable.
add_executable(hybrid_compctx_test test/hybrid_compctx_test.c)
target_include_directories(hybrid_compctx_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_compctx_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME hybrid_compctx_test COMMAND hybrid_compctx_test)
set_tests_properties(hybrid_compctx_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Encoder interop test: hybrid-written SPKI decoded + verified by oqsprovider.
add_executable(hybrid_encode_test test/hybrid_encode_test.c)
target_include_directories(hybrid_encode_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_encode_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_encode_test COMMAND hybrid_encode_test)
set_tests_properties(hybrid_encode_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# TLS-GROUP code-point parity: our tls_codepoint values vs the live capabilities
# advertised by the default provider / oqsprovider (guards against drift).
add_executable(hybrid_capability_test test/hybrid_capability_test.c)
target_include_directories(hybrid_capability_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_capability_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_capability_test COMMAND hybrid_capability_test)
set_tests_properties(hybrid_capability_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# hybrid_log() diagnostics: HYBRID_LOG=1 reports the drop of an inoperable
# hybrid (a group/sigalg whose components are not both fetchable); silent when
# unset. Runs in a default-only context so the Frodo groups are dropped.
add_executable(hybrid_log_test test/hybrid_log_test.c)
target_include_directories(hybrid_log_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_log_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_log_test COMMAND hybrid_log_test)
set_tests_properties(hybrid_log_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# End-to-end hybrid-signature certificate over TLS 1.3 (in-process). Self-skips
# per-algorithm when the components are unavailable (e.g. no ML-DSA on 3.4).
add_executable(hybrid_cert_tls_test test/hybrid_cert_tls_test.c)
target_include_directories(hybrid_cert_tls_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_cert_tls_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME hybrid_cert_tls_test COMMAND hybrid_cert_tls_test)
set_tests_properties(hybrid_cert_tls_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# KEM key-file interop test (SPKI + PKCS8 round-trip vs oqsprovider). Self-skips
# unless both providers were built with KEM encoders on (HYBRID_KEM_ENCODERS /
# OQS_KEM_ENCODERS).
add_executable(hybrid_kem_encode_test test/hybrid_kem_encode_test.c)
target_include_directories(hybrid_kem_encode_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_kem_encode_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_kem_encode_test COMMAND hybrid_kem_encode_test)
set_tests_properties(hybrid_kem_encode_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Provider-coexistence test (M8 drop-in contract; inverse of oqsprovider's
# alg-overlap test). Fetch-only, so it covers the whole inventory without a PQ
# base; loads oqsprovider when present to also prove hybrid<->oqs coexistence.
add_executable(hybrid_coexist_test test/hybrid_coexist_test.c)
target_include_directories(hybrid_coexist_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_coexist_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_coexist_test COMMAND hybrid_coexist_test)
set_tests_properties(hybrid_coexist_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# EVP_PKEY parameter round-trip / gettable-param parity (raw OSSL_PARAM export +
# import, distinct from the DER encoder tests). Drives the full tables; each
# algorithm self-skips when its components are unavailable.
add_executable(hybrid_param_test test/hybrid_param_test.c)
target_include_directories(hybrid_param_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_param_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_param_test COMMAND hybrid_param_test)
set_tests_properties(hybrid_param_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# CMS SignedData with hybrid signatures (in-process analog of oqsprovider's CMS
# scripts). ML-DSA hybrids need only the default provider; Falcon/MAYO/… self-
# skip without oqsprovider, and each algorithm self-skips if unavailable.
add_executable(hybrid_cms_test test/hybrid_cms_test.c)
target_include_directories(hybrid_cms_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_cms_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_cms_test COMMAND hybrid_cms_test)
set_tests_properties(hybrid_cms_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Concurrency / fork / teardown stress test (issue #43): many threads doing
# keygen/encaps/decaps/sign/verify on shared algorithms and a shared key,
# concurrent provider load/unload, and a fork-then-operate leg — the regression
# guard that the provider keeps no shared mutable runtime state (per-instance
# immutable cede tables + constant sizes). Runs under ASan on the sanitize leg
# and under TSan on the tsan leg. Uses X25519MLKEM768 + p256_mldsa44; each libctx
# loads oqsprovider best-effort, so the PQ halves resolve on OpenSSL < 3.5 too
# (native default provider on >= 3.5), letting it run on the whole version matrix.
#
# POSIX-only: it uses pthreads and fork(). The provider targets Linux (see
# CLAUDE.md), and a portable-threads rewrite would add noise for no coverage
# gain, so the test is simply gated to UNIX rather than ported to Windows.
if(UNIX)
find_package(Threads REQUIRED)
add_executable(hybrid_threads_test test/hybrid_threads_test.c)
target_include_directories(hybrid_threads_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_threads_test PRIVATE OpenSSL::Crypto Threads::Threads)
# Under ThreadSanitizer, disable ASLR (setarch -R) and point TSan at the
# library-frame suppressions: modern kernels randomize mmap enough that TSan's
# fixed shadow mapping aborts with "unexpected memory mapping" otherwise. The
# wrapper is a no-op for non-TSan builds.
if(HYBRID_TSAN)
    find_program(SETARCH_EXE setarch)
    if(SETARCH_EXE)
        add_test(NAME hybrid_threads_test
                 COMMAND ${SETARCH_EXE} -R $<TARGET_FILE:hybrid_threads_test>)
    else()
        add_test(NAME hybrid_threads_test COMMAND hybrid_threads_test)
    endif()
    set_tests_properties(hybrid_threads_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR};TSAN_OPTIONS=suppressions=${CMAKE_SOURCE_DIR}/test/tsan.supp:halt_on_error=1"
    )
else()
    add_test(NAME hybrid_threads_test COMMAND hybrid_threads_test)
    set_tests_properties(hybrid_threads_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )
endif()
endif()

# Component-size constant-table verifier (issue #43 follow-up): the provider
# carries per-component sizes as compile-time constants (no runtime discovery,
# no cache, no lock); this re-derives them from live component keygens and fails
# on drift. Skips rows whose components are unavailable, so it runs on every
# OpenSSL version (oqsprovider supplies the non-native families when loaded).
add_executable(hybrid_sizes_test test/hybrid_sizes_test.c)
target_include_directories(hybrid_sizes_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_sizes_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_sizes_test COMMAND hybrid_sizes_test)
set_tests_properties(hybrid_sizes_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Full-matrix cross-version interop sweep vs oqsprovider, driven by the master
# tables so every hybrid KEM + SIG is checked (nothing silently omitted).
# Skipped wholesale when oqsprovider is unavailable.
add_executable(hybrid_matrix_test test/hybrid_matrix_test.c)
target_include_directories(hybrid_matrix_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_matrix_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_matrix_test COMMAND hybrid_matrix_test)
set_tests_properties(hybrid_matrix_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Coverage guard: every hybrid oqsprovider advertises must be in our tables
# (inverse of the matrix test; catches whole families omitted from the list).
add_executable(hybrid_coverage_test test/hybrid_coverage_test.c)
target_include_directories(hybrid_coverage_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_coverage_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_coverage_test COMMAND hybrid_coverage_test)
set_tests_properties(hybrid_coverage_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Composite (LAMPS) tests — the composite family itself is compiled into the
# hybrid provider above (HYBRID_COMPOSITE). These just exercise it; they load
# "provider=hybrid" and need the hybrid module built with -DHYBRID_COMPOSITE.
if(HYBRID_COMPOSITE)
    # Combiner self-consistency test (drives composite_sig.c directly).
    add_executable(composite_sig_test test/composite_sig_test.c composite_sig.c)
    target_include_directories(composite_sig_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_sig_test PRIVATE OpenSSL::Crypto)
    add_test(NAME composite_sig_test COMMAND composite_sig_test)
    set_tests_properties(composite_sig_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Provider-level test: drive composite through EVP by name (provider=hybrid).
    add_executable(composite_test test/composite_test.c)
    target_include_directories(composite_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_test PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_test hybrid-provider)
    add_test(NAME composite_test COMMAND composite_test)
    set_tests_properties(composite_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Composite ML-KEM provider round-trip: keygen/encaps/decaps + SPKI + PKCS8
    # for every combo, driven through EVP by name (provider=hybrid). Runs on all
    # versions: the standardized rows self-skip below 3.5 (not registered), the
    # experimental Frodo/BIKE/HQC rows run from the oqsprovider floor (3.2+).
    add_executable(composite_kem_prov_test test/composite_kem_prov_test.c)
    target_include_directories(composite_kem_prov_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_kem_prov_test PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_kem_prov_test hybrid-provider)
    add_test(NAME composite_kem_prov_test COMMAND composite_kem_prov_test)
    set_tests_properties(composite_kem_prov_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Standardized-tier tests: the composite draft KATs and the ML-KEM combiner /
    # KAT tests are seed-based, so they only apply on OpenSSL 3.5+. On <3.5 the
    # standardized tiers are not registered; the experimental composite signatures
    # are covered by composite_sig_test / composite_test and the experimental
    # composite KEMs by composite_kem_prov_test, which self-skip the standardized
    # rows.
    if(COMPOSITE_SEED)
    # KAT interop: verify the draft-19 reference test vectors (real cross-impl
    # check against lamps-wg/draft-composite-sigs, distilled into composite_kat.txt).
    add_executable(composite_kat_test test/composite_kat_test.c)
    target_include_directories(composite_kat_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_kat_test PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_kat_test hybrid-provider)
    add_test(NAME composite_kat_test
        COMMAND composite_kat_test ${CMAKE_SOURCE_DIR}/test/composite_kat.txt)
    set_tests_properties(composite_kat_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Composite ML-KEM combiner test (drives composite_kem.c directly): draft
    # X25519 combiner KAT + encaps/decaps self-consistency across the combos.
    add_executable(composite_kem_test test/composite_kem_test.c composite_kem.c)
    target_include_directories(composite_kem_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_kem_test PRIVATE OpenSSL::Crypto)
    add_test(NAME composite_kem_test COMMAND composite_kem_test)
    set_tests_properties(composite_kem_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Composite ML-KEM KAT interop: decapsulate the draft-18 reference ciphertexts
    # (lamps-wg/draft-composite-kem, distilled into composite_kem_kat.txt) and check
    # each recovers the reference shared secret.
    add_executable(composite_kem_kat_test test/composite_kem_kat_test.c)
    target_include_directories(composite_kem_kat_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_kem_kat_test PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_kem_kat_test hybrid-provider)
    add_test(NAME composite_kem_kat_test
        COMMAND composite_kem_kat_test ${CMAKE_SOURCE_DIR}/test/composite_kem_kat.txt)
    set_tests_properties(composite_kem_kat_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )
    endif()   # COMPOSITE_SEED (standardized-tier tests, 3.5+)

    # Certificate benchmark: self-signed X.509 cert size + cert-gen/verify time
    # for every composite (standardized ML-DSA + experimental OQS families). Runs
    # a short per-op budget under ctest (smoke); pass a larger budget in ms for
    # real numbers, e.g. `composite_sig_bench 2000`.
    add_executable(composite_sig_bench test/composite_sig_bench.c)
    target_include_directories(composite_sig_bench PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_sig_bench PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_sig_bench hybrid-provider)
    add_test(NAME composite_sig_bench COMMAND composite_sig_bench 20)
    set_tests_properties(composite_sig_bench PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # KEM benchmark: keygen/encaps/decaps time + pk/ct/sk sizes for every composite
    # ML-KEM (standardized + experimental Frodo/BIKE/HQC). The KEM analogue of
    # composite_sig_bench; same short smoke budget under ctest, larger via argv[1].
    add_executable(composite_kem_bench test/composite_kem_bench.c)
    target_include_directories(composite_kem_bench PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_kem_bench PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_kem_bench hybrid-provider)
    add_test(NAME composite_kem_bench COMMAND composite_kem_bench 20)
    set_tests_properties(composite_kem_bench PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Guard the README "Algorithms served:" headline against silent drift:
    # recomputes the KEM/SIG/composite counts from the source-of-truth tables
    # and asserts the README number still matches. Built here (HYBRID_COMPOSITE)
    # so all four tables — incl. composite sig/KEM — are in scope. Loads no
    # provider; just includes the headers and reads ${CMAKE_SOURCE_DIR}/README.md.
    add_executable(hybrid_count_test test/hybrid_count_test.c)
    target_include_directories(hybrid_count_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_compile_definitions(hybrid_count_test PRIVATE HYBRID_COMPOSITE)
    target_link_libraries(hybrid_count_test PRIVATE OpenSSL::Crypto)
    add_test(NAME hybrid_count_test COMMAND hybrid_count_test ${CMAKE_SOURCE_DIR}/README.md)
endif()

# Separate-process CLI harnesses driven by test/hybrid_scenarios.sh. These are
# gated on NOT WIN32: the harness is a bash script (uses /dev/tcp, POSIX quoting,
# etc.), so it runs on Linux/macOS but not native Windows. Under MSYS2/Cygwin the
# script itself copes (SOEXT handling), but ctest would still need a POSIX shell,
# so we simply do not register these on Windows.
if(OPENSSL_CLI AND NOT WIN32)
    # TLS interop for Frodo/BIKE/HQC hybrids via the hybrid provider's private
    # component context, against a pure-oqsprovider peer (both directions). The
    # multi-process complement to in-process hybrid_compctx_test. Self-skips
    # (exit 0) when oqsprovider.so is not on the module path.
    add_test(NAME hybrid_scenarios_tls_compctx
        COMMAND ${CMAKE_SOURCE_DIR}/test/hybrid_scenarios.sh
                --openssl ${OPENSSL_CLI}
                --libpath ${_ossl_libdir}
                --module-dir ${CMAKE_BINARY_DIR}
                tls-compctx)

    # CLI end-to-end coverage for the hybrid + composite SIGNATURE algorithms:
    # genpkey -> self-signed cert -> verify -> x509 -text -> CMS sign/verify.
    # Complements the in-process hybrid_cert_tls_test (same signatures over TLS).
    # ML-DSA hybrids and the LAMPS composite combos run from the default provider;
    # the oqs-sourced research hybrids run when oqsprovider.so is present and
    # otherwise self-skip.
    add_test(NAME hybrid_scenarios_sig_certs
        COMMAND ${CMAKE_SOURCE_DIR}/test/hybrid_scenarios.sh
                --openssl ${OPENSSL_CLI}
                --libpath ${_ossl_libdir}
                --module-dir ${CMAKE_BINARY_DIR}
                sig-certs)

    # Cross-provider private-key file interop for the hybrid signatures: a key
    # written by the hybrid provider is read back by oqsprovider and vice versa
    # (shared names/OIDs/PKCS8 layout). Self-skips when oqsprovider.so is not on
    # the module path. Composite is excluded (oqsprovider has no LAMPS).
    add_test(NAME hybrid_scenarios_sig_interop
        COMMAND ${CMAKE_SOURCE_DIR}/test/hybrid_scenarios.sh
                --openssl ${OPENSSL_CLI}
                --libpath ${_ossl_libdir}
                --module-dir ${CMAKE_BINARY_DIR}
                sig-interop)
endif()

# Cede-to-default test: by default the provider withdraws whatever the default
# provider already serves. Table-driven over the whole inventory — for every
# hybrid KEM/signature it uses "does the default provider resolve this?" as the
# oracle and asserts, flipping the HYBRID_CEDE_TO_DEFAULT lever around each
# provider load, that provider=hybrid resolves it with ceding off (coexistence)
# and only when the default provider does NOT serve it with ceding on. Manages
# the lever itself via setenv().
add_executable(hybrid_cede_test test/hybrid_cede_test.c)
target_include_directories(hybrid_cede_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_cede_test PRIVATE OpenSSL::Crypto)
add_test(NAME hybrid_cede_test COMMAND hybrid_cede_test)
set_tests_properties(hybrid_cede_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)

# Provider robustness under adverse load, coexistence, and query/init ordering
# (issue #47): merely activating the provider must not break SSL_CTX_new; init
# tolerates being loaded before default, activated twice, and a pre-registered
# colliding OID; the first fetch after load resolves (query never cached-empty);
# retained algorithms never overlap the default provider (name/OID/code point)
# and ceding withdraws only what the default actually serves; foreign key I/O is
# not shadowed; and repeated load failure returns rather than hanging. Drives the
# HYBRID_CEDE_TO_DEFAULT lever itself per phase (like hybrid_cede_test), so it is
# excluded from the suite-wide "ceding off" override below. A TIMEOUT turns any
# hang (the load-loop / init-deadlock failure modes) into a test failure.
add_executable(hybrid_adverse_test test/hybrid_adverse_test.c)
target_include_directories(hybrid_adverse_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_adverse_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME hybrid_adverse_test COMMAND hybrid_adverse_test)
set_tests_properties(hybrid_adverse_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    TIMEOUT 120
)

# Leak-detection test with teeth (issue #47 follow-up to the #42 sanitizer leg).
# Exercises and frees every provider allocation path (keygen/free, import/export,
# match, sign/verify, encaps/decaps, encode/decode) across the whole inventory,
# then unloads every provider before freeing the libctx (unload-clean) so teardown
# runs before LSan's check. Because it is unload-clean it is run WITHOUT the broad
# leak:libcrypto catch-all: its LSAN_OPTIONS is pinned to lsan_leakcheck.supp,
# which suppresses only the un-instrumented PQ dependencies' one-time init state.
# This overrides the suite-wide LSAN_OPTIONS the CI sanitize leg exports, so a
# leak newly introduced in provider code surfaces here unmasked and fails.
add_executable(hybrid_leakcheck_test test/hybrid_leakcheck_test.c)
target_include_directories(hybrid_leakcheck_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_leakcheck_test PRIVATE OpenSSL::Crypto)
if(HYBRID_COMPOSITE)
    target_compile_definitions(hybrid_leakcheck_test PRIVATE HYBRID_COMPOSITE)
endif()
add_test(NAME hybrid_leakcheck_test COMMAND hybrid_leakcheck_test)
set_tests_properties(hybrid_leakcheck_test PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR};LSAN_OPTIONS=suppressions=${CMAKE_SOURCE_DIR}/test/lsan_leakcheck.supp"
    TIMEOUT 300
)

# Benchmark: hybrid provider vs native (default / oqsprovider). Run manually
# with an iteration count for real numbers (e.g. `hybrid_bench 1000`); wired
# into ctest as a low-iteration smoke test that it runs and completes.
add_executable(hybrid_bench test/hybrid_bench.c)
add_test(NAME hybrid_bench COMMAND hybrid_bench 10)
set_tests_properties(hybrid_bench PROPERTIES
    ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
)
target_include_directories(hybrid_bench PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_bench PRIVATE OpenSSL::Crypto)

# ---------------------------------------------------------------------------
# Decoder fuzz harness (test/hybrid_decode_fuzz.c)
#
# Fuzzes the untrusted-key-material decode surface — hybrid_decode() (SPKI) and
# hybrid_decode_p8() (PKCS#8) plus the component sub-key loading they drive —
# for out-of-bounds accesses in DER key parsing (e.g. a serialization write that
# precedes its size check, or an unbounded length taken from the input). Enable
# with -DHYBRID_FUZZ=ON. Two shapes depending on compiler support for
# -fsanitize=fuzzer:
#   - libFuzzer present -> coverage-guided binary (run manually / under OSS-Fuzz)
#   - otherwise         -> standalone corpus runner, wired into ctest so the
#                          seed corpus is replayed on every `ctest` run.
# ASAN is forced on for BOTH the harness and the provider module it loads —
# without instrumenting the provider itself, an out-of-bounds access inside the
# decode path would go unreported.
# ---------------------------------------------------------------------------
option(HYBRID_FUZZ "Build the decoder fuzz harness (ASAN)" OFF)
if(HYBRID_FUZZ)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=fuzzer")
    check_c_source_compiles(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { (void)d; (void)n; return 0; }"
        HYBRID_HAVE_LIBFUZZER)
    unset(CMAKE_REQUIRED_FLAGS)

    # Instrument the provider module too, so bugs in its decode code are caught.
    target_compile_options(hybrid-provider PRIVATE -fsanitize=address -g)
    target_link_options(hybrid-provider PRIVATE -fsanitize=address)

    add_executable(hybrid_decode_fuzz test/hybrid_decode_fuzz.c)
    target_include_directories(hybrid_decode_fuzz
        PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(hybrid_decode_fuzz PRIVATE OpenSSL::Crypto)
    target_compile_options(hybrid_decode_fuzz PRIVATE -fsanitize=address -g)
    target_link_options(hybrid_decode_fuzz PRIVATE -fsanitize=address)

    if(HYBRID_HAVE_LIBFUZZER)
        target_compile_definitions(hybrid_decode_fuzz PRIVATE HYBRID_FUZZ_LIBFUZZER)
        target_compile_options(hybrid_decode_fuzz PRIVATE -fsanitize=fuzzer)
        target_link_options(hybrid_decode_fuzz PRIVATE -fsanitize=fuzzer)
        message(STATUS "HYBRID_FUZZ: libFuzzer build (coverage-guided)")
    else()
        # No libFuzzer: replay the committed seed corpus under ASAN on each run.
        add_test(NAME hybrid_decode_fuzz
                 COMMAND hybrid_decode_fuzz ${CMAKE_SOURCE_DIR}/test/corpus/decode)
        set_tests_properties(hybrid_decode_fuzz PROPERTIES
            ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}")
        message(STATUS "HYBRID_FUZZ: no libFuzzer; standalone corpus runner wired into ctest")
    endif()
endif()

# The provider cedes whatever the default provider already serves by DEFAULT
# (see HYBRID_CONF_CEDE_TO_DEFAULT). The interop suite deliberately loads both
# providers and compares the two implementations of the same identifier, so it
# needs ceding OFF; switch it off for every test here. hybrid_cede_test is the
# one exception — it drives the lever itself via setenv() to exercise both states.
get_property(_hp_tests DIRECTORY PROPERTY TESTS)
foreach(_t ${_hp_tests})
    if(NOT _t STREQUAL "hybrid_cede_test" AND NOT _t STREQUAL "hybrid_adverse_test")
        set_property(TEST ${_t} APPEND PROPERTY ENVIRONMENT "HYBRID_CEDE_TO_DEFAULT=0")
    endif()
endforeach()
