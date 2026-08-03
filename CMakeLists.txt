cmake_minimum_required(VERSION 3.16)
project(hybrid-provider C)

set(CMAKE_C_STANDARD 11)

# Allow pointing to a local OpenSSL build:
#   cmake .. -DOPENSSL_ROOT_DIR=../.local
if(DEFINED OPENSSL_ROOT_DIR)
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    list(INSERT CMAKE_PREFIX_PATH 0 "${OPENSSL_ROOT_DIR}")
endif()

find_package(OpenSSL 3.4 REQUIRED)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION} from ${OPENSSL_INCLUDE_DIR}")

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

# Composite (LAMPS) signature family — issue #6. Per the packaging decision
# (redesign.md Phase 2) composite is a build-flag-gated capability in this
# provider, default OFF. First slice: the generic combiner (composite_sig.c) and
# its self-consistency test; the provider module (keymgmt/registration) follows.
option(HYBRID_COMPOSITE "Build the composite (LAMPS) signature family" OFF)
if(HYBRID_COMPOSITE)
    # Combiner self-consistency test (no provider registration).
    add_executable(composite_sig_test test/composite_sig_test.c composite_sig.c)
    target_include_directories(composite_sig_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_sig_test PRIVATE OpenSSL::Crypto)
    add_test(NAME composite_sig_test COMMAND composite_sig_test)
    set_tests_properties(composite_sig_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # Composite provider module — keygen + sign/verify. Like hybrid above, no
    # SUFFIX override: the MODULE default suffix is already correct per platform.
    add_library(composite-provider MODULE
        composite_prov.c
        composite_keymgmt.c
        composite_sig.c
        composite_encoder.c
        composite_decoder.c
    )
    target_include_directories(composite-provider PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(composite-provider PRIVATE OpenSSL::Crypto)
    set_target_properties(composite-provider PROPERTIES
        PREFIX ""
        OUTPUT_NAME "composite"
    )

    # Provider-level test: drive composite through EVP by name.
    add_executable(composite_test test/composite_test.c)
    target_include_directories(composite_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_test PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_test composite-provider)
    add_test(NAME composite_test COMMAND composite_test)
    set_tests_properties(composite_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )

    # KAT interop: verify the draft-19 reference test vectors (real cross-impl
    # check against lamps-wg/draft-composite-sigs, distilled into composite_kat.txt).
    add_executable(composite_kat_test test/composite_kat_test.c)
    target_include_directories(composite_kat_test PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
    target_link_libraries(composite_kat_test PRIVATE OpenSSL::Crypto)
    add_dependencies(composite_kat_test composite-provider)
    add_test(NAME composite_kat_test
        COMMAND composite_kat_test ${CMAKE_SOURCE_DIR}/test/composite_kat.txt)
    set_tests_properties(composite_kat_test PROPERTIES
        ENVIRONMENT "OPENSSL_MODULES=${CMAKE_BINARY_DIR}"
    )
endif()

# Separate-process CLI TLS interop for Frodo/BIKE/HQC hybrids: the hybrid
# provider (configured via cnf with component-providers/component-path) drives
# real openssl s_server/s_client handshakes against a pure-oqsprovider peer,
# both directions. This is the multi-process complement to the in-process
# hybrid_compctx_test. The script self-skips (exit 0) when oqsprovider.so is not
# on the module path. Only registered when an openssl CLI was found.
if(OPENSSL_CLI)
    add_test(NAME hybrid_scenarios_tls_compctx
        COMMAND ${CMAKE_SOURCE_DIR}/test/hybrid_scenarios.sh
                --openssl ${OPENSSL_CLI}
                --libpath ${_ossl_libdir}
                --module-dir ${CMAKE_BINARY_DIR}
                tls-compctx)
endif()

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
