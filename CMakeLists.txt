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
set_target_properties(hybrid-provider PROPERTIES
    PREFIX ""
    OUTPUT_NAME "hybrid"
    SUFFIX ".so"
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
