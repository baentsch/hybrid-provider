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
