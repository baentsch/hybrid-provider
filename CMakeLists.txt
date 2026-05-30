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

# Benchmark executable: hybrid provider vs default provider
add_executable(hybrid_bench test/hybrid_bench.c)
target_include_directories(hybrid_bench PRIVATE ${OPENSSL_INCLUDE_DIR} ${CMAKE_SOURCE_DIR})
target_link_libraries(hybrid_bench PRIVATE OpenSSL::Crypto)
