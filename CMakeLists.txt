cmake_minimum_required(VERSION 3.16)
project(hybrid-provider C)

set(CMAKE_C_STANDARD 11)

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
# Composite requires OpenSSL 3.5+ — because of the SEED, not ML-DSA availability as
# such. ML-DSA the algorithm exists on 3.4 too (via oqsprovider), but draft-19
# mandates the composite private key BE the ML-DSA 32-byte seed, and retaining /
# serializing that seed uses OpenSSL's ML-DSA seed API (OSSL_PKEY_PARAM_ML_DSA_SEED),
# added in 3.5. On 3.4 that symbol is not even declared (composite would not
# compile) and there is no standard seed plumbing to form a conformant composite
# private key regardless of which provider supplies ML-DSA. So force off below 3.5.
if(HYBRID_COMPOSITE AND OPENSSL_VERSION VERSION_LESS 3.5)
    message(STATUS "HYBRID_COMPOSITE needs OpenSSL 3.5+ (ML-DSA seed API); disabling on ${OPENSSL_VERSION}")
    set(HYBRID_COMPOSITE OFF)
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
