/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thin ASN.1 string compatibility shim.
 *
 * OpenSSL 4.1 deprecated the int-typed ASN1_STRING_set() / ASN1_STRING_length()
 * in favour of the size_t-typed ASN1_STRING_set1_data() / ASN1_STRING_get_length():
 *
 *   4.1+ :  ASN1_STRING_set1_data() / ASN1_STRING_get_length()
 *   <=4.0:  ASN1_STRING_set()       / ASN1_STRING_length()
 *
 * We pick between them at compile time on HAVE_ASN1_STRING_GET_LENGTH, which CMake
 * defines via a feature test — deliberately a feature test, not a version test:
 * 4.1.0-dev reports the same OPENSSL_VERSION_NUMBER both before and after the new
 * symbols landed, so a version comparison (e.g. PREREQ(4,1)) cannot tell the two
 * apart. Because each branch calls only the API current for the build it targets,
 * neither path trips -Wdeprecated-declarations and no #pragma suppression is needed.
 *
 * (An earlier 4.1.0-dev spelled these ASN1_STRING_set_data()/_length_ex() before
 * upstream renamed them; that spelling never shipped in a release or in master, so
 * it is not carried here — a stale local dev checkout built against it simply needs
 * rebuilding to current master.)
 */
#ifndef HYBRID_ASN1_COMPAT_H
#define HYBRID_ASN1_COMPAT_H

#include <limits.h>
#include <openssl/asn1.h>
#include <openssl/opensslv.h>       /* OPENSSL_VERSION_NUMBER (build-system fallback) */

/*
 * HAVE_ASN1_STRING_GET_LENGTH is normally provided by the CMake feature test (see
 * CMakeLists.txt) — the reliable signal. If this header is compiled outside that
 * build system the macro is absent; rather than silently drop to the deprecated
 * int API on an OpenSSL that offers the size_t one, fall back to a version check
 * (best effort — 4.1.0-dev is ambiguous, hence the feature test) and warn loudly.
 */
#if !defined(HAVE_ASN1_STRING_GET_LENGTH) && OPENSSL_VERSION_NUMBER >= 0x40100000L
#  if defined(_MSC_VER)
#    pragma message("hybrid_asn1_compat.h: HAVE_ASN1_STRING_GET_LENGTH not set by the build system; assuming the OpenSSL 4.1 size_t ASN.1 API. Build via CMake for a reliable feature test.")
#  else
#    warning "hybrid_asn1_compat.h: HAVE_ASN1_STRING_GET_LENGTH not set by the build system; assuming the OpenSSL 4.1 size_t ASN.1 API. Build via CMake for a reliable feature test."
#  endif
#  define HAVE_ASN1_STRING_GET_LENGTH 1
#endif

/* Set an ASN1_STRING's contents from a size_t-length buffer. Returns 1 on
 * success, 0 on failure (including a length the legacy int API cannot hold). */
static inline int hybrid_asn1_octet_set(ASN1_OCTET_STRING *oct,
                                        const unsigned char *data, size_t len)
{
#ifdef HAVE_ASN1_STRING_GET_LENGTH
    return ASN1_STRING_set1_data(oct, data, len);
#else
    if (len > (size_t)INT_MAX)
        return 0;
    return ASN1_STRING_set(oct, data, (int)len);
#endif
}

/* Length of an ASN1_STRING as a size_t (clamps the legacy API's -1 to 0). */
static inline size_t hybrid_asn1_string_length(const ASN1_STRING *str)
{
#ifdef HAVE_ASN1_STRING_GET_LENGTH
    return ASN1_STRING_get_length(str);
#else
    int len = ASN1_STRING_length(str);
    return len < 0 ? 0 : (size_t)len;
#endif
}

#endif /* HYBRID_ASN1_COMPAT_H */
