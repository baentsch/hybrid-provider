/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Thin ASN.1 string compatibility shim.
 *
 * OpenSSL 4.1 deprecated the int-typed ASN1_STRING_set() / ASN1_STRING_length()
 * in favour of the size_t-typed ASN1_STRING_set_data() / ASN1_STRING_length_ex().
 * We pick between them at compile time on HAVE_ASN1_STRING_LENGTH_EX, which CMake
 * defines via check_symbol_exists() — deliberately a feature test, not a version
 * test: OpenSSL 4.1.0-dev reports the same OPENSSL_VERSION_NUMBER both before and
 * after the new symbols landed, so a version comparison (e.g. PREREQ(4,1)) cannot
 * tell the two apart. Because each branch calls only the API that is current for
 * the build it targets, neither path trips -Wdeprecated-declarations and no
 * diagnostic suppression (#pragma) is needed.
 */
#ifndef HYBRID_ASN1_COMPAT_H
#define HYBRID_ASN1_COMPAT_H

#include <limits.h>
#include <openssl/asn1.h>

/* Set an ASN1_STRING's contents from a size_t-length buffer. Returns 1 on
 * success, 0 on failure (including a length the legacy int API cannot hold). */
static inline int hybrid_asn1_octet_set(ASN1_OCTET_STRING *oct,
                                        const unsigned char *data, size_t len)
{
#ifdef HAVE_ASN1_STRING_LENGTH_EX
    return ASN1_STRING_set_data(oct, data, len);
#else
    if (len > (size_t)INT_MAX)
        return 0;
    return ASN1_STRING_set(oct, data, (int)len);
#endif
}

/* Length of an ASN1_STRING as a size_t (clamps the legacy API's -1 to 0). */
static inline size_t hybrid_asn1_string_length(const ASN1_STRING *str)
{
#ifdef HAVE_ASN1_STRING_LENGTH_EX
    return ASN1_STRING_length_ex(str);
#else
    int len = ASN1_STRING_length(str);
    return len < 0 ? 0 : (size_t)len;
#endif
}

#endif /* HYBRID_ASN1_COMPAT_H */
