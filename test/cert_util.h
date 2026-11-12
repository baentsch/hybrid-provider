/*
 * Copyright 2026 The hybrid-provider Authors
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef HYBRID_TEST_CERT_UTIL_H
#define HYBRID_TEST_CERT_UTIL_H

#include <openssl/x509.h>

/*
 * Set a (self-signed) certificate's subject AND issuer distinguished name to a
 * single CN=<cn>, portably and const-correctly.
 *
 * We build the X509_NAME ourselves rather than mutating the object returned by
 * X509_get_subject_name(): that getter's return type gained a `const` qualifier
 * in OpenSSL 4.x, so writing through the returned pointer is not const-correct
 * across the 3.0..4.x range this project spans (casting the const away would only
 * hide the warning, not resolve it). Every function used here keeps a stable,
 * non-const signature across all supported versions.
 *
 * X509_set_subject_name()/X509_set_issuer_name() dup the name, so ownership stays
 * local and is released before returning. Returns 1 on success, 0 on failure.
 */
static inline int hybrid_test_cert_set_cn(X509 *cert, const char *cn)
{
    X509_NAME *name = X509_NAME_new();
    int ok = name != NULL
             && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                           (const unsigned char *)cn, -1, -1, 0)
             && X509_set_subject_name(cert, name)
             && X509_set_issuer_name(cert, name);

    X509_NAME_free(name);
    return ok;
}

#endif /* HYBRID_TEST_CERT_UTIL_H */
