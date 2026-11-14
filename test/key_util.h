/*
 * Copyright 2026 The hybrid-provider Authors
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef HYBRID_TEST_KEY_UTIL_H
#define HYBRID_TEST_KEY_UTIL_H

/*
 * Key and operation helpers shared by the table-driven negative/dispatch tests
 * (hybrid_op_neg_test, hybrid_dispatch_test). Every fetch pins the hybrid
 * provider via HYBRID_TEST_PROPQ; every helper clears the error queue so a
 * probe that fails by design leaves nothing behind for the next check.
 */
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define HYBRID_TEST_PROPQ "provider=hybrid"

/* Fail the current check: print `what` and the error queue, clear `ok`, and
 * jump to the caller's `end:` label. */
#define HYBRID_TEST_EXPECT(cond, what)                                       \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("FAIL: %s\n", what);                                      \
            ERR_print_errors_fp(stdout);                                     \
            ok = 0;                                                          \
            goto end;                                                        \
        }                                                                    \
    } while (0)

/* A freshly generated `alg` keypair, or NULL (components unavailable). */
static inline EVP_PKEY *hybrid_test_keygen(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, HYBRID_TEST_PROPQ);
    EVP_PKEY *k = NULL;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0)
        EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    ERR_clear_error();
    return k;
}

/* `k`'s `selection` exported and re-imported as a fresh `alg` key, or NULL. */
static inline EVP_PKEY *hybrid_test_reimport(OSSL_LIB_CTX *ctx,
                                             const char *alg, EVP_PKEY *k,
                                             int selection)
{
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *c = NULL;
    EVP_PKEY *out = NULL;

    if (EVP_PKEY_todata(k, selection, &params) > 0
            && (c = EVP_PKEY_CTX_new_from_name(ctx, alg,
                                               HYBRID_TEST_PROPQ)) != NULL
            && EVP_PKEY_fromdata_init(c) > 0)
        EVP_PKEY_fromdata(c, &out, selection, params);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return out;
}

/*
 * An `alg` key carrying no key material (paramgen-style), or NULL when the
 * family has none to offer. A family whose generator always produces a full
 * keypair regardless of selection yields a key that exports a public half;
 * that is not material-less, so it is discarded (NULL).
 */
static inline EVP_PKEY *hybrid_test_empty_key(OSSL_LIB_CTX *ctx,
                                              const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, HYBRID_TEST_PROPQ);
    EVP_PKEY *k = NULL;
    OSSL_PARAM *params = NULL;

    if (g != NULL && EVP_PKEY_paramgen_init(g) > 0)
        EVP_PKEY_paramgen(g, &k);
    EVP_PKEY_CTX_free(g);
    if (k != NULL && EVP_PKEY_todata(k, EVP_PKEY_PUBLIC_KEY, &params) > 0) {
        EVP_PKEY_free(k);
        k = NULL;
    }
    OSSL_PARAM_free(params);
    ERR_clear_error();
    return k;
}

/* 1 iff `sig` is a valid signature by `k` over msg[0..msglen). */
static inline int hybrid_test_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *k,
                                     const unsigned char *sig, size_t siglen,
                                     const unsigned char *msg, size_t msglen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int r = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, HYBRID_TEST_PROPQ, k,
                                   NULL) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, msglen) == 1;

    EVP_MD_CTX_free(m);
    ERR_clear_error();
    return r;
}

/* Decapsulate `ct` with `k` into ss (in: capacity, out: length); 1 on success. */
static inline int hybrid_test_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *k,
                                     const unsigned char *ct, size_t ctlen,
                                     unsigned char *ss, size_t *sslen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, k, HYBRID_TEST_PROPQ);
    int r = c != NULL && EVP_PKEY_decapsulate_init(c, NULL) > 0
        && EVP_PKEY_decapsulate(c, ss, sslen, ct, ctlen) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return r;
}

#endif /* HYBRID_TEST_KEY_UTIL_H */
