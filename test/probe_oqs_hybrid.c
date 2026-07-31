/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * M1 probe: determine oqsprovider's EVP-level raw key + wire layout for its
 * OQS-legacy hybrid KEMs, so the hybrid-provider can match it byte-for-byte.
 *
 * For each algorithm we print the sizes of:
 *   - ENCODED_PUBLIC_KEY (TLS key-share form)
 *   - PUB_KEY / PRIV_KEY octet-string params
 *   - encapsulation ciphertext and shared secret
 * and compare against the known component sizes to infer raw-concat vs
 * 4-byte length-prefix and component ordering.
 *
 * Build+run via test harness env (OPENSSL_MODULES=build has oqsprovider.so
 * symlinked in by test/setup_oqs_interop.sh).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/err.h>

static size_t octet_size(EVP_PKEY *k, const char *pname)
{
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(k, pname, NULL, 0, &len) <= 0)
        return 0;
    return len;
}

static void probe(OSSL_LIB_CTX *ctx, const char *alg,
                  size_t classic_pub, size_t pq_pub)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=oqsprovider");
    EVP_PKEY *k = NULL;

    printf("=== %s (classic_pub=%zu pq_pub=%zu; concat=%zu, +4prefix=%zu) ===\n",
           alg, classic_pub, pq_pub, classic_pub + pq_pub,
           classic_pub + pq_pub + 4);
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &k) <= 0) {
        printf("  keygen FAILED\n");
        ERR_print_errors_fp(stdout);
        goto done;
    }
    printf("  ENCODED_PUBLIC_KEY = %zu\n",
           octet_size(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY));
    printf("  PUB_KEY            = %zu\n",
           octet_size(k, OSSL_PKEY_PARAM_PUB_KEY));
    printf("  PRIV_KEY           = %zu\n",
           octet_size(k, OSSL_PKEY_PARAM_PRIV_KEY));

    {
        EVP_PKEY_CTX *e = EVP_PKEY_CTX_new_from_pkey(ctx, k, "provider=oqsprovider");
        size_t ctlen = 0, sslen = 0;
        if (e != NULL && EVP_PKEY_encapsulate_init(e, NULL) > 0)
            EVP_PKEY_encapsulate(e, NULL, &ctlen, NULL, &sslen);
        printf("  ciphertext         = %zu\n  shared secret      = %zu\n",
               ctlen, sslen);
        EVP_PKEY_CTX_free(e);
    }
done:
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(g);
    printf("\n");
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
        || OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        fprintf(stderr, "provider load failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* component pub sizes: EC uncompressed point / X25519 raw; ML-KEM pub */
    probe(ctx, "x25519_mlkem512", 32, 800);    /* ML-KEM-512 pub = 800 */
    probe(ctx, "p384_mlkem768",   97, 1184);   /* P-384 uncompressed; MLKEM768 */
    probe(ctx, "p256_mlkem512",   65, 800);
    probe(ctx, "x448_mlkem768",   56, 1184);

    OSSL_LIB_CTX_free(ctx);
    return 0;
}
