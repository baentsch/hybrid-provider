/*
 * Copyright 2025 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interoperability tests for the hybrid provider against
 * the OpenSSL default provider's built-in hybrid KEMs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

#define TEST_START(name) do { \
    test_count++; \
    printf("  TEST %d: %s ... ", test_count, name); \
    fflush(stdout); \
} while (0)

#define TEST_PASS() do { \
    pass_count++; \
    printf("PASS\n"); \
} while (0)

#define TEST_FAIL(msg) do { \
    fail_count++; \
    printf("FAIL: %s\n", msg); \
    ERR_print_errors_fp(stderr); \
} while (0)

/*
 * Test 1: Self-consistency — generate, encapsulate, decapsulate within
 * the hybrid provider. Shared secrets must match.
 */
static int test_self_consistency(OSSL_LIB_CTX *libctx, const char *algname)
{
    char label[128];
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *ctext = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t ctlen = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ret = 0;

    snprintf(label, sizeof(label), "self-consistency %s", algname);
    TEST_START(label);

    /* Generate keypair using hybrid provider */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &key) <= 0) {
        TEST_FAIL("keygen failed");
        goto err;
    }

    /* Encapsulate */
    ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid");
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0)  {
        TEST_FAIL("encapsulate_init failed");
        goto err;
    }

    /* Query sizes */
    if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &ss_enc_len) <= 0) {
        TEST_FAIL("encapsulate size query failed");
        goto err;
    }

    ctext = OPENSSL_malloc(ctlen);
    ss_enc = OPENSSL_malloc(ss_enc_len);
    if (ctext == NULL || ss_enc == NULL) {
        TEST_FAIL("malloc failed");
        goto err;
    }

    if (EVP_PKEY_encapsulate(ectx, ctext, &ctlen, ss_enc, &ss_enc_len) <= 0) {
        TEST_FAIL("encapsulate failed");
        goto err;
    }

    /* Decapsulate */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid");
    if (dctx == NULL || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        TEST_FAIL("decapsulate_init failed");
        goto err;
    }

    /* Query size */
    if (EVP_PKEY_decapsulate(dctx, NULL, &ss_dec_len, ctext, ctlen) <= 0) {
        TEST_FAIL("decapsulate size query failed");
        goto err;
    }

    ss_dec = OPENSSL_malloc(ss_dec_len);
    if (ss_dec == NULL) {
        TEST_FAIL("malloc failed");
        goto err;
    }

    if (EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ctext, ctlen) <= 0) {
        TEST_FAIL("decapsulate failed");
        goto err;
    }

    /* Compare shared secrets */
    if (ss_enc_len != ss_dec_len
        || memcmp(ss_enc, ss_dec, ss_enc_len) != 0) {
        TEST_FAIL("shared secrets do not match");
        goto err;
    }

    TEST_PASS();
    ret = 1;

err:
    OPENSSL_free(ctext);
    OPENSSL_free(ss_enc);
    OPENSSL_free(ss_dec);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Helper: export raw key bytes from an EVP_PKEY via get_params.
 * Returns allocated buffer, caller must free.
 */
static unsigned char *
export_pubkey(EVP_PKEY *pkey, size_t *outlen)
{
    if (EVP_PKEY_get_octet_string_param(pkey,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0, outlen) <= 0)
        return NULL;

    unsigned char *buf = OPENSSL_malloc(*outlen);
    if (buf == NULL)
        return NULL;

    if (EVP_PKEY_get_octet_string_param(pkey,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, *outlen, outlen) <= 0) {
        OPENSSL_free(buf);
        return NULL;
    }
    return buf;
}

/*
 * Test 2: Cross-provider encapsulate/decapsulate.
 *
 * Generate keypair with hybrid provider, export public key,
 * import into default provider, encapsulate with default,
 * decapsulate with hybrid. Compare shared secrets.
 */
static int test_cross_encap_default_encaps(OSSL_LIB_CTX *libctx,
                                            const char *algname)
{
    char label[128];
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY_CTX *import_ctx = NULL;
    EVP_PKEY *hybrid_key = NULL, *default_key = NULL;
    unsigned char *pubraw = NULL;
    unsigned char *ctext = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t publen = 0, ctlen = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ret = 0;

    snprintf(label, sizeof(label), "cross-encap (default encaps) %s", algname);
    TEST_START(label);

    /* Generate keypair with hybrid provider */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &hybrid_key) <= 0) {
        TEST_FAIL("hybrid keygen failed");
        goto err;
    }
    EVP_PKEY_CTX_free(gctx);
    gctx = NULL;

    /* Export public key from hybrid */
    pubraw = export_pubkey(hybrid_key, &publen);
    if (pubraw == NULL) {
        TEST_FAIL("export pubkey from hybrid failed");
        goto err;
    }

    /* Import public key into default provider */
    import_ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=default");
    if (import_ctx == NULL) {
        TEST_FAIL("default provider CTX creation failed");
        goto err;
    }
    {
        OSSL_PARAM iparams[2];
        iparams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, pubraw, publen);
        iparams[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(import_ctx) <= 0
            || EVP_PKEY_fromdata(import_ctx, &default_key,
                                 OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                                 | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                                 iparams) <= 0) {
            TEST_FAIL("import into default provider failed");
            goto err;
        }
    }

    /* Encapsulate with default provider */
    ectx = EVP_PKEY_CTX_new_from_pkey(libctx, default_key, "provider=default");
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) {
        TEST_FAIL("default encapsulate_init failed");
        goto err;
    }
    if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &ss_enc_len) <= 0) {
        TEST_FAIL("default encapsulate size query failed");
        goto err;
    }
    ctext = OPENSSL_malloc(ctlen);
    ss_enc = OPENSSL_malloc(ss_enc_len);
    if (EVP_PKEY_encapsulate(ectx, ctext, &ctlen, ss_enc, &ss_enc_len) <= 0) {
        TEST_FAIL("default encapsulate failed");
        goto err;
    }

    /* Decapsulate with hybrid provider */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, hybrid_key, "provider=hybrid");
    if (dctx == NULL || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        TEST_FAIL("hybrid decapsulate_init failed");
        goto err;
    }
    if (EVP_PKEY_decapsulate(dctx, NULL, &ss_dec_len, ctext, ctlen) <= 0) {
        TEST_FAIL("hybrid decapsulate size query failed");
        goto err;
    }
    ss_dec = OPENSSL_malloc(ss_dec_len);
    if (EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ctext, ctlen) <= 0) {
        TEST_FAIL("hybrid decapsulate failed");
        goto err;
    }

    /* Compare */
    if (ss_enc_len != ss_dec_len
        || memcmp(ss_enc, ss_dec, ss_enc_len) != 0) {
        TEST_FAIL("shared secrets do not match");
        goto err;
    }

    TEST_PASS();
    ret = 1;

err:
    OPENSSL_free(pubraw);
    OPENSSL_free(ctext);
    OPENSSL_free(ss_enc);
    OPENSSL_free(ss_dec);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(import_ctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(hybrid_key);
    EVP_PKEY_free(default_key);
    return ret;
}

/*
 * Test 3: Cross-provider — default generates, hybrid encapsulates,
 * default decapsulates.
 */
static int test_cross_encap_hybrid_encaps(OSSL_LIB_CTX *libctx,
                                           const char *algname)
{
    char label[128];
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY_CTX *import_ctx = NULL;
    EVP_PKEY *default_key = NULL, *hybrid_pub = NULL;
    unsigned char *pubraw = NULL;
    unsigned char *ctext = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t publen = 0, ctlen = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ret = 0;

    snprintf(label, sizeof(label), "cross-encap (hybrid encaps) %s", algname);
    TEST_START(label);

    /* Generate keypair with default provider */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=default");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &default_key) <= 0) {
        TEST_FAIL("default keygen failed");
        goto err;
    }
    EVP_PKEY_CTX_free(gctx);
    gctx = NULL;

    /* Export public key from default */
    pubraw = export_pubkey(default_key, &publen);
    if (pubraw == NULL) {
        TEST_FAIL("export pubkey from default failed");
        goto err;
    }

    /* Import public key into hybrid provider */
    import_ctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (import_ctx == NULL) {
        TEST_FAIL("hybrid provider CTX creation failed");
        goto err;
    }
    {
        OSSL_PARAM iparams[2];
        iparams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, pubraw, publen);
        iparams[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(import_ctx) <= 0
            || EVP_PKEY_fromdata(import_ctx, &hybrid_pub,
                                 OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                                 | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                                 iparams) <= 0) {
            TEST_FAIL("import into hybrid provider failed");
            goto err;
        }
    }

    /* Encapsulate with hybrid provider */
    ectx = EVP_PKEY_CTX_new_from_pkey(libctx, hybrid_pub, "provider=hybrid");
    if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0) {
        TEST_FAIL("hybrid encapsulate_init failed");
        goto err;
    }
    if (EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &ss_enc_len) <= 0) {
        TEST_FAIL("hybrid encapsulate size query failed");
        goto err;
    }
    ctext = OPENSSL_malloc(ctlen);
    ss_enc = OPENSSL_malloc(ss_enc_len);
    if (EVP_PKEY_encapsulate(ectx, ctext, &ctlen, ss_enc, &ss_enc_len) <= 0) {
        TEST_FAIL("hybrid encapsulate failed");
        goto err;
    }

    /* Decapsulate with default provider */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, default_key, "provider=default");
    if (dctx == NULL || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
        TEST_FAIL("default decapsulate_init failed");
        goto err;
    }
    if (EVP_PKEY_decapsulate(dctx, NULL, &ss_dec_len, ctext, ctlen) <= 0) {
        TEST_FAIL("default decapsulate size query failed");
        goto err;
    }
    ss_dec = OPENSSL_malloc(ss_dec_len);
    if (EVP_PKEY_decapsulate(dctx, ss_dec, &ss_dec_len, ctext, ctlen) <= 0) {
        TEST_FAIL("default decapsulate failed");
        goto err;
    }

    /* Compare */
    if (ss_enc_len != ss_dec_len
        || memcmp(ss_enc, ss_dec, ss_enc_len) != 0) {
        TEST_FAIL("shared secrets do not match");
        goto err;
    }

    TEST_PASS();
    ret = 1;

err:
    OPENSSL_free(pubraw);
    OPENSSL_free(ctext);
    OPENSSL_free(ss_enc);
    OPENSSL_free(ss_dec);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(import_ctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(default_key);
    EVP_PKEY_free(hybrid_pub);
    return ret;
}

/*
 * Test 4: Key export/import round-trip.
 * Generate with hybrid, export, import back, compare public keys.
 */
static int test_key_roundtrip(OSSL_LIB_CTX *libctx, const char *algname)
{
    char label[128];
    EVP_PKEY_CTX *gctx = NULL, *ictx = NULL;
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    unsigned char *pub1 = NULL, *pub2 = NULL;
    size_t pub1len = 0, pub2len = 0;
    int ret = 0;

    snprintf(label, sizeof(label), "key roundtrip %s", algname);
    TEST_START(label);

    /* Generate */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &key1) <= 0) {
        TEST_FAIL("keygen failed");
        goto err;
    }

    /* Export public key */
    pub1 = export_pubkey(key1, &pub1len);
    if (pub1 == NULL) {
        TEST_FAIL("export failed");
        goto err;
    }

    /* Import back */
    ictx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (ictx == NULL) {
        TEST_FAIL("import CTX creation failed");
        goto err;
    }
    {
        OSSL_PARAM iparams[2];
        iparams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub1, pub1len);
        iparams[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_fromdata_init(ictx) <= 0
            || EVP_PKEY_fromdata(ictx, &key2,
                                 OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                                 | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                                 iparams) <= 0) {
            TEST_FAIL("import failed");
            goto err;
        }
    }

    /* Re-export and compare */
    pub2 = export_pubkey(key2, &pub2len);
    if (pub2 == NULL) {
        TEST_FAIL("re-export failed");
        goto err;
    }

    if (pub1len != pub2len || memcmp(pub1, pub2, pub1len) != 0) {
        TEST_FAIL("public keys do not match after roundtrip");
        goto err;
    }

    TEST_PASS();
    ret = 1;

err:
    OPENSSL_free(pub1);
    OPENSSL_free(pub2);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(ictx);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    return ret;
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *hybrid_prov = NULL, *dflt_prov = NULL;
    const char *modulepath;
    int exit_code = 1;

    static const char *algorithms[] = {
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "X448MLKEM1024",
        "SecP384r1MLKEM1024",
    };
    size_t nalgs = sizeof(algorithms) / sizeof(algorithms[0]);

    /* Use OPENSSL_MODULES env or build dir */
    modulepath = getenv("OPENSSL_MODULES");

    printf("hybrid-provider interoperability tests\n");
    printf("======================================\n");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL) {
        fprintf(stderr, "Failed to create library context\n");
        goto done;
    }

    /* Load default provider first */
    dflt_prov = OSSL_PROVIDER_load(libctx, "default");
    if (dflt_prov == NULL) {
        fprintf(stderr, "Failed to load default provider\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    /* Set search path for hybrid provider if given */
    if (modulepath != NULL)
        OSSL_PROVIDER_set_default_search_path(libctx, modulepath);

    hybrid_prov = OSSL_PROVIDER_load(libctx, "hybrid");
    if (hybrid_prov == NULL) {
        fprintf(stderr, "Failed to load hybrid provider from %s\n",
                modulepath ? modulepath : "(default path)");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    printf("Providers loaded successfully.\n\n");

    for (size_t i = 0; i < nalgs; i++) {
        const char *alg = algorithms[i];

        printf("[%s]\n", alg);
        test_self_consistency(libctx, alg);
        test_key_roundtrip(libctx, alg);
        test_cross_encap_default_encaps(libctx, alg);
        test_cross_encap_hybrid_encaps(libctx, alg);
        printf("\n");
    }

    printf("======================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           pass_count, test_count, fail_count);

    exit_code = (fail_count == 0) ? 0 : 1;

done:
    OSSL_PROVIDER_unload(hybrid_prov);
    OSSL_PROVIDER_unload(dflt_prov);
    OSSL_LIB_CTX_free(libctx);
    return exit_code;
}
