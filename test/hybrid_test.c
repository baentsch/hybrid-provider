/*
 * Copyright 2026 hybrid-provider contributors
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

/* Does the named provider (matched by property) expose ML-KEM-768? */
static int provider_has_mlkem(OSSL_LIB_CTX *libctx, const char *provprop)
{
    char propq[128];
    EVP_KEM *kem;
    int ok;

    snprintf(propq, sizeof(propq), "provider=%s", provprop);
    kem = EVP_KEM_fetch(libctx, "MLKEM768", propq);
    ok = (kem != NULL);
    EVP_KEM_free(kem);
    ERR_clear_error();
    return ok;
}

/*
 * Set the property query the hybrid provider uses to resolve its component
 * sub-algorithms, so we can steer the ML-KEM component to a specific provider
 * (e.g. "?provider=bcrust"). Returns 1 on success, 0 on failure.
 */
static int set_component_propq(EVP_PKEY_CTX *gctx, const char *comp_propq)
{
    OSSL_PARAM gp[2];

    if (comp_propq == NULL)
        return 1;
    gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES,
                                             (char *)comp_propq, 0);
    gp[1] = OSSL_PARAM_construct_end();
    return EVP_PKEY_CTX_set_params(gctx, gp) > 0;
}

/*
 * Test 1: Self-consistency — generate, encapsulate, decapsulate within
 * the hybrid provider. Shared secrets must match. When comp_propq is non-NULL
 * the component sub-algorithms are resolved with that property query.
 */
static int test_self_consistency(OSSL_LIB_CTX *libctx, const char *algname,
                                 const char *comp_propq)
{
    char label[160];
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *ctext = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t ctlen = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ret = 0;

    if (comp_propq != NULL)
        snprintf(label, sizeof(label), "self-consistency %s (components %s)",
                 algname, comp_propq);
    else
        snprintf(label, sizeof(label), "self-consistency %s", algname);
    TEST_START(label);

    /* Generate keypair using hybrid provider */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0) {
        TEST_FAIL("keygen init failed");
        goto err;
    }
    if (!set_component_propq(gctx, comp_propq)) {
        TEST_FAIL("set component properties failed");
        goto err;
    }
    if (EVP_PKEY_keygen(gctx, &key) <= 0) {
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
                                            const char *algname,
                                            const char *comp_propq)
{
    char label[160];
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY_CTX *import_ctx = NULL;
    EVP_PKEY *hybrid_key = NULL, *default_key = NULL;
    unsigned char *pubraw = NULL;
    unsigned char *ctext = NULL, *ss_enc = NULL, *ss_dec = NULL;
    size_t publen = 0, ctlen = 0, ss_enc_len = 0, ss_dec_len = 0;
    int ret = 0;

    if (comp_propq != NULL)
        snprintf(label, sizeof(label),
                 "cross-encap (default encaps) %s (components %s)",
                 algname, comp_propq);
    else
        snprintf(label, sizeof(label),
                 "cross-encap (default encaps) %s", algname);
    TEST_START(label);

    /* Generate keypair with hybrid provider */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0) {
        TEST_FAIL("hybrid keygen init failed");
        goto err;
    }
    if (!set_component_propq(gctx, comp_propq)) {
        TEST_FAIL("set component properties failed");
        goto err;
    }
    if (EVP_PKEY_keygen(gctx, &hybrid_key) <= 0) {
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

/*
 * Signature test: self-consistency — keygen, sign, verify.
 */
static int test_sig_self_consistency(OSSL_LIB_CTX *libctx, const char *algname)
{
    char label[128];
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sctx = NULL, *vctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const unsigned char msg[] = "hybrid signature test message";
    size_t msglen = sizeof(msg) - 1;
    int ret = 0;

    snprintf(label, sizeof(label), "sig self-consistency %s", algname);
    TEST_START(label);

    /* Generate keypair */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &key) <= 0) {
        TEST_FAIL("keygen failed");
        goto err;
    }

    /* Sign */
    sctx = EVP_MD_CTX_new();
    if (sctx == NULL) {
        TEST_FAIL("EVP_MD_CTX_new failed");
        goto err;
    }
    if (EVP_DigestSignInit_ex(sctx, NULL, NULL, libctx,
                               "provider=hybrid", key, NULL) <= 0) {
        TEST_FAIL("DigestSignInit failed");
        goto err;
    }
    /* Query size */
    if (EVP_DigestSign(sctx, NULL, &siglen, msg, msglen) <= 0) {
        TEST_FAIL("DigestSign size query failed");
        goto err;
    }
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        TEST_FAIL("malloc failed");
        goto err;
    }
    if (EVP_DigestSign(sctx, sig, &siglen, msg, msglen) <= 0) {
        TEST_FAIL("DigestSign failed");
        goto err;
    }

    /* Verify */
    vctx = EVP_MD_CTX_new();
    if (vctx == NULL) {
        TEST_FAIL("EVP_MD_CTX_new failed");
        goto err;
    }
    if (EVP_DigestVerifyInit_ex(vctx, NULL, NULL, libctx,
                                 "provider=hybrid", key, NULL) <= 0) {
        TEST_FAIL("DigestVerifyInit failed");
        goto err;
    }
    if (EVP_DigestVerify(vctx, sig, siglen, msg, msglen) <= 0) {
        TEST_FAIL("DigestVerify failed");
        goto err;
    }

    TEST_PASS();
    ret = 1;

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Signature test: wrong message — sign, corrupt message, verify should fail.
 */
static int test_sig_wrong_message(OSSL_LIB_CTX *libctx, const char *algname)
{
    char label[128];
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *sctx = NULL, *vctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const unsigned char msg[] = "hybrid signature test message";
    const unsigned char bad[] = "hybrid signature WRONG message";
    size_t msglen = sizeof(msg) - 1;
    size_t badlen = sizeof(bad) - 1;
    int ret = 0;

    snprintf(label, sizeof(label), "sig wrong-message %s", algname);
    TEST_START(label);

    /* Generate keypair */
    gctx = EVP_PKEY_CTX_new_from_name(libctx, algname, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
        || EVP_PKEY_keygen(gctx, &key) <= 0) {
        TEST_FAIL("keygen failed");
        goto err;
    }

    /* Sign */
    sctx = EVP_MD_CTX_new();
    if (sctx == NULL) {
        TEST_FAIL("EVP_MD_CTX_new failed");
        goto err;
    }
    if (EVP_DigestSignInit_ex(sctx, NULL, NULL, libctx,
                               "provider=hybrid", key, NULL) <= 0) {
        TEST_FAIL("DigestSignInit failed");
        goto err;
    }
    if (EVP_DigestSign(sctx, NULL, &siglen, msg, msglen) <= 0) {
        TEST_FAIL("DigestSign size query failed");
        goto err;
    }
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL) {
        TEST_FAIL("malloc failed");
        goto err;
    }
    if (EVP_DigestSign(sctx, sig, &siglen, msg, msglen) <= 0) {
        TEST_FAIL("DigestSign failed");
        goto err;
    }

    /* Verify with wrong message — must fail */
    vctx = EVP_MD_CTX_new();
    if (vctx == NULL) {
        TEST_FAIL("EVP_MD_CTX_new failed");
        goto err;
    }
    if (EVP_DigestVerifyInit_ex(vctx, NULL, NULL, libctx,
                                 "provider=hybrid", key, NULL) <= 0) {
        TEST_FAIL("DigestVerifyInit failed");
        goto err;
    }
    if (EVP_DigestVerify(vctx, sig, siglen, bad, badlen) > 0) {
        TEST_FAIL("DigestVerify should have failed with wrong message");
        goto err;
    }

    /* Clear expected errors */
    ERR_clear_error();

    TEST_PASS();
    ret = 1;

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_free(key);
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
        test_self_consistency(libctx, alg, NULL);
        test_key_roundtrip(libctx, alg);
        test_cross_encap_default_encaps(libctx, alg, NULL);
        test_cross_encap_hybrid_encaps(libctx, alg);
        printf("\n");
    }

    /*
     * Optional: compose the ML-KEM component from bcrust-provider instead of
     * the default provider. bcrust-provider ships its own FIPS 203 ML-KEM, so
     * this exercises cross-provider composition and proves that a bcrust-sourced
     * ML-KEM interoperates with OpenSSL's native MLX hybrid (requires 3.5+).
     * The module loads as "bcrust_provider" but advertises "provider=bcrust".
     * Skipped (not failed) when bcrust-provider is not on the module path.
     */
    {
        OSSL_PROVIDER *bcrust_prov = OSSL_PROVIDER_load(libctx, "bcrust_provider");

        if (bcrust_prov != NULL && provider_has_mlkem(libctx, "bcrust")) {
            printf("[bcrust-provider ML-KEM composition]\n");
            for (size_t i = 0; i < nalgs; i++) {
                test_self_consistency(libctx, algorithms[i], "?provider=bcrust");
                test_cross_encap_default_encaps(libctx, algorithms[i],
                                                "?provider=bcrust");
            }
            printf("\n");
        } else {
            printf("[bcrust-provider ML-KEM composition] SKIPPED "
                   "(bcrust_provider unavailable)\n\n");
            ERR_clear_error();
        }
        if (bcrust_prov != NULL)
            OSSL_PROVIDER_unload(bcrust_prov);
    }

    /* --- Signature tests --- */
    {
        static const char *sig_algorithms[] = {
            "ed25519mldsa44",
            "ed25519mldsa65",
            "ed448mldsa87",
            "p256mldsa44",
            "p256mldsa65",
            "p384mldsa87",
        };
        size_t nsigs = sizeof(sig_algorithms) / sizeof(sig_algorithms[0]);

        for (size_t i = 0; i < nsigs; i++) {
            const char *alg = sig_algorithms[i];

            printf("[%s]\n", alg);
            test_sig_self_consistency(libctx, alg);
            test_sig_wrong_message(libctx, alg);
            printf("\n");
        }
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
