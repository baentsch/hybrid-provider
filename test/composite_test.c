/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) provider test (issue #6): drive the composite provider
 * through the public EVP API by name — keygen, one-shot EVP_DigestSign /
 * EVP_DigestVerify, and a tamper check — for every row in the master table.
 * Standardized ML-DSA combos need only the default provider; the experimental
 * tier needs oqsprovider; each combo self-skips when its components are absent.
 *
 * Proves the provider wiring (keymgmt + signature dispatch + registration). Wire-
 * format interop is a separate, external matter (Bouncy Castle / OpenSSL-native).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include "composite_prov.h"

static int tests, passed, failed, skipped;

#define CERT_VALIDITY_SECS  (365L * 24 * 60 * 60)   /* one year */

/* Encode the public key to DER SPKI, decode it back, and verify a signature made
 * by the original key with the *decoded* key — exercises the encoder, decoder and
 * public-component reconstruction. */
static int spki_roundtrip_ok(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info,
                             EVP_PKEY *key)
{
    const unsigned char msg[] = "composite SPKI encode/decode round-trip";
    unsigned char *sig = NULL, *der = NULL;
    size_t siglen = 0, derlen = 0;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_PKEY *dec = NULL;
    OSSL_ENCODER_CTX *ec = NULL;
    OSSL_DECODER_CTX *dc = NULL;
    const unsigned char *p;
    int ok = 0;

    if (m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                     key, NULL) <= 0
            || EVP_DigestSign(m, NULL, &siglen, msg, sizeof(msg) - 1) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg) - 1) <= 0)
        goto end;

    ec = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_PUBLIC_KEY, "DER",
                                       "SubjectPublicKeyInfo",
                                       "provider=hybrid");
    if (ec == NULL || OSSL_ENCODER_to_data(ec, &der, &derlen) <= 0)
        goto end;

    dc = OSSL_DECODER_CTX_new_for_pkey(&dec, "DER", "SubjectPublicKeyInfo",
                                       info->name, EVP_PKEY_PUBLIC_KEY, ctx,
                                       "provider=hybrid");
    p = der;
    if (dc == NULL || OSSL_DECODER_from_data(dc, &p, &derlen) <= 0 || dec == NULL)
        goto end;

    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    ok = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                   dec, NULL) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg) - 1) == 1;
end:
    OPENSSL_free(sig);
    OPENSSL_free(der);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(dec);
    OSSL_ENCODER_CTX_free(ec);
    OSSL_DECODER_CTX_free(dc);
    return ok;
}

/* Self-signed X.509 round-trip: exercises the composite OID registration and the
 * signature's AlgorithmIdentifier getter (one-shot X509_sign, NULL md). */
static int x509_selfsign_ok(OSSL_LIB_CTX *ctx, EVP_PKEY *key)
{
    X509 *cert = X509_new_ex(ctx, NULL);
    X509_NAME *nm;
    int ok = 0;

    if (cert != NULL
            && X509_set_version(cert, X509_VERSION_3)
            && ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            && X509_gmtime_adj(X509_getm_notBefore(cert), 0) != NULL
            && X509_gmtime_adj(X509_getm_notAfter(cert), CERT_VALIDITY_SECS) != NULL
            && X509_set_pubkey(cert, key)
            && (nm = X509_get_subject_name(cert)) != NULL
            && X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                                          (unsigned char *)"composite", -1, -1, 0)
            && X509_set_issuer_name(cert, nm)
            && X509_sign(cert, key, NULL) != 0
            && X509_verify(cert, key) == 1)
        ok = 1;
    X509_free(cert);
    return ok;
}

/* Encode the PRIVATE key to DER PKCS#8, decode it back, and sign with the decoded
 * key + verify with the original — exercises the PKCS#8 encoder/decoder and the
 * private-component (ML-DSA seed) reconstruction. */
static int pkcs8_roundtrip_ok(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info,
                              EVP_PKEY *key)
{
    const unsigned char msg[] = "composite PKCS8 encode/decode round-trip";
    unsigned char *der = NULL, *sig = NULL;
    size_t derlen = 0, siglen = 0;
    EVP_PKEY *dec = NULL;
    OSSL_ENCODER_CTX *ec = NULL;
    OSSL_DECODER_CTX *dc = NULL;
    EVP_MD_CTX *m = NULL;
    const unsigned char *p;
    int ok = 0;

    ec = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, "DER",
                                       "PrivateKeyInfo", "provider=hybrid");
    if (ec == NULL || OSSL_ENCODER_to_data(ec, &der, &derlen) <= 0)
        goto end;
    dc = OSSL_DECODER_CTX_new_for_pkey(&dec, "DER", "PrivateKeyInfo", info->name,
                                       EVP_PKEY_KEYPAIR, ctx, "provider=hybrid");
    p = der;
    if (dc == NULL || OSSL_DECODER_from_data(dc, &p, &derlen) <= 0 || dec == NULL)
        goto end;

    /* Sign with the decoded private key, verify with the original. */
    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                     dec, NULL) <= 0
            || EVP_DigestSign(m, NULL, &siglen, msg, sizeof(msg) - 1) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg) - 1) <= 0)
        goto end;
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    ok = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                   key, NULL) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg) - 1) == 1;
end:
    OPENSSL_free(der);
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(dec);
    OSSL_ENCODER_CTX_free(ec);
    OSSL_DECODER_CTX_free(dc);
    return ok;
}

/* Export the key to OSSL_PARAMs and re-import it, then compare (exercises the
 * keymgmt import/export + match; OID-independent, so runs for every combo). */
static int params_roundtrip_ok(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info,
                               EVP_PKEY *key)
{
    OSSL_PARAM *params = NULL;
    EVP_PKEY *copy = NULL;
    EVP_PKEY_CTX *fc = NULL;
    int ok = 0;

    if (EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &params) <= 0 || params == NULL)
        goto end;
    fc = EVP_PKEY_CTX_new_from_name(ctx, info->name, "provider=hybrid");
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &copy, EVP_PKEY_KEYPAIR, params) <= 0
            || copy == NULL)
        goto end;
    ok = EVP_PKEY_eq(key, copy) == 1;
end:
    OSSL_PARAM_free(params);
    EVP_PKEY_free(copy);
    EVP_PKEY_CTX_free(fc);
    return ok;
}

static void check(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const unsigned char msg[] = "composite provider EVP round-trip";
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *m = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    tests++;
    printf("  %-22s %s ... ", info->name,
           info->tier == COMPOSITE_TIER_EXPERIMENTAL ? "(exp)" : "(std)");
    fflush(stdout);

    gctx = EVP_PKEY_CTX_new_from_name(ctx, info->name, "provider=hybrid");
    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &key) <= 0) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestSignInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                     key, NULL) <= 0
            || EVP_DigestSign(m, NULL, &siglen, msg, sizeof(msg) - 1) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg) - 1) <= 0) {
        printf("FAIL (sign)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                       key, NULL) <= 0
            || EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg) - 1) != 1) {
        printf("FAIL (verify)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }

    sig[siglen - 1] ^= 0x01;
    EVP_MD_CTX_free(m);
    m = EVP_MD_CTX_new();
    if (m != NULL
            && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
                                       key, NULL) > 0
            && EVP_DigestVerify(m, sig, siglen, msg, sizeof(msg) - 1) == 1) {
        printf("FAIL (tampered signature verified)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();

    /* Raw-param export/import round-trip (OID-independent). */
    if (!params_roundtrip_ok(ctx, info, key)) {
        printf("FAIL (todata/fromdata round-trip)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }

    /* Where an OID is assigned, exercise the X.509 + SPKI encode/decode paths. */
    if (info->oid != NULL) {
        if (!x509_selfsign_ok(ctx, key)) {
            printf("FAIL (X509 self-sign/verify)\n");
            ERR_print_errors_fp(stdout);
            failed++;
            goto done;
        }
        if (!spki_roundtrip_ok(ctx, info, key)) {
            printf("FAIL (SPKI encode/decode round-trip)\n");
            ERR_print_errors_fp(stdout);
            failed++;
            goto done;
        }
        if (!pkcs8_roundtrip_ok(ctx, info, key)) {
            printf("FAIL (PKCS8 encode/decode round-trip)\n");
            ERR_print_errors_fp(stdout);
            failed++;
            goto done;
        }
    }
    printf("PASS (sig=%zu, params%s)\n", siglen,
           info->oid ? ", x509, spki, pkcs8" : "");
    passed++;
done:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gctx);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    OSSL_PROVIDER_load(ctx, "oqsprovider");   /* optional: experimental tier */
    ERR_clear_error();

    printf("composite (LAMPS) provider — keygen + sign/verify via EVP\n");
    printf("=========================================================\n");
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check(ctx, &composite_sig_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
