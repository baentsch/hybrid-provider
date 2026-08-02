/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * CMS SignedData with hybrid signatures (analog of oqsprovider's
 * scripts/oqsprovider-cmssign.sh / -cmsverify.sh, in-process).
 *
 * oqsprovider proves its hybrid sigs work through the CMS machinery via the CLI
 * (`openssl cms -sign -signer cert -inkey key -md sha512`). We reproduce that
 * end to end in one process: for each hybrid signature, generate a key + a
 * self-signed certificate signed with it, build a CMS SignedData over a message
 * (SHA-512 message digest, signed attributes), then CMS_verify it — proving the
 * hybrid AlgorithmIdentifier and one-shot signing drive OpenSSL's CMS layer, not
 * just X.509/TLS (that is hybrid_cert_tls_test). A tampered content is required
 * to FAIL verification.
 *
 * The ML-DSA hybrids use the default provider's ML-DSA (3.5+), so no oqsprovider
 * is needed; the Falcon/MAYO/… families need oqsprovider and self-skip without
 * it. Each algorithm self-skips if its components are unavailable (e.g. on 3.4).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/err.h>

static int tests, passed, failed, skipped;

/* ML-DSA hybrids: base from the default provider, always attempted. */
static const char *mldsa_sigs[] = {
    "p256_mldsa44", "rsa3072_mldsa44", "p384_mldsa65", "p521_mldsa87",
};
/* Representative oqs-base hybrids across the remaining families (need oqs). */
static const char *oqs_sigs[] = {
    "p256_falcon512", "rsa3072_falcon512", "p521_falcon1024",
    "p256_mayo1", "p384_mayo3",
    "p256_OV_Is_pkc", "p256_snova2454", "p256_mqom2cat1gf16fastr5",
};

static int make_cert(OSSL_LIB_CTX *libctx, const char *alg,
                     EVP_PKEY **pkey_out, X509 **cert_out)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, alg, "provider=hybrid");
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name;
    int ok = 0;

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
            || EVP_PKEY_keygen(g, &pkey) <= 0)
        goto end;                                   /* components unavailable */
    if ((cert = X509_new_ex(libctx, NULL)) == NULL
            || !X509_set_version(cert, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL
            || !X509_set_pubkey(cert, pkey))
        goto end;
    name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"hybrid-cms", -1, -1, 0)
            || !X509_set_issuer_name(cert, name)
            || X509_sign(cert, pkey, NULL) == 0)   /* NULL md: one-shot sig */
        goto end;
    *pkey_out = pkey; pkey = NULL;
    *cert_out = cert; cert = NULL;
    ok = 1;
end:
    EVP_PKEY_CTX_free(g);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ok;
}

/* DER-encode a CMS structure into a fresh buffer. */
static int cms_to_der(CMS_ContentInfo *cms, unsigned char **der, long *derlen)
{
    BIO *b = BIO_new(BIO_s_mem());
    const unsigned char *p;
    long n;
    int ok = 0;

    if (b != NULL && i2d_CMS_bio(b, cms) > 0) {
        n = BIO_get_mem_data(b, &p);
        if (n > 0 && (*der = OPENSSL_memdup(p, n)) != NULL) {
            *derlen = n;
            ok = 1;
        }
    }
    BIO_free(b);
    return ok;
}

static void check(OSSL_LIB_CTX *libctx, const char *alg)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL, *good = NULL, *bad = NULL;
    X509_STORE *store = NULL;
    STACK_OF(X509) *certs = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    long derlen = 0;
    const unsigned char content[] = "hybrid CMS SignedData payload";
    /* Detached: the signature covers the message digest but the content is not
     * embedded, so verification must be supplied the content and a wrong one is
     * cleanly rejected (the tamper check). */
    unsigned int flags = CMS_BINARY | CMS_PARTIAL | CMS_DETACHED;

    tests++;
    printf("  %-24s CMS sign/verify (sha512) ... ", alg);
    fflush(stdout);

    if (!make_cert(libctx, alg, &pkey, &cert)) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    /* Sign: SignedData with SHA-512 message digest + signed attributes, signed
     * with the hybrid key (mirrors `openssl cms -sign ... -md sha512`).
     * The propq is left NULL, not "provider=hybrid": CMS applies it to *every*
     * fetch, including the generic SHA-512 message digest, which the hybrid
     * provider does not implement (it would fail "unknown digest algorithm").
     * The signature is bound to the hybrid key via `pkey`, so it stays hybrid
     * regardless; only the digest needs to resolve from the default provider. */
    in = BIO_new_mem_buf(content, sizeof(content) - 1);
    cms = CMS_sign_ex(NULL, NULL, NULL, in, flags, libctx, NULL);
    if (cms == NULL
            || CMS_add1_signer(cms, cert, pkey, EVP_sha512(), CMS_BINARY) == NULL
            || CMS_final(cms, in, NULL, flags) <= 0)
        goto fail;
    /* Round-trip through DER (exercises the CMS encode/decode path too). */
    if (!cms_to_der(cms, &der, &derlen))
        goto fail;

    /* Trust the self-signed signer cert. */
    store = X509_STORE_new();
    certs = sk_X509_new_null();
    if (store == NULL || certs == NULL
            || X509_STORE_add_cert(store, cert) <= 0
            || !sk_X509_push(certs, cert))
        goto fail;
    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);

    /* Verify against the correct detached content -> must succeed. */
    CMS_ContentInfo_free(cms);
    p = der;
    cms = d2i_CMS_ContentInfo(NULL, &p, derlen);
    good = BIO_new_mem_buf(content, sizeof(content) - 1);
    if (cms == NULL || good == NULL
            || CMS_verify(cms, certs, store, good, NULL, CMS_BINARY) <= 0)
        goto fail;

    /* Tamper: verify the same signature against different content -> must fail
     * (messageDigest mismatch). */
    CMS_ContentInfo_free(cms);
    p = der;
    cms = d2i_CMS_ContentInfo(NULL, &p, derlen);
    bad = BIO_new_mem_buf("different payload!!!", 19);
    if (cms == NULL || bad == NULL)
        goto fail;
    if (CMS_verify(cms, certs, store, bad, NULL, CMS_BINARY) > 0) {
        printf("FAIL (tampered content verified)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();

    printf("PASS\n");
    passed++;
    goto done;
fail:
    printf("FAIL\n");
    ERR_print_errors_fp(stdout);
    failed++;
done:
    BIO_free(in);
    BIO_free(good);
    BIO_free(bad);
    OPENSSL_free(der);
    sk_X509_free(certs);
    X509_STORE_free(store);
    CMS_ContentInfo_free(cms);
    EVP_PKEY_free(pkey);
    X509_free(cert);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    int have_oqs;
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    have_oqs = OSSL_PROVIDER_load(ctx, "oqsprovider") != NULL;
    ERR_clear_error();

    printf("hybrid signatures in CMS SignedData\n");
    printf("===================================\n");
    for (i = 0; i < sizeof(mldsa_sigs) / sizeof(mldsa_sigs[0]); i++)
        check(ctx, mldsa_sigs[i]);
    if (have_oqs)
        for (i = 0; i < sizeof(oqs_sigs) / sizeof(oqs_sigs[0]); i++)
            check(ctx, oqs_sigs[i]);
    else
        printf("  (oqsprovider absent -- skipping Falcon/MAYO/OV/SNOVA/MQOM)\n");

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
