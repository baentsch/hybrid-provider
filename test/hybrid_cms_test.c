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
 * self-signed certificate signed with it, build a CMS SignedData over a message,
 * then CMS_verify it — proving the hybrid AlgorithmIdentifier and one-shot
 * signing drive OpenSSL's CMS layer, not just X.509/TLS (that is
 * hybrid_cert_tls_test). A tampered content is required to FAIL verification.
 *
 * Each algorithm is exercised in BOTH CMS SignerInfo modes (work-items item 14):
 *  - with signed attributes (the default; SHA-512 messageDigest attribute), and
 *  - without signed attributes (CMS_NOATTR, `openssl cms -sign -noattr`), where
 *    the hybrid signature is computed directly over the content. The no-attribute
 *    path had no coverage; a provider that only handled attribute-wrapped signing
 *    would pass the first and fail the second.
 *
 * The set of algorithms is driven off the master HYBRID_SIG_LIST, split by PQ
 * half: the standardized (ML-DSA) hybrids use the default provider's ML-DSA
 * (3.5+), so no oqsprovider is needed; the non-standardized PQ signatures
 * (Falcon, MAYO, OV, SNOVA, MQOM, ...) need oqsprovider and are skipped without
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
#include "hybrid_prov.h"

static int tests, passed, failed, skipped;

/*
 * A hybrid's PQ half is "standardized" when it is ML-DSA, which the default
 * provider ships (OpenSSL >= 3.5); every other PQ signature (Falcon, MAYO, OV,
 * SNOVA, MQOM, ...) is non-standardized and only oqsprovider provides it. We do
 * not enumerate the algorithms here — the set is driven off the master
 * HYBRID_SIG_LIST so it never goes stale as rows are added.
 */
static int is_standardized_pq_sig(const char *pq_name)
{
    return strncmp(pq_name, "MLDSA", 5) == 0;
}

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

/*
 * Does this OpenSSL support CMS content-signing (CMS_NOATTR) for a "md-less"
 * signature algorithm — one with no default digest, like ML-DSA and our hybrids?
 *
 * OpenSSL routes attribute-free CMS signing for such algorithms through the
 * message-signature API (EVP_PKEY_sign_message_*), which only landed after 3.5:
 * on 3.5.x even *native* ML-DSA `cms -sign -noattr` fails with "provider
 * signature not supported". We probe the capability at runtime with native
 * ML-DSA-44 (always present with the default provider on 3.5+) rather than
 * hard-coding a version, so the hybrid `-noattr` expectation tracks whatever the
 * running library actually supports. The hybrid provider implements the
 * message-signature API regardless (proven directly by the round-trip below), so
 * the moment the base library supports the path, the hybrid `-noattr` cases pass.
 */
static int mdless_cms_noattr_supported(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, "ML-DSA-44", NULL);
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL;
    const unsigned char content[] = "probe";
    unsigned int flags = CMS_BINARY | CMS_PARTIAL | CMS_DETACHED;
    int supported = 0;

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
            || EVP_PKEY_keygen(g, &pkey) <= 0)
        goto end;                                   /* no native ML-DSA: give up */
    if ((cert = X509_new_ex(libctx, NULL)) == NULL
            || !X509_set_version(cert, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL
            || !X509_set_pubkey(cert, pkey))
        goto end;
    name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"probe", -1, -1, 0)
            || !X509_set_issuer_name(cert, name)
            || X509_sign(cert, pkey, NULL) == 0)
        goto end;

    in = BIO_new_mem_buf(content, sizeof(content) - 1);
    cms = CMS_sign_ex(NULL, NULL, NULL, in, flags, libctx, NULL);
    if (cms != NULL
            && CMS_add1_signer(cms, cert, pkey, EVP_sha512(),
                               CMS_BINARY | CMS_NOATTR) != NULL
            && CMS_final(cms, in, NULL, flags) > 0)
        supported = 1;
end:
    ERR_clear_error();
    BIO_free(in);
    CMS_ContentInfo_free(cms);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    EVP_PKEY_CTX_free(g);
    return supported;
}

/*
 * Decode CMS DER into a ContentInfo bound to `libctx`. This matters for the
 * -noattr (content-signed) path: md-less CMS verification resolves the signature
 * algorithm BY NAME from the ContentInfo's own library context, so a
 * libctx-less d2i (global default context) cannot find the hybrid provider and
 * fails "algorithm unsupported". The signed-attributes path happens to dodge
 * this because it verifies through the signer certificate's public key.
 */
static CMS_ContentInfo *cms_from_der(OSSL_LIB_CTX *libctx,
                                     const unsigned char *der, long derlen)
{
    CMS_ContentInfo *cms = CMS_ContentInfo_new_ex(libctx, NULL);
    const unsigned char *p = der;

    if (cms == NULL)
        return NULL;
    if (d2i_CMS_ContentInfo(&cms, &p, derlen) == NULL) {
        CMS_ContentInfo_free(cms);
        return NULL;
    }
    return cms;
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

/* mode: 0 = with signed attributes, 1 = CMS_NOATTR (no signed attributes).
 * noattr_supported: whether this OpenSSL supports md-less CMS content-signing. */
static void check(OSSL_LIB_CTX *libctx, const char *alg, int noattr,
                  int noattr_supported)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL, *good = NULL, *bad = NULL;
    X509_STORE *store = NULL;
    STACK_OF(X509) *certs = NULL;
    unsigned char *der = NULL;
    long derlen = 0;
    const unsigned char content[] = "hybrid CMS SignedData payload";
    /* Detached: the signature covers the message digest but the content is not
     * embedded, so verification must be supplied the content and a wrong one is
     * cleanly rejected (the tamper check). */
    unsigned int flags = CMS_BINARY | CMS_PARTIAL | CMS_DETACHED;
    /* CMS_NOATTR: no signed attributes -> the hybrid signature is computed
     * directly over the content, not over a messageDigest attribute. */
    unsigned int signer_flags = CMS_BINARY | (noattr ? CMS_NOATTR : 0);

    /* The base library cannot content-sign an md-less algorithm here (< 3.6);
     * native ML-DSA fails identically. Skip rather than record a false failure —
     * the hybrid message-signature API itself is proven by the direct round-trip
     * in main(). */
    if (noattr && !noattr_supported) {
        printf("  %-24s CMS sign/verify (sha512, -noattr) ... SKIP "
               "(no md-less CMS content-signing in this OpenSSL)\n", alg);
        skipped++;
        return;
    }

    tests++;
    printf("  %-24s CMS sign/verify (%s) ... ",
           alg, noattr ? "sha512, -noattr" : "sha512, signed attrs");
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
            || CMS_add1_signer(cms, cert, pkey, EVP_sha512(),
                               signer_flags) == NULL
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
    cms = cms_from_der(libctx, der, derlen);
    good = BIO_new_mem_buf(content, sizeof(content) - 1);
    if (cms == NULL || good == NULL
            || CMS_verify(cms, certs, store, good, NULL, CMS_BINARY) <= 0)
        goto fail;

    /* Tamper: verify the same signature against different content -> must fail
     * (messageDigest mismatch, or content-signature mismatch under -noattr). */
    CMS_ContentInfo_free(cms);
    cms = cms_from_der(libctx, der, derlen);
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

/*
 * Direct round-trip of the hybrid provider's message-signature API (item 14):
 * streaming sign_message init/update/final, then verify_message init/update
 * (signature delivered via OSSL_SIGNATURE_PARAM_SIGNATURE)/final, plus a tamper
 * check. This is the machinery OpenSSL's md-less CMS content-signing drives, and
 * it exercises the provider's new entry points regardless of whether the base
 * library's CMS layer is new enough to use them (so it gives real coverage on
 * 3.5.x too).
 */
static void check_message_api(OSSL_LIB_CTX *libctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, alg, "provider=hybrid");
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *sc = NULL, *vc = NULL, *vc2 = NULL;
    unsigned char *sbuf = NULL;
    size_t slen = 0;
    const unsigned char msg[] = "hybrid message-signature streaming round-trip";
    const unsigned char bad[] = "Hybrid message-signature streaming round-trip";
    const size_t half = 20;
    OSSL_PARAM vp[2];

    tests++;
    printf("  %-24s message-API sign/verify (stream) ... ", alg);
    fflush(stdout);

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0
            || EVP_PKEY_keygen(g, &pkey) <= 0) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    /* streaming sign: size query, then the real signature */
    sig = EVP_SIGNATURE_fetch(libctx, alg, "provider=hybrid");
    sc = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (sig == NULL || sc == NULL
            || EVP_PKEY_sign_message_init(sc, sig, NULL) <= 0
            || EVP_PKEY_sign_message_update(sc, msg, half) <= 0
            || EVP_PKEY_sign_message_update(sc, msg + half,
                                            sizeof(msg) - 1 - half) <= 0
            || EVP_PKEY_sign_message_final(sc, NULL, &slen) <= 0
            || (sbuf = OPENSSL_malloc(slen)) == NULL
            || EVP_PKEY_sign_message_final(sc, sbuf, &slen) <= 0)
        goto fail;

    /* streaming verify: signature supplied via ctx-param */
    vp[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE,
                                              sbuf, slen);
    vp[1] = OSSL_PARAM_construct_end();
    vc = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (vc == NULL
            || EVP_PKEY_verify_message_init(vc, sig, NULL) <= 0
            || EVP_PKEY_CTX_set_params(vc, vp) <= 0
            || EVP_PKEY_verify_message_update(vc, msg, half) <= 0
            || EVP_PKEY_verify_message_update(vc, msg + half,
                                              sizeof(msg) - 1 - half) <= 0
            || EVP_PKEY_verify_message_final(vc) <= 0)
        goto fail;

    /* tamper: same signature, altered message -> must FAIL */
    vc2 = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if (vc2 == NULL
            || EVP_PKEY_verify_message_init(vc2, sig, NULL) <= 0
            || EVP_PKEY_CTX_set_params(vc2, vp) <= 0
            || EVP_PKEY_verify_message_update(vc2, bad, sizeof(bad) - 1) <= 0)
        goto fail;
    if (EVP_PKEY_verify_message_final(vc2) > 0) {
        printf("FAIL (tampered message verified)\n");
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
    OPENSSL_free(sbuf);
    EVP_PKEY_CTX_free(sc);
    EVP_PKEY_CTX_free(vc);
    EVP_PKEY_CTX_free(vc2);
    EVP_SIGNATURE_free(sig);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(g);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    int have_oqs, noattr_supported;
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
    noattr_supported = mdless_cms_noattr_supported(ctx);

    printf("hybrid signatures in CMS SignedData\n");
    printf("===================================\n");
    printf("  md-less CMS content-signing (-noattr) supported by this "
           "OpenSSL: %s\n", noattr_supported ? "yes" : "no");
    /* Drive the whole hybrid-signature inventory from the master table. The
     * standardized (ML-DSA) hybrids run against the default provider; the
     * non-standardized ones need oqsprovider and are skipped without it. Each
     * algorithm additionally self-skips if its components are unavailable. */
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *info = &hybrid_sig_table[i];

        if (is_standardized_pq_sig(info->alg2_name) || have_oqs) {
            check(ctx, info->hybrid_name, 0, noattr_supported);   /* signed attrs */
            check(ctx, info->hybrid_name, 1, noattr_supported);   /* CMS_NOATTR */
            check_message_api(ctx, info->hybrid_name);            /* item 14 API */
        }
    }
    if (!have_oqs)
        printf("  (oqsprovider absent -- skipping non-standardized PQ "
               "signatures)\n");

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
