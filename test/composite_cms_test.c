/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * CMS SignedData with composite (LAMPS) signatures — the composite-family analog
 * of hybrid_cms_test.c (issue #109, the SignedData counterpart to the composite
 * ML-KEM CMS KEMRI coverage in hybrid_cms_kem_test.c, #108).
 *
 * hybrid_cms_test.c covers CMS SignedData for the *concatenation* hybrid keytype;
 * the composite keytype (draft-ietf-lamps-pq-composite-sigs-19) is a distinct
 * algorithm, and draft-ietf-lamps-cms-composite-sigs is its CMS binding. For each
 * composite combo we generate a key + a self-signed certificate signed with it,
 * build a CMS SignedData over a message, then CMS_verify it — proving the
 * composite AlgorithmIdentifier and one-shot signing drive OpenSSL's CMS layer. A
 * tampered content is required to FAIL verification.
 *
 * Each combo is exercised in BOTH CMS SignerInfo modes (matching the concat
 * coverage), with no caller digest, so CMS takes the key's mandatory digest --
 * the composite's prehash PH, as draft-ietf-lamps-cms-composite-sigs-05 Table 1
 * requires for the SignerInfo digestAlgorithm:
 *  - with signed attributes: the messageDigest attribute must be PH(content)
 *    (64 bytes for SHAKE256), and CMS signs the attributes via the streaming
 *    digest-sign path;
 *  - without signed attributes (CMS_NOATTR, `openssl cms -sign -noattr`): CMS
 *    hashes the content with PH and signs ph through EVP_PKEY_sign -- draft-19
 *    "External Pre-hashing". The SignerInfo signature must then also verify
 *    over the raw content through the message route, independently of CMS.
 * Another digest (SHA-256 for SHA-512 combos, else SHA-512) must be refused.
 *
 * The draft's own example SignedData (Appendix B) is checked against the
 * draft-19 x5c in composite_kat_test (K9).
 *
 * The combo set is driven off the master composite_sig_table, split by tier: the
 * standardized (ML-DSA) combos use the default provider's ML-DSA (3.5+, and the
 * ML-DSA seed API the composite private encoding needs), so no oqsprovider is
 * required; the experimental combos (Falcon, MAYO, OV, SNOVA, MQOM, CROSS) need
 * oqsprovider and are skipped without it. Each combo self-skips if its components
 * are unavailable (e.g. the standardized tier below 3.5).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "hybrid_asn1_compat.h"   /* hybrid_asn1_string_length */
#include "composite_prov.h"
#include "cert_util.h"   /* hybrid_test_cert_set_cn */
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */

static int tests, passed, failed, skipped;

static int make_cert(OSSL_LIB_CTX *libctx, const char *alg,
                     EVP_PKEY **pkey_out, X509 **cert_out)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, alg, "provider=hybrid");
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
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
    if (!hybrid_test_cert_set_cn(cert, "composite-cms")
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
 * Decode CMS DER into a ContentInfo bound to `libctx` — matters for the -noattr
 * (content-signed) path: md-less CMS verification resolves the signature algorithm
 * BY NAME from the ContentInfo's own library context, so a libctx-less d2i cannot
 * find the composite provider. The signed-attributes path dodges this by verifying
 * through the signer certificate's public key.
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

/* 1 iff si's signature verifies over content via one-shot message verify. */
static int signs_content(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                         CMS_SignerInfo *si, const unsigned char *content,
                         size_t contentlen)
{
    ASN1_OCTET_STRING *sig = CMS_SignerInfo_get0_signature(si);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int r = sig != NULL && m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, libctx, "provider=hybrid",
                                   pkey, NULL) > 0
        && EVP_DigestVerify(m, ASN1_STRING_get0_data(sig),
                            hybrid_asn1_string_length(sig), content,
                            contentlen) == 1;

    ERR_clear_error();
    EVP_MD_CTX_free(m);
    return r;
}

/*
 * Is the SignerInfo's digestAlgorithm the composite's prehash PH (the key's
 * mandatory digest), and -- with signed attributes -- is the messageDigest
 * attribute PH(content) at PH's length?
 */
static int digest_is_ph(OSSL_LIB_CTX *libctx, EVP_PKEY *pkey,
                        CMS_SignerInfo *si, int noattr,
                        const unsigned char *content, size_t contentlen)
{
    char ph[64] = "";
    X509_ALGOR *dig = NULL;
    EVP_MD *md = NULL;
    EVP_MD_CTX *mc = NULL;
    unsigned char want[EVP_MAX_MD_SIZE];
    size_t wantlen;
    const ASN1_OCTET_STRING *got;
    int ok = 0;

    if (EVP_PKEY_get_default_digest_name(pkey, ph, sizeof(ph)) != 2)
        return 0;
    CMS_SignerInfo_get0_algs(si, NULL, NULL, &dig, NULL);
    if (dig == NULL || OBJ_obj2nid(dig->algorithm) != OBJ_txt2nid(ph)
            || dig->parameter != NULL)          /* parameters MUST be absent */
        return 0;
    if (noattr)
        return 1;
    if ((md = EVP_MD_fetch(libctx, ph, NULL)) == NULL
            || (mc = EVP_MD_CTX_new()) == NULL
            || EVP_DigestInit_ex2(mc, md, NULL) <= 0
            || EVP_DigestUpdate(mc, content, contentlen) <= 0)
        goto end;
    if ((EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
        wantlen = COMPOSITE_XOF_PH_BYTES;   /* SHAKE256: 64 bytes, sec. 3.3 */
        if (EVP_DigestFinalXOF(mc, want, wantlen) <= 0)
            goto end;
    } else {
        unsigned int l = 0;

        if (EVP_DigestFinal_ex(mc, want, &l) <= 0)
            goto end;
        wantlen = l;
    }
    got = CMS_signed_get0_data_by_OBJ(si, OBJ_nid2obj(NID_pkcs9_messageDigest),
                                      -3, V_ASN1_OCTET_STRING);
    ok = got != NULL && hybrid_asn1_string_length(got) == wantlen
         && memcmp(ASN1_STRING_get0_data(got), want, wantlen) == 0;
end:
    EVP_MD_CTX_free(mc);
    EVP_MD_free(md);
    return ok;
}

/*
 * A digest other than PH must be refused in both SignerInfo modes, never
 * signed (cms-composite-sigs-05 sec. 3.3: digestAlgorithm MUST be PH). The
 * wrong digest is the realistic one: SHA-256 for the SHA-512 combos, else
 * SHA-512.
 */
static void check_wrong_digest(OSSL_LIB_CTX *libctx,
                               const COMPOSITE_SIG_INFO *info, int noattr)
{
    const char *alg = info->name;
    const char *wrong = OPENSSL_strcasecmp(info->prehash, "SHA512") == 0
                            ? "SHA256" : "SHA512";
    EVP_MD *md = EVP_MD_fetch(libctx, wrong, NULL);
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL;
    const unsigned char content[] = "composite CMS SignedData payload";
    unsigned int flags = CMS_BINARY | CMS_PARTIAL | CMS_DETACHED;
    int signed_ok;

    tests++;
    printf("  %-28s CMS refuses %s (%s) ... ", alg, wrong,
           noattr ? "-noattr" : "signed attrs");
    fflush(stdout);
    if (!make_cert(libctx, alg, &pkey, &cert)) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }
    in = BIO_new_mem_buf(content, sizeof(content) - 1);
    cms = CMS_sign_ex(NULL, NULL, NULL, in, flags, libctx, NULL);
    signed_ok = cms != NULL
        && md != NULL
        && CMS_add1_signer(cms, cert, pkey, md,
                           CMS_BINARY | (noattr ? CMS_NOATTR : 0)) != NULL
        && CMS_final(cms, in, NULL, flags) > 0;
    ERR_clear_error();
    if (signed_ok) {
        printf("FAIL (signed with a digest other than PH)\n");
        failed++;
    } else {
        printf("PASS\n");
        passed++;
    }
done:
    BIO_free(in);
    CMS_ContentInfo_free(cms);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    EVP_MD_free(md);
}

/* mode: 0 = with signed attributes, 1 = CMS_NOATTR (no signed attributes).
 */
static void check(OSSL_LIB_CTX *libctx, const char *alg, int noattr)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL, *good = NULL, *bad = NULL;
    X509_STORE *store = NULL;
    STACK_OF(X509) *certs = NULL;
    CMS_SignerInfo *si = NULL;
    unsigned char *der = NULL;
    long derlen = 0;
    const unsigned char content[] = "composite CMS SignedData payload";
    /* Detached: the signature covers the content/digest but the content is not
     * embedded, so verification is supplied the content and a wrong one is cleanly
     * rejected (the tamper check). */
    unsigned int flags = CMS_BINARY | CMS_PARTIAL | CMS_DETACHED;
    unsigned int signer_flags = CMS_BINARY | (noattr ? CMS_NOATTR : 0);

    tests++;
    printf("  %-28s CMS sign/verify (%s) ... ",
           alg, noattr ? "Table 1 digest, -noattr"
                       : "Table 1 digest, signed attrs");
    fflush(stdout);

    if (!make_cert(libctx, alg, &pkey, &cert)) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    /* Sign with no caller digest: CMS takes the key's mandatory digest, the
     * composite's prehash PH (cms-composite-sigs-05 Table 1). The propq is
     * left NULL, not "provider=hybrid": CMS applies it to *every* fetch,
     * including the generic digest, which the composite provider does not
     * implement. The signature is bound to the composite key via `pkey`, so
     * it stays composite regardless. */
    in = BIO_new_mem_buf(content, sizeof(content) - 1);
    cms = CMS_sign_ex(NULL, NULL, NULL, in, flags, libctx, NULL);
    if (cms == NULL
            || (si = CMS_add1_signer(cms, cert, pkey, NULL,
                                     signer_flags)) == NULL
            || CMS_final(cms, in, NULL, flags) <= 0)
        goto fail;
    /* digestAlgorithm MUST be PH; with signed attributes the messageDigest
     * attribute MUST be PH(content), 64 bytes for SHAKE256 (sec. 3.3). */
    /* -noattr: the SignerInfo signature is Composite-Sign over the content
     * itself (sec. 3.3), however CMS computed it (here via external prehash).
     * Check it through the message route, not through CMS. */
    if (noattr && !signs_content(libctx, pkey, si, content,
                                 sizeof(content) - 1)) {
        printf("FAIL (-noattr signature does not verify over the content)\n");
        failed++;
        goto done;
    }
    if (!digest_is_ph(libctx, pkey, si, noattr, content, sizeof(content) - 1)) {
        printf("FAIL (digestAlgorithm / messageDigest is not the Table 1 "
               "digest)\n");
        failed++;
        goto done;
    }
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
 * Direct round-trip of the composite provider's message-signature API (issue
 * #109): streaming sign_message init/update/final, then verify_message init/update
 * (signature delivered via OSSL_SIGNATURE_PARAM_SIGNATURE)/final, plus a tamper
 * check. This is the machinery OpenSSL's md-less CMS content-signing drives, and it
 * exercises the provider's new entry points regardless of whether the base
 * library's CMS layer is new enough to use them (so it gives real coverage on
 * 3.5.x too). 3.4+ only, so compiled out where the API does not exist.
 */
#ifdef OSSL_SIGNATURE_PARAM_SIGNATURE
static void check_message_api(OSSL_LIB_CTX *libctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, alg, "provider=hybrid");
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *sc = NULL, *vc = NULL, *vc2 = NULL;
    unsigned char *sbuf = NULL;
    size_t slen = 0;
    const unsigned char msg[] = "composite message-signature streaming round-trip";
    const unsigned char bad[] = "Composite message-signature streaming round-trip";
    const size_t half = 20;
    OSSL_PARAM vp[2];

    tests++;
    printf("  %-28s message-API sign/verify (stream) ... ", alg);
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
#endif /* OSSL_SIGNATURE_PARAM_SIGNATURE */

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    int have_oqs;
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (hybrid_test_load(ctx, "default") == NULL
            || hybrid_test_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    have_oqs = hybrid_test_load(ctx, "oqsprovider") != NULL;
    ERR_clear_error();

    printf("composite signatures in CMS SignedData\n");
    printf("=======================================\n");
    /* Drive the whole composite inventory from the master table. The standardized
     * (ML-DSA) combos run against the default provider; the experimental ones need
     * oqsprovider and are skipped without it. Each combo additionally self-skips if
     * its components are unavailable (e.g. the standardized tier below 3.5). */
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const COMPOSITE_SIG_INFO *info = &composite_sig_table[i];

        if (info->tier == COMPOSITE_TIER_STANDARD || have_oqs) {
            check(ctx, info->name, 0);   /* signed attrs */
            check(ctx, info->name, 1);   /* CMS_NOATTR */
            check_wrong_digest(ctx, info, 0);
            check_wrong_digest(ctx, info, 1);
#ifdef OSSL_SIGNATURE_PARAM_SIGNATURE
            check_message_api(ctx, info->name);            /* issue #109 API */
#endif
        }
    }
    if (!have_oqs)
        printf("  (oqsprovider absent -- skipping experimental composite "
               "combos)\n");

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
