/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * End-to-end PQ-hybrid / composite signature certificate over TLS 1.3 (in-process,
 * memory BIOs).
 *
 * For each signature whose components are available, generate a key and a
 * self-signed certificate signed with that key, run a TLS 1.3 handshake where the
 * server authenticates with that certificate and the client verifies it, and
 * assert that (a) the handshake completes, (b) the client accepts the chain
 * (X509_V_OK), and (c) the CertificateVerify was made with that signature
 * algorithm (SSL_get_peer_signature_type_nid == the algorithm's NID).
 *
 * The test is provider-parametrized and covers both families with one code path:
 *   - hybrid (`provider=hybrid`): the ML-DSA hybrids, oqsprovider not needed.
 *   - composite (`provider=hybrid`): the LAMPS composite ML-DSA combos, only
 *     when the composite provider is built (-DHYBRID_COMPOSITE) and loadable.
 * Exercises the whole chain: the TLS-SIGALG capability (hybrid_caps.c /
 * composite_caps.c), the signature AlgorithmIdentifier, and the OID registration
 * at provider init. Each entry self-skips when its provider or components are
 * unavailable (e.g. composite off, or no ML-DSA on 3.4).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/err.h>

static int tests, passed, failed, skipped;

static const struct { const char *propq; const char *alg; } algs[] = {
    { "provider=hybrid",    "p256_mldsa44" },
    { "provider=hybrid",    "rsa3072_mldsa44" },
    { "provider=hybrid",    "p384_mldsa65" },
    { "provider=hybrid",    "p521_mldsa87" },
    /* Composite (LAMPS) — self-skip unless the composite provider is loaded. */
    { "provider=hybrid", "mldsa44_ecdsa_p256" },
    { "provider=hybrid", "mldsa65_rsa3072_pss" },
    { "provider=hybrid", "mldsa65_ed25519" },
    { "provider=hybrid", "mldsa87_ecdsa_p384" },
    { "provider=hybrid", "mldsa87_ed448" },
};

/* Generate a keypair + self-signed cert signed with that key (one-shot). */
static int make_cert(OSSL_LIB_CTX *libctx, const char *propq, const char *alg,
                     EVP_PKEY **pkey_out, X509 **cert_out)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, alg, propq);
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
                                    (unsigned char *)"hybrid-cert", -1, -1, 0)
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

/* Drive the client/server SSL objects to completion over a shared memory-BIO
 * pair. Returns 1 on a completed handshake. */
static int pump(SSL *server, SSL *client)
{
    int i;

    for (i = 0; i < 50; i++) {
        int cs = SSL_do_handshake(client);
        int ss = SSL_do_handshake(server);

        if (cs == 1 && ss == 1)
            return 1;
        if (cs <= 0 && SSL_get_error(client, cs) != SSL_ERROR_WANT_READ
                && SSL_get_error(client, cs) != SSL_ERROR_WANT_WRITE)
            return 0;
        if (ss <= 0 && SSL_get_error(server, ss) != SSL_ERROR_WANT_READ
                && SSL_get_error(server, ss) != SSL_ERROR_WANT_WRITE)
            return 0;
    }
    return 0;
}

static void check(OSSL_LIB_CTX *libctx, const char *propq, const char *alg)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *s = NULL, *c = NULL;
    BIO *cbio = NULL, *sbio = NULL;
    int nid = 0, want_nid = OBJ_sn2nid(alg);

    tests++;
    printf("  %-22s cert over TLS 1.3 ... ", alg);
    fflush(stdout);

    if (!make_cert(libctx, propq, alg, &pkey, &cert)) {
        printf("SKIP (provider/components unavailable)\n");
        skipped++; tests--;
        ERR_clear_error();
        goto done;
    }

    sctx = SSL_CTX_new_ex(libctx, NULL, TLS_server_method());
    cctx = SSL_CTX_new_ex(libctx, NULL, TLS_client_method());
    if (sctx == NULL || cctx == NULL
            || SSL_CTX_use_certificate(sctx, cert) <= 0
            || SSL_CTX_use_PrivateKey(sctx, pkey) <= 0
            || !SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION)
            || !SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION))
        goto fail;
    /* client trusts the self-signed server cert and requires verification */
    if (X509_STORE_add_cert(SSL_CTX_get_cert_store(cctx), cert) <= 0)
        goto fail;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_PEER, NULL);

    s = SSL_new(sctx);
    c = SSL_new(cctx);
    if (s == NULL || c == NULL)
        goto fail;
    SSL_set_accept_state(s);
    SSL_set_connect_state(c);
    if (!BIO_new_bio_pair(&cbio, 0, &sbio, 0))
        goto fail;
    SSL_set_bio(c, cbio, cbio);     /* takes ownership */
    SSL_set_bio(s, sbio, sbio);
    cbio = sbio = NULL;

    if (!pump(s, c))
        goto fail;
    /* handshake done: client must have verified the chain, and the server's
     * CertificateVerify must have used the hybrid signature algorithm. */
    if (SSL_get_verify_result(c) != X509_V_OK)
        goto fail;
    if (!SSL_get_peer_signature_type_nid(c, &nid) || nid != want_nid)
        goto fail;

    printf("PASS (peer sig=%s)\n", OBJ_nid2sn(nid));
    passed++;
    goto done;
fail:
    printf("FAIL\n");
    ERR_print_errors_fp(stdout);
    failed++;
done:
    BIO_free(cbio);
    BIO_free(sbio);
    SSL_free(s);
    SSL_free(c);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
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
    /* Composite is a capability of the hybrid provider (build-flag-gated); its
     * entries self-skip when hybrid was built without -DHYBRID_COMPOSITE. */

    printf("PQ-hybrid / composite signature certificates over TLS 1.3\n");
    printf("========================================================\n");
    for (i = 0; i < sizeof(algs) / sizeof(algs[0]); i++)
        check(ctx, algs[i].propq, algs[i].alg);
    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
