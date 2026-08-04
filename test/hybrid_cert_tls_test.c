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
 * APPLICATION CONTEXT — the app libctx loads only `default` + `hybrid`; the
 * hybrid provider sources its PQ base from a PRIVATE "default oqsprovider"
 * component context (component-providers/component-path). This is deliberate and
 * is what makes the research-signature hybrids testable here at all:
 *   - ML-DSA hybrids and the LAMPS composite combos resolve from the default
 *     provider directly.
 *   - Falcon/MAYO/UOV/SNOVA/MQOM2 hybrids need an oqs-sourced PQ base; the hybrid
 *     provider pulls it from its private component context, so oqsprovider does
 *     NOT enter the app libctx.
 *
 * Why not co-load oqsprovider in the app libctx (issue #14): the hybrid provider
 * and oqsprovider register the *same* hybrid keytype names. When both are in one
 * libctx, libssl's add_provider_sigalgs() keeps a provider's TLS-SIGALG
 * advertisement only if the unqualified EVP_KEYMGMT_fetch(keytype) resolves back
 * to that same provider (ssl/t1_lib.c) — and for the shared names that fetch
 * resolves to oqsprovider, so OUR advertisements are silently discarded. Since
 * oqsprovider advertises the OV_Ip variants but not OV_Is, co-loading makes
 * exactly the OV_Is certificates fail cert-type classification ("unknown
 * certificate type"), while OV_Ip/Falcon/MAYO survive only because oqsprovider
 * advertises them. Keeping oqsprovider in the hybrid provider's own libctx makes
 * hybrid the sole advertiser in the app libctx, so every hybrid — OV_Is included
 * — classifies and completes cert authentication. See issue #14.
 *
 * Exercises the whole chain for every row with a TLS code point: the TLS-SIGALG
 * capability (hybrid_caps.c / composite_caps.c), the signature AlgorithmIdentifier,
 * and the OID registration at provider init. Rows self-skip only when their
 * components are genuinely absent (composite off, no ML-DSA on 3.4, or oqsprovider
 * not on the module path for the research bases).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "hybrid_prov.h"       /* hybrid_sig_table — drive the list from the master */
#include "composite_prov.h"    /* composite_sig_table (data only; self-skips if the
                                * provider was built without composite) */

static int tests, passed, failed, skipped;

/*
 * App libctx: default + hybrid only, with the hybrid provider configured to
 * source its PQ components from a private "default oqsprovider" context. This
 * keeps oqsprovider out of the app libctx (see the file header / issue #14) so
 * the hybrid provider is the sole TLS-SIGALG advertiser for the shared hybrid
 * names. module_dir defaults to OPENSSL_MODULES (where ctest points it).
 */
static OSSL_LIB_CTX *make_app_ctx(void)
{
    const char *module_dir = getenv("OPENSSL_MODULES");
    char cnf[] = "/tmp/hybrid_cert_tls.XXXXXX";
    OSSL_LIB_CTX *libctx = NULL;
    int fd;
    FILE *f;

    if (module_dir == NULL)
        module_dir = ".";
    if ((fd = mkstemp(cnf)) < 0)
        return NULL;
    close(fd);
    if ((f = fopen(cnf, "w")) == NULL) {
        remove(cnf);
        return NULL;
    }
    fprintf(f,
            "openssl_conf = c\n"
            "[c]\nproviders = p\n"
            "[p]\ndefault = d\nhybrid = h\n"
            "[d]\nactivate = 1\n"
            "[h]\nmodule = %s/hybrid.so\nactivate = 1\n"
            "component-providers = default oqsprovider\n"
            "component-path = %s\n",
            module_dir, module_dir);
    fclose(f);

    if ((libctx = OSSL_LIB_CTX_new()) != NULL
            && !OSSL_LIB_CTX_load_config(libctx, cnf)) {
        OSSL_LIB_CTX_free(libctx);
        libctx = NULL;
    }
    remove(cnf);
    return libctx;
}

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
    OSSL_LIB_CTX *ctx = make_app_ctx();
    size_t i;

    if (ctx == NULL) {
        fprintf(stderr, "failed to build app libctx (default + hybrid)\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    /*
     * The app libctx holds default + hybrid only; the hybrid provider sources
     * its PQ base from a private "default oqsprovider" component context (see
     * make_app_ctx() and the file header). Keeping oqsprovider out of the app
     * libctx makes hybrid the sole TLS-SIGALG advertiser for the shared hybrid
     * names, so every hybrid — OV_Is included — classifies as a TLS cert
     * (issue #14). Rows still self-skip when their base is genuinely absent
     * (oqsprovider not on the module path, or composite built out).
     */

    printf("PQ-hybrid / composite signature certificates over TLS 1.3\n");
    printf("========================================================\n");
    /*
     * Drive the list from the master tables rather than a hand-kept static list:
     * every hybrid and composite signature that carries a TLS SignatureScheme
     * code point is exercised.
     */
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (hybrid_sig_table[i].tls_codepoint != 0)
            check(ctx, "provider=hybrid", hybrid_sig_table[i].hybrid_name);
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        if (composite_sig_table[i].tls_codepoint != 0)
            check(ctx, "provider=hybrid", composite_sig_table[i].name);
    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
