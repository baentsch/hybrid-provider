/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private component-context test (redesign.md M7 / option 1).
 *
 * The hybrid provider is configured with
 *     component-providers = default oqsprovider
 * so it sources its PQ base (FrodoKEM/BIKE/HQC, available only in oqsprovider)
 * from its OWN library context. The application context therefore loads only
 * default + hybrid: oqsprovider's competing hybrid TLS groups never appear
 * there, so the Frodo/BIKE/HQC hybrid groups resolve unambiguously to the
 * hybrid provider and can be used over TLS with a plain (non-mandatory) query.
 *
 * We verify (a) the group resolves to the hybrid provider even with no property
 * query, and (b) a full TLS 1.3 handshake against pure oqsprovider succeeds
 * with matching keying material. Skipped when oqsprovider is unavailable.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

static int tests, passed, failed;
#define TEST_START(n) do { tests++; printf("  %s ... ", n); fflush(stdout); } while (0)
#define TEST_PASS()   do { passed++; printf("PASS\n"); } while (0)
#define TEST_FAIL(m)  do { failed++; printf("FAIL: %s\n", m); ERR_print_errors_fp(stdout); } while (0)

static const char *module_dir;

/* App context: default + hybrid only; hybrid sources components from a private
 * "default oqsprovider" context. */
static OSSL_LIB_CTX *make_app_ctx(void)
{
    char cnf[] = "/tmp/hybrid_compctx.XXXXXX";
    int fd = mkstemp(cnf);
    OSSL_LIB_CTX *libctx = NULL;
    FILE *f;

    if (fd < 0)
        return NULL;
    close(fd);
    if ((f = fopen(cnf, "w")) == NULL)
        goto end;
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
end:
    remove(cnf);
    return libctx;
}

static int make_self_signed(OSSL_LIB_CTX *libctx, EVP_PKEY **pk, X509 **crt)
{
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256");
    X509 *cert = NULL;
    X509_NAME *nm;

    if (pkey == NULL || (cert = X509_new_ex(libctx, NULL)) == NULL)
        goto err;
    if (!X509_set_version(cert, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL
            || !X509_set_pubkey(cert, pkey))
        goto err;
    nm = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
            (const unsigned char *)"compctx", -1, -1, 0)
            || !X509_set_issuer_name(cert, nm)
            || !X509_sign(cert, pkey, EVP_sha256()))
        goto err;
    *pk = pkey; *crt = cert;
    return 1;
err:
    EVP_PKEY_free(pkey); X509_free(cert);
    return 0;
}

/* TLS 1.3 handshake for one group; server in sctxlib, client in cctxlib. */
static int handshake(OSSL_LIB_CTX *slib, const char *sprop,
                     OSSL_LIB_CTX *clib, const char *cprop, const char *group)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *srv = NULL, *cli = NULL;
    BIO *c2s = NULL, *s2c = NULL;
    EVP_PKEY *pkey = NULL; X509 *cert = NULL;
    unsigned char skm[32], ckm[32];
    static const char label[] = "compctx";
    int i, ret = 0;

    if (!make_self_signed(slib, &pkey, &cert))
        goto end;
    sctx = SSL_CTX_new_ex(slib, sprop, TLS_server_method());
    cctx = SSL_CTX_new_ex(clib, cprop, TLS_client_method());
    if (sctx == NULL || cctx == NULL
            || SSL_CTX_use_certificate(sctx, cert) <= 0
            || SSL_CTX_use_PrivateKey(sctx, pkey) <= 0
            || !SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(sctx, TLS1_3_VERSION)
            || !SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION)
            || !SSL_CTX_set1_groups_list(sctx, group)
            || !SSL_CTX_set1_groups_list(cctx, group))
        goto end;
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    srv = SSL_new(sctx); cli = SSL_new(cctx);
    if (srv == NULL || cli == NULL)
        goto end;
    SSL_set_accept_state(srv); SSL_set_connect_state(cli);
    c2s = BIO_new(BIO_s_mem()); s2c = BIO_new(BIO_s_mem());
    if (c2s == NULL || s2c == NULL || !BIO_up_ref(c2s) || !BIO_up_ref(s2c))
        goto end;
    SSL_set_bio(cli, s2c, c2s);
    SSL_set_bio(srv, c2s, s2c);

    for (i = 0; i < 50; i++) {
        int cf = SSL_is_init_finished(cli), sf = SSL_is_init_finished(srv);
        if (cf && sf) break;
        if (!cf) { int r = SSL_do_handshake(cli), e = SSL_get_error(cli, r);
            if (r <= 0 && e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) goto end; }
        if (!sf) { int r = SSL_do_handshake(srv), e = SSL_get_error(srv, r);
            if (r <= 0 && e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) goto end; }
    }
    if (!SSL_is_init_finished(cli) || !SSL_is_init_finished(srv))
        goto end;
    if (SSL_export_keying_material(srv, skm, sizeof(skm), label, sizeof(label)-1, NULL, 0, 0) != 1
            || SSL_export_keying_material(cli, ckm, sizeof(ckm), label, sizeof(label)-1, NULL, 0, 0) != 1
            || memcmp(skm, ckm, sizeof(skm)) != 0)
        goto end;
    ret = 1;
end:
    SSL_free(srv); SSL_free(cli);
    SSL_CTX_free(sctx); SSL_CTX_free(cctx);
    EVP_PKEY_free(pkey); X509_free(cert);
    return ret;
}

int main(void)
{
    OSSL_LIB_CTX *app = NULL, *oqs = NULL;
    OSSL_PROVIDER *od = NULL, *oq = NULL;
    /*
     * Representative Frodo/BIKE/HQC groups (PQ base only in oqsprovider).
     * BIKE-L1 (p256_bikel1 etc.) is intentionally omitted: the oqsprovider peer
     * does not negotiate BIKE-L1 groups over TLS in this build (its own
     * client/server report "no suitable groups" / "no suitable key share"),
     * while BIKE-L3/L5 do. BIKE-L1 KEM interop itself is covered in
     * hybrid_oqs_test.
     */
    static const char *groups[] = {
        "p256_frodo640aes", "x25519_frodo640aes", "p384_frodo976aes",
        "x448_bikel3", "p521_bikel5",
        "p256_hqc1", "p384_hqc3", "p521_hqc5",
    };
    size_t i, n = sizeof(groups) / sizeof(groups[0]);

    module_dir = getenv("OPENSSL_MODULES");
    if (module_dir == NULL)
        module_dir = ".";

    printf("hybrid private-component-context test (Frodo/BIKE/HQC over TLS)\n");
    printf("=============================================================\n");

    app = make_app_ctx();
    oqs = OSSL_LIB_CTX_new();
    if (app == NULL || oqs == NULL) {
        fprintf(stderr, "context setup failed\n");
        return 1;
    }
    if ((od = OSSL_PROVIDER_load(oqs, "default")) == NULL
            || (oq = OSSL_PROVIDER_load(oqs, "oqsprovider")) == NULL) {
        printf("oqsprovider unavailable -- SKIPPING\n");
        ERR_clear_error();
        return 0;
    }

    /* The hybrid provider must have loaded oqsprovider into its private ctx; if
     * not (module not found), Frodo keygen fails and the tests below report it. */
    for (i = 0; i < n; i++) {
        char t[160];

        /* (a) group resolves to hybrid in the app ctx with NO property query */
        snprintf(t, sizeof(t), "%s: resolves to hybrid (no propq, no collision)",
                 groups[i]);
        TEST_START(t);
        {
            EVP_KEM *k = EVP_KEM_fetch(app, groups[i], NULL);
            const char *p = k ? OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(k))
                              : "(none)";
            if (k != NULL && strcmp(p, "hybrid") == 0)
                TEST_PASS();
            else
                TEST_FAIL("did not resolve to hybrid");
            EVP_KEM_free(k);
            ERR_clear_error();
        }

        /* (b) TLS handshake: hybrid app ctx <-> pure oqsprovider */
        snprintf(t, sizeof(t), "%s: hybrid server <-> oqs client (TLS)", groups[i]);
        TEST_START(t);
        if (handshake(app, NULL, oqs, NULL, groups[i]))
            TEST_PASS();
        else
            TEST_FAIL("handshake / keying-material mismatch");

        snprintf(t, sizeof(t), "%s: oqs server <-> hybrid client (TLS)", groups[i]);
        TEST_START(t);
        if (handshake(oqs, NULL, app, NULL, groups[i]))
            TEST_PASS();
        else
            TEST_FAIL("handshake / keying-material mismatch");
    }

    printf("\nResults: %d/%d passed", passed, tests);
    if (failed) printf(" (%d FAILED)", failed);
    printf("\n");

    OSSL_PROVIDER_unload(oq);
    OSSL_PROVIDER_unload(od);
    OSSL_LIB_CTX_free(oqs);
    OSSL_LIB_CTX_free(app);
    return failed == 0 ? 0 : 1;
}
