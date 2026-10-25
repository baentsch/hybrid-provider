/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Private component-context test (design.md: Private component context).
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
#include <openssl/core_names.h>
#include "hybrid_prov.h"      /* HYBRID_ALG_NAME_MAX (advertised-name buffer) */

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

/*
 * Runtime derivation of the group set (issue #78 follow-up). Rather than
 * hand-maintain the list, enumerate oqsprovider's live TLS-GROUP advertisement
 * and keep exactly the groups that exercise the private component context.
 */
#define HYBRID_MAX_GROUPS 128
static struct { char name[HYBRID_ALG_NAME_MAX]; int min_tls; } adv[HYBRID_MAX_GROUPS];
static int nadv;

/* Capability callback: record each advertised (group name -> min TLS version).
 * oqsprovider encodes "enable_tls: false" (e.g. BIKE-L1) as min_tls == -1. */
static int collect_groups(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *pn =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
    const OSSL_PARAM *pm =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_MIN_TLS);
    const char *name = NULL;
    int mn = 0;

    (void)arg;
    if (pn != NULL && OSSL_PARAM_get_utf8_string_ptr(pn, &name)
            && nadv < HYBRID_MAX_GROUPS) {
        if (pm != NULL)
            OSSL_PARAM_get_int(pm, &mn);
        snprintf(adv[nadv].name, sizeof(adv[nadv].name), "%s", name);
        adv[nadv].min_tls = mn;
        nadv++;
    }
    return 1;
}

/* True iff the group name fetches as a KEM served by the hybrid provider. */
static int resolves_to_hybrid(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_KEM *k = EVP_KEM_fetch(ctx, name, NULL);
    int yes = k != NULL
        && strcmp(OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(k)), "hybrid") == 0;

    EVP_KEM_free(k);
    ERR_clear_error();
    return yes;
}

/* True iff a keypair for the group can actually be generated in ctx. In a
 * default-only component context this succeeds for ML-KEM hybrids (default
 * serves ML-KEM) but fails for Frodo/BIKE/HQC (PQ base only in oqsprovider). */
static int can_keygen(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    EVP_PKEY *k = NULL;
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0
        && EVP_PKEY_generate(c, &k) > 0;

    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

int main(void)
{
    OSSL_LIB_CTX *app = NULL, *oqs = NULL, *defonly = NULL;
    OSSL_PROVIDER *od = NULL, *oq = NULL;
    /*
     * The group set is derived at runtime from oqsprovider's own TLS-GROUP
     * advertisement (issue #78) — NOT hand-maintained. A group qualifies when
     * all three hold:
     *   1. oqsprovider advertises it with min_tls != -1, i.e. it is actually
     *      TLS-negotiable. oqsprovider encodes "enable_tls: false" as -1, so
     *      BIKE-L1 (p256_bikel1, x25519_bikel1) drops out here automatically —
     *      no hand-coded exclusion. (Its KEM interop is covered by hybrid_oqs_test.)
     *   2. it resolves to the hybrid provider in the app ctx (a group we own).
     *   3. its keypair cannot be generated from the default provider alone
     *      (checked in `defonly` below) — this keeps the ML-KEM hybrids out
     *      (default serves ML-KEM, so they would NOT exercise the private
     *      component context) while keeping Frodo/BIKE/HQC in.
     * The result follows an upstream rename/addition/re-point by itself. It is
     * NOT a probe that drops groups which fail to handshake: membership is
     * decided by the advertisement, so an advertised-usable group that fails to
     * negotiate stays in the set and fails the test — the regression signal the
     * old hand-curated contract existed to catch is preserved.
     */
    const char *groups[HYBRID_MAX_GROUPS];
    size_t i, n = 0;

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

    /* Enumerate oqsprovider's advertised TLS groups (name + min TLS version). */
    OSSL_PROVIDER_get_capabilities(oq, "TLS-GROUP", collect_groups, NULL);

    /*
     * Default-only component context, built programmatically (NO config file):
     * with no "component-providers" set, the hybrid provider uses its parent
     * libctx -- default only -- for components. Built programmatically rather
     * than from a second cnf because loading a second hybrid-provider config in
     * this process trips OpenSSL's "recursive section reference" (the hybrid
     * init re-enters provider-config parsing to build its component ctx); `app`
     * is the one config-driven hybrid load. A group whose keypair generates here
     * is served by the default provider and therefore does not exercise the
     * private component context, so it is excluded.
     */
    defonly = OSSL_LIB_CTX_new();
    if (defonly == NULL
            || OSSL_PROVIDER_load(defonly, "default") == NULL
            || OSSL_PROVIDER_load(defonly, "hybrid") == NULL) {
        fprintf(stderr, "default-only probe context setup failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    for (i = 0; i < (size_t)nadv; i++) {
        if (adv[i].min_tls == -1)                   /* not TLS-enabled (BIKE-L1) */
            continue;
        if (!resolves_to_hybrid(app, adv[i].name))  /* not a hybrid-owned group */
            continue;
        if (can_keygen(defonly, adv[i].name))       /* default serves it (ML-KEM) */
            continue;
        groups[n++] = adv[i].name;                  /* adv[] outlives this scope */
    }
    OSSL_LIB_CTX_free(defonly);
    defonly = NULL;

    /* A non-empty derived set is part of the contract: an empty set would make
     * every assertion below vacuous and hide a broken advertisement or probe. */
    TEST_START("derived a non-empty private-ctx group set from oqsprovider");
    if (n > 0)
        TEST_PASS();
    else
        TEST_FAIL("no private-ctx hybrid groups derived");

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
