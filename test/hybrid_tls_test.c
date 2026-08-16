/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * In-process TLS 1.3 handshake interop test.
 *
 * Drives a full handshake between two independent OSSL_LIB_CTXs connected by
 * shared memory BIOs:
 *   - one peer sources the hybrid MLX KEM group from the hybrid provider
 *     (selected via the optional property query "?provider=hybrid"),
 *   - the other from the default provider's built-in MLX implementation.
 *
 * The handshake completing AND both peers deriving identical exported keying
 * material proves the hybrid provider's KEM is wire-compatible with the
 * default provider's, end to end.
 *
 * Only the three MLX hybrids with standardized TLS codepoints are covered;
 * X448MLKEM1024 has no TLS group codepoint and is skipped (reported below).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "hybrid_prov.h"   /* HYBRID_KEM_ALG_COUNT, HYBRID_ALG_NAME_MAX */

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

#define TEST_START(name) do { \
    test_count++; \
    printf("  TEST %d: %s ... ", test_count, name); \
    fflush(stdout); \
} while (0)

#define TEST_PASS() do { pass_count++; printf("PASS\n"); } while (0)

#define TEST_FAIL(msg) do { \
    fail_count++; \
    printf("FAIL: %s\n", msg); \
    ERR_print_errors_fp(stderr); \
} while (0)

/* Standardized TLS codepoints (draft-ietf-tls-ecdhe-mlkem). */
static const struct {
    const char *name;
    int codepoint;
} GROUPS[] = {
    { "X25519MLKEM768",     0x11EC },
    { "SecP256r1MLKEM768",  0x11EB },
    { "SecP384r1MLKEM1024", 0x11ED },
};
#define N_GROUPS (sizeof(GROUPS) / sizeof(GROUPS[0]))

/*
 * Records the TLS-GROUP code points the hybrid provider advertises, so the
 * test can assert advertised == wire: the value the provider hands to libssl
 * (below) must equal the value that comes back from SSL_get_negotiated_group()
 * after a real handshake (in run_handshake). Closing that loop is acceptance
 * item 1 of issue #45.
 */
/* One slot per hybrid KEM (the provider advertises at most one group per
 * master-list row); name buffer per the shared bound. */
static struct { char name[HYBRID_ALG_NAME_MAX]; unsigned int id; }
    g_adv[HYBRID_KEM_ALG_COUNT];
static int g_nadv;

static int collect_group(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *pn =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
    const OSSL_PARAM *pi =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_ID);
    const char *name = NULL;
    unsigned int id = 0;

    (void)arg;
    if (pn != NULL && pi != NULL && g_nadv < (int)HYBRID_KEM_ALG_COUNT
        && OSSL_PARAM_get_utf8_string_ptr(pn, &name)
        && OSSL_PARAM_get_uint(pi, &id)) {
        OPENSSL_strlcpy(g_adv[g_nadv].name, name, sizeof(g_adv[0].name));
        g_adv[g_nadv].id = id;
        g_nadv++;
    }
    return 1;
}

/* Code point the hybrid provider advertises for `name`, or -1 if not advertised. */
static long advertised_codepoint(const char *name)
{
    int i;

    for (i = 0; i < g_nadv; i++)
        if (strcmp(g_adv[i].name, name) == 0)
            return (long)g_adv[i].id;
    return -1;
}

/*
 * Confirm that fetching the group's KEM with the given property query resolves
 * to the expected provider, so we know the handshake exercises the intended
 * implementation rather than silently falling through to the default provider.
 */
static int kem_provider_is(OSSL_LIB_CTX *libctx, const char *propq,
                           const char *alg, const char *want_provider)
{
    EVP_KEM *kem = EVP_KEM_fetch(libctx, alg, propq);
    const char *got = NULL;
    int ok;

    if (kem != NULL)
        got = OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(kem));
    ok = (got != NULL && strcmp(got, want_provider) == 0);
    if (!ok)
        fprintf(stderr, "[%s via '%s' -> %s, wanted %s] ",
                alg, propq ? propq : "(null)", got ? got : "(none)",
                want_provider);
    EVP_KEM_free(kem);
    ERR_clear_error();
    return ok;
}

/* Generate an ephemeral EC P-256 self-signed cert in the given libctx. */
static int make_self_signed(OSSL_LIB_CTX *libctx, EVP_PKEY **pkey_out,
                            X509 **cert_out)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    int ok = 0;

    pkey = EVP_PKEY_Q_keygen(libctx, NULL, "EC", "P-256");
    if (pkey == NULL)
        goto err;
    if ((cert = X509_new_ex(libctx, NULL)) == NULL)
        goto err;
    if (!X509_set_version(cert, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL
            || !X509_set_pubkey(cert, pkey))
        goto err;
    name = X509_get_subject_name(cert);
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"hybrid-test",
                                    -1, -1, 0)
            || !X509_set_issuer_name(cert, name))
        goto err;
    if (!X509_sign(cert, pkey, EVP_sha256()))
        goto err;

    *pkey_out = pkey;
    *cert_out = cert;
    return 1;
err:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ok;
}

/*
 * Run a TLS 1.3 handshake for one group in one direction.
 *   srv_libctx/srv_propq  — libctx + property query for the server
 *   cli_libctx/cli_propq  — libctx + property query for the client
 * Returns 1 if the handshake completes, the negotiated group matches the
 * expected codepoint, and exported keying material matches on both ends.
 */
static int run_handshake(OSSL_LIB_CTX *srv_libctx, const char *srv_propq,
                         OSSL_LIB_CTX *cli_libctx, const char *cli_propq,
                         const char *group, int expect_codepoint)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *c2s = NULL, *s2c = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    unsigned char skm[32], ckm[32];
    static const char label[] = "hybrid interop test";
    int i, ret = 0;
    const char *stage = "make_self_signed";

    if (!make_self_signed(srv_libctx, &pkey, &cert))
        goto end;

    stage = "SSL_CTX_new_ex";
    sctx = SSL_CTX_new_ex(srv_libctx, srv_propq, TLS_server_method());
    cctx = SSL_CTX_new_ex(cli_libctx, cli_propq, TLS_client_method());
    if (sctx == NULL || cctx == NULL)
        goto end;

    stage = "use_certificate/key";
    if (SSL_CTX_use_certificate(sctx, cert) <= 0
            || SSL_CTX_use_PrivateKey(sctx, pkey) <= 0)
        goto end;

    if (!SSL_CTX_set_min_proto_version(sctx, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(sctx, TLS1_3_VERSION)
            || !SSL_CTX_set_min_proto_version(cctx, TLS1_3_VERSION)
            || !SSL_CTX_set_max_proto_version(cctx, TLS1_3_VERSION))
        goto end;

    /* Restrict both ends to the single group under test. */
    stage = "set1_groups_list";
    if (!SSL_CTX_set1_groups_list(sctx, group)
            || !SSL_CTX_set1_groups_list(cctx, group))
        goto end;

    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);

    server = SSL_new(sctx);
    client = SSL_new(cctx);
    if (server == NULL || client == NULL)
        goto end;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);

    /* Shared memory BIOs: data written by one end is read by the other. */
    c2s = BIO_new(BIO_s_mem());
    s2c = BIO_new(BIO_s_mem());
    if (c2s == NULL || s2c == NULL)
        goto end;
    if (!BIO_up_ref(c2s) || !BIO_up_ref(s2c))
        goto end;
    SSL_set_bio(client, s2c, c2s); /* client reads s2c, writes c2s */
    SSL_set_bio(server, c2s, s2c); /* server reads c2s, writes s2c */

    for (i = 0; i < 50; i++) {
        int cf = SSL_is_init_finished(client);
        int sf = SSL_is_init_finished(server);

        if (cf && sf)
            break;
        if (!cf) {
            int r = SSL_do_handshake(client);
            int e = SSL_get_error(client, r);
            if (r <= 0 && e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                goto end;
        }
        if (!sf) {
            int r = SSL_do_handshake(server);
            int e = SSL_get_error(server, r);
            if (r <= 0 && e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
                goto end;
        }
    }

    stage = "handshake_complete";
    if (!SSL_is_init_finished(client) || !SSL_is_init_finished(server))
        goto end;

    /*
     * SSL_get_negotiated_group() returns TLSEXT_nid_unknown (0x1000000) OR'd
     * with the wire codepoint for groups that have no OpenSSL NID, as these
     * hybrids do. Both peers must agree and the low 16 bits must be the
     * expected codepoint.
     */
    stage = "negotiated_group";
    if ((SSL_get_negotiated_group(server) & 0xFFFF) != expect_codepoint
            || (SSL_get_negotiated_group(client) & 0xFFFF) != expect_codepoint)
        goto end;

    if (SSL_export_keying_material(server, skm, sizeof(skm),
                                   label, sizeof(label) - 1, NULL, 0, 0) != 1
            || SSL_export_keying_material(client, ckm, sizeof(ckm),
                                   label, sizeof(label) - 1, NULL, 0, 0) != 1)
        goto end;

    if (memcmp(skm, ckm, sizeof(skm)) != 0)
        goto end;

    ret = 1;
    stage = "ok";
end:
    if (ret != 1)
        fprintf(stderr, "[stage=%s] ", stage);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return ret;
}

int main(void)
{
    OSSL_LIB_CTX *dflt_ctx = NULL, *hyb_ctx = NULL;
    OSSL_PROVIDER *d1 = NULL, *d2 = NULL, *hyb = NULL;
    size_t g;
    int rc = 1;

    printf("Hybrid provider TLS 1.3 handshake interop tests\n");
    printf("================================================\n");

    /* Client-side context: default provider only. */
    dflt_ctx = OSSL_LIB_CTX_new();
    /* Server-side context: hybrid (for the group) + default (for components). */
    hyb_ctx = OSSL_LIB_CTX_new();
    if (dflt_ctx == NULL || hyb_ctx == NULL)
        goto end;

    if ((d1 = OSSL_PROVIDER_load(dflt_ctx, "default")) == NULL) {
        fprintf(stderr, "cannot load default provider\n");
        goto end;
    }
    if ((d2 = OSSL_PROVIDER_load(hyb_ctx, "default")) == NULL
            || (hyb = OSSL_PROVIDER_load(hyb_ctx, "hybrid")) == NULL) {
        fprintf(stderr, "cannot load hybrid provider "
                        "(set OPENSSL_MODULES to the build dir)\n");
        goto end;
    }

    /*
     * Routing checks: "?provider=hybrid" must select the hybrid provider for
     * the (name-colliding) group, while a plain fetch in the default-only
     * context selects the default provider. This proves the handshakes below
     * exercise the hybrid implementation, not a silent default fallback.
     */
    for (g = 0; g < N_GROUPS; g++) {
        char t[128];

        snprintf(t, sizeof(t), "%s: '?provider=hybrid' routes to hybrid",
                 GROUPS[g].name);
        TEST_START(t);
        if (kem_provider_is(hyb_ctx, "?provider=hybrid", GROUPS[g].name,
                            "hybrid"))
            TEST_PASS();
        else
            TEST_FAIL("group did not resolve to hybrid provider");

        snprintf(t, sizeof(t), "%s: default context routes to default",
                 GROUPS[g].name);
        TEST_START(t);
        if (kem_provider_is(dflt_ctx, NULL, GROUPS[g].name, "default"))
            TEST_PASS();
        else
            TEST_FAIL("group did not resolve to default provider");
    }

    /*
     * Advertised == wire (issue #45, item 1). Collect the code points the
     * hybrid provider advertises via OSSL_PROVIDER_get_capabilities and assert
     * each MLX group is advertised at the expected code point. The handshakes
     * below then assert the negotiated (on-the-wire) group carries that same
     * code point, closing advertised -> wire end to end.
     */
    OSSL_PROVIDER_get_capabilities(hyb, "TLS-GROUP", collect_group, NULL);
    for (g = 0; g < N_GROUPS; g++) {
        char t[128];
        long adv;

        snprintf(t, sizeof(t), "%s: advertised code point == 0x%04x",
                 GROUPS[g].name, GROUPS[g].codepoint);
        TEST_START(t);
        adv = advertised_codepoint(GROUPS[g].name);
        if (adv == GROUPS[g].codepoint)
            TEST_PASS();
        else if (adv < 0)
            TEST_FAIL("group not advertised by hybrid provider");
        else
            TEST_FAIL("advertised code point differs from expected");
    }

    /*
     * gen_init accepts the selection libssl uses for a TLS key-share (issue #45,
     * item 4). libssl generates a key-share with EVP_PKEY keygen, which drives
     * keymgmt gen_init with OSSL_KEYMGMT_SELECT_KEYPAIR; a successful hybrid
     * keygen here proves gen_init accepted it. (The handshakes below rely on the
     * same path; this isolates it as an explicit unit check.)
     */
    for (g = 0; g < N_GROUPS; g++) {
        char t[128];
        EVP_PKEY_CTX *kg;
        EVP_PKEY *pk = NULL;

        snprintf(t, sizeof(t), "%s: keymgmt gen_init accepts key-share selection",
                 GROUPS[g].name);
        TEST_START(t);
        kg = EVP_PKEY_CTX_new_from_name(hyb_ctx, GROUPS[g].name,
                                        "?provider=hybrid");
        if (kg != NULL && EVP_PKEY_keygen_init(kg) > 0
                && EVP_PKEY_keygen(kg, &pk) > 0 && pk != NULL)
            TEST_PASS();
        else
            TEST_FAIL("hybrid key-share keygen failed");
        EVP_PKEY_free(pk);
        EVP_PKEY_CTX_free(kg);
    }

    /* "?provider=hybrid": prefer hybrid for the (colliding) group name, but
     * fall back to default for the X25519/EC/ML-KEM components. */
    for (g = 0; g < N_GROUPS; g++) {
        char t[128];

        snprintf(t, sizeof(t), "%s: hybrid server <-> default client",
                 GROUPS[g].name);
        TEST_START(t);
        if (run_handshake(hyb_ctx, "?provider=hybrid", dflt_ctx, NULL,
                          GROUPS[g].name, GROUPS[g].codepoint))
            TEST_PASS();
        else
            TEST_FAIL("handshake / keying-material mismatch");

        snprintf(t, sizeof(t), "%s: default server <-> hybrid client",
                 GROUPS[g].name);
        TEST_START(t);
        if (run_handshake(dflt_ctx, NULL, hyb_ctx, "?provider=hybrid",
                          GROUPS[g].name, GROUPS[g].codepoint))
            TEST_PASS();
        else
            TEST_FAIL("handshake / keying-material mismatch");
    }

    /*
     * TLS interop with oqsprovider for the OQS-legacy ML-KEM hybrid groups.
     * These have no default-provider equivalent, so oqsprovider is the peer.
     * Their ML-KEM base comes from the default provider, so the hybrid side
     * needs no oqsprovider and the two libctxs stay collision-free. Skipped
     * (not failed) when oqsprovider is unavailable.
     */
    {
        static const struct { const char *name; int codepoint; } OQS_GROUPS[] = {
            { "x25519_mlkem512", 0x2FB6 }, { "p256_mlkem512", 0x2F4B },
            { "bp256_mlkem512",  0xFE20 }, { "p384_mlkem768", 0x2F4C },
            { "x448_mlkem768",   0x2FB7 }, { "bp384_mlkem768", 0xFE21 },
            { "p521_mlkem1024",  0x2F4D }, { "bp512_mlkem1024", 0xFE22 },
        };
        size_t n = sizeof(OQS_GROUPS) / sizeof(OQS_GROUPS[0]);
        OSSL_LIB_CTX *oqs_ctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *od = NULL, *oq = NULL;

        if (oqs_ctx != NULL
                && (od = OSSL_PROVIDER_load(oqs_ctx, "default")) != NULL
                && (oq = OSSL_PROVIDER_load(oqs_ctx, "oqsprovider")) != NULL) {
            printf("\n[hybrid <-> oqsprovider TLS interop]\n");
            for (g = 0; g < n; g++) {
                char t[128];

                snprintf(t, sizeof(t), "%s: hybrid server <-> oqs client",
                         OQS_GROUPS[g].name);
                TEST_START(t);
                if (run_handshake(hyb_ctx, "?provider=hybrid", oqs_ctx, NULL,
                                  OQS_GROUPS[g].name, OQS_GROUPS[g].codepoint))
                    TEST_PASS();
                else
                    TEST_FAIL("handshake / keying-material mismatch");

                snprintf(t, sizeof(t), "%s: oqs server <-> hybrid client",
                         OQS_GROUPS[g].name);
                TEST_START(t);
                if (run_handshake(oqs_ctx, NULL, hyb_ctx, "?provider=hybrid",
                                  OQS_GROUPS[g].name, OQS_GROUPS[g].codepoint))
                    TEST_PASS();
                else
                    TEST_FAIL("handshake / keying-material mismatch");
            }
        } else {
            printf("\n[hybrid <-> oqsprovider TLS interop] SKIPPED "
                   "(oqsprovider unavailable)\n");
            ERR_clear_error();
        }
        OSSL_PROVIDER_unload(oq);
        OSSL_PROVIDER_unload(od);
        OSSL_LIB_CTX_free(oqs_ctx);
    }

    /*
     * Note: Frodo/BIKE/HQC hybrid groups are validated at the KEM level in
     * hybrid_oqs_test (56/56, all directions). They are not exercised here over
     * TLS in-process: the hybrid side must load oqsprovider to source their PQ
     * base, at which point both providers advertise the same group name/code
     * point in one libctx and the TLS keyshare keygen cannot be steered to the
     * hybrid implementation. Cross-provider TLS for these needs two separate
     * processes and is out of scope for this in-process harness.
     */
    printf("\nNote: X448MLKEM1024 has no standardized TLS group codepoint and "
           "is exercised only via the KEM API (see hybrid_test).\n");

    printf("\n================================================\n");
    printf("Results: %d/%d passed", pass_count, test_count);
    if (fail_count > 0)
        printf(" (%d FAILED)", fail_count);
    printf("\n");
    rc = (fail_count == 0) ? 0 : 1;

end:
    OSSL_PROVIDER_unload(hyb);
    OSSL_PROVIDER_unload(d2);
    OSSL_PROVIDER_unload(d1);
    OSSL_LIB_CTX_free(hyb_ctx);
    OSSL_LIB_CTX_free(dflt_ctx);
    return rc;
}
