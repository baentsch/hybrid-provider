/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Provider robustness under adverse load, coexistence, and query/init ordering
 * (issue #47). Prior art shows a rich family of load-time failures; this test
 * asserts the hybrid provider is graceful in each of them. Every phase runs in
 * its own fresh OSSL_LIB_CTX so nothing leaks between them, and the cede lever is
 * driven explicitly per phase via HYBRID_CEDE_TO_DEFAULT (read at each provider
 * init) — so this test is excluded from the suite-wide "ceding off" override in
 * CMakeLists.txt and sets the lever itself.
 *
 * Phases (mapping the issue's acceptance bullets):
 *   A. Merely activating the provider must not break SSL_CTX_new / TLS init,
 *      with no provider key material in use — both lever states, both roles.
 *   B. Init tolerates being loaded BEFORE the default provider (no NULL deref,
 *      no hang): the cede probe finds no default, cedes nothing, and the
 *      provider still serves its inventory once default is loaded afterwards.
 *   C. Double activation (loaded twice) leaves the provider functional; one
 *      unload does not disable the other handle.
 *   D. query_operation never returns an empty/partial result that OpenSSL would
 *      cache: the very first fetch after load resolves (the provider is not
 *      silently disabled for the process).
 *   E. OID/NID registration skips an already-registered identifier and
 *      continues: pre-register a colliding OID, then load — the provider still
 *      comes up and serves its algorithms.
 *   F. No code-point / OID / name overlap with the default provider for anything
 *      NOT deliberately ceded (ceding on).
 *   G. Cede only when the default provider actually serves it — never withdraw
 *      an identifier the default does not provide (both directions).
 *   H. Coexistence: a foreign provider's generic key I/O still works with hybrid
 *      loaded (we do not shadow foreign encoders/decoders).
 *   I. Repeated load failure never hangs or loops unboundedly — it returns.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

static int tests, passed, failed;
#define OK(cond, ...) do { tests++; if (cond) { passed++; } \
    else { failed++; printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); \
           ERR_print_errors_fp(stdout); } } while (0)

static const char *g_mods;

/* Fresh libctx with the module search path and the cede lever set to `cede`.
 * The lever is read from the environment at each provider init, so setting it
 * here governs every hybrid load into the returned context. */
static OSSL_LIB_CTX *fresh_ctx(int cede)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();

    setenv("HYBRID_CEDE_TO_DEFAULT", cede ? "1" : "0", 1);
    if (ctx != NULL && g_mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, g_mods);
    return ctx;
}

static int kem_resolves(OSSL_LIB_CTX *ctx, const char *name, const char *prov)
{
    EVP_KEM *k = EVP_KEM_fetch(ctx, name, prov);
    int r = (k != NULL);

    EVP_KEM_free(k);
    ERR_clear_error();
    return r;
}

static int sig_resolves(OSSL_LIB_CTX *ctx, const char *name, const char *prov)
{
    EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(ctx, name, prov);
    int r = (s != NULL);

    EVP_SIGNATURE_free(s);
    ERR_clear_error();
    return r;
}

/* ------------------------------------------------------------------ */
/* A. Merely activating the provider must not break SSL_CTX_new.       */
/* ------------------------------------------------------------------ */
static void phase_ssl_ctx_new(int cede)
{
    OSSL_LIB_CTX *ctx = fresh_ctx(cede);
    SSL_CTX *sctx = NULL, *cctx = NULL;
    const char *tag = cede ? "cede on" : "cede off";

    if (ctx == NULL
            || OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        OK(0, "phase A (%s): load default+hybrid", tag);
        OSSL_LIB_CTX_free(ctx);
        return;
    }

    /* No key material, no explicit config: just build TLS contexts against a
     * libctx that has the hybrid provider active. This must not fail. */
    sctx = SSL_CTX_new_ex(ctx, NULL, TLS_server_method());
    OK(sctx != NULL, "phase A (%s): SSL_CTX_new_ex server", tag);
    cctx = SSL_CTX_new_ex(ctx, NULL, TLS_client_method());
    OK(cctx != NULL, "phase A (%s): SSL_CTX_new_ex client", tag);

    /* Group configuration on such a context must also still work: whatever the
     * provider advertises (or cedes), a plain default group name resolves. */
    if (cctx != NULL)
        OK(SSL_CTX_set1_groups_list(cctx, "X25519") == 1,
           "phase A (%s): SSL_CTX_set1_groups_list", tag);

    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    OSSL_LIB_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* B. Loaded before the default provider: no crash, cedes nothing.    */
/* ------------------------------------------------------------------ */
static void phase_load_before_default(void)
{
    OSSL_LIB_CTX *ctx = fresh_ctx(1);   /* ceding ON — the real-world default */
    OSSL_PROVIDER *hyb, *dflt;
    size_t i, retained = 0;

    if (ctx == NULL) {
        OK(0, "phase B: libctx");
        return;
    }
    /* Load hybrid FIRST. Its init probes for a "default" provider to cede to;
     * none is present yet, so the probe must find nothing (no NULL deref) and
     * withdraw nothing. */
    hyb = OSSL_PROVIDER_load(ctx, "hybrid");
    OK(hyb != NULL, "phase B: hybrid loads before default (no crash/hang)");

    /* With no default present at init, nothing standardized was ceded, so the
     * whole inventory is served — check a representative group resolves. */
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if (kem_resolves(ctx, hybrid_kem_table[i].hybrid_name, "provider=hybrid"))
            retained++;
    OK(retained == HYBRID_KEM_ALG_COUNT,
       "phase B: hybrid serves its whole KEM inventory when loaded first "
       "(%zu/%zu)", retained, (size_t)HYBRID_KEM_ALG_COUNT);

    /* Now load default afterwards; the two coexist without disturbing hybrid. */
    dflt = OSSL_PROVIDER_load(ctx, "default");
    OK(dflt != NULL, "phase B: default loads after hybrid");
    OK(kem_resolves(ctx, hybrid_kem_table[0].hybrid_name, "provider=hybrid"),
       "phase B: hybrid still resolves after default is loaded");

    OSSL_LIB_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* C. Double activation.                                              */
/* ------------------------------------------------------------------ */
static void phase_double_activation(void)
{
    OSSL_LIB_CTX *ctx = fresh_ctx(0);
    OSSL_PROVIDER *h1, *h2;

    if (ctx == NULL || OSSL_PROVIDER_load(ctx, "default") == NULL) {
        OK(0, "phase C: libctx/default");
        OSSL_LIB_CTX_free(ctx);
        return;
    }
    /* Activate the provider twice (mimics an explicit load layered on top of a
     * config activation). Both handles must be valid and the provider usable. */
    h1 = OSSL_PROVIDER_load(ctx, "hybrid");
    h2 = OSSL_PROVIDER_load(ctx, "hybrid");
    OK(h1 != NULL && h2 != NULL, "phase C: hybrid activates twice");
    OK(kem_resolves(ctx, hybrid_kem_table[0].hybrid_name, "provider=hybrid"),
       "phase C: provider functional after double activation");

    /* Dropping one reference must not disable the other. */
    OSSL_PROVIDER_unload(h2);
    OK(kem_resolves(ctx, hybrid_kem_table[0].hybrid_name, "provider=hybrid"),
       "phase C: still functional after one unload");

    OSSL_LIB_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* D. First fetch after load resolves (query not cached-empty).       */
/* ------------------------------------------------------------------ */
static void phase_query_not_empty(void)
{
    OSSL_LIB_CTX *ctx = fresh_ctx(0);

    if (ctx == NULL || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        OK(0, "phase D: load hybrid");
        OSSL_LIB_CTX_free(ctx);
        return;
    }
    /* The very first thing we do is fetch. If query_operation had returned an
     * empty table (e.g. because init had not finished registering) OpenSSL would
     * cache that and the provider would be disabled for the process — the fetch
     * would fail. It must succeed. */
    OK(kem_resolves(ctx, hybrid_kem_table[0].hybrid_name, "provider=hybrid"),
       "phase D: first fetch after load resolves (query not cached-empty)");
    OSSL_LIB_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* E. Colliding OID pre-registration does not abort the provider.     */
/* ------------------------------------------------------------------ */
static void phase_colliding_oid(void)
{
    OSSL_LIB_CTX *ctx;
    const HYBRID_SIG_INFO *first = &hybrid_sig_table[0];
    size_t i, served = 0;

    /* Pre-register one of our own signature OIDs in the global OBJ table BEFORE
     * loading the provider, forcing a registration collision at init. (OBJ_create
     * is process-global; a second registration of the same OID returns 0 rather
     * than replacing it, which is exactly the collision the provider must
     * tolerate via its core up-call.) */
    if (first->oid != NULL)
        (void)OBJ_create(first->oid, first->hybrid_name, first->hybrid_name);
    ERR_clear_error();

    ctx = fresh_ctx(0);
    if (ctx == NULL || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        OK(0, "phase E: hybrid loads despite a pre-registered colliding OID");
        OSSL_LIB_CTX_free(ctx);
        return;
    }
    OK(1, "phase E: hybrid loads despite a pre-registered colliding OID");

    /* The whole provider must still be up: every signature it would serve
     * resolves — one colliding OID did not abort registration. */
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (sig_resolves(ctx, hybrid_sig_table[i].hybrid_name, "provider=hybrid"))
            served++;
    OK(served == HYBRID_SIG_ALG_COUNT,
       "phase E: provider serves its whole signature inventory after collision "
       "(%zu/%zu)", served, (size_t)HYBRID_SIG_ALG_COUNT);

    OSSL_LIB_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* F + G. No overlap with default for retained algs; cede only when   */
/*        the default actually serves the identifier.                 */
/* ------------------------------------------------------------------ */

/* Collect the default provider's advertised TLS code points (groups + sigalgs)
 * into a flat set, so we can assert no retained hybrid alg collides by value. */
#define MAX_CP 256
static unsigned int g_def_cp[MAX_CP];
static int g_def_cp_n;

static int collect_cp(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;
    unsigned int id = 0;

    (void)arg;
    if ((p = OSSL_PARAM_locate_const(params,
             OSSL_CAPABILITY_TLS_GROUP_ID)) != NULL)
        (void)OSSL_PARAM_get_uint(p, &id);
#ifdef OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT
    if (id == 0
            && (p = OSSL_PARAM_locate_const(params,
                     OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT)) != NULL)
        (void)OSSL_PARAM_get_uint(p, &id);
#endif
    if (id != 0 && g_def_cp_n < MAX_CP)
        g_def_cp[g_def_cp_n++] = id;
    return 1;
}

static int default_has_cp(unsigned int cp)
{
    int i;

    for (i = 0; i < g_def_cp_n; i++)
        if (g_def_cp[i] == cp)
            return 1;
    return 0;
}

static void phase_no_overlap_and_cede_soundness(void)
{
    OSSL_LIB_CTX *on = fresh_ctx(1);    /* ceding ON  (real-world default) */
    OSSL_LIB_CTX *off;
    OSSL_PROVIDER *dflt;
    size_t i;
    int overlap = 0, cede_unsound = 0;

    if (on == NULL
            || (dflt = OSSL_PROVIDER_load(on, "default")) == NULL
            || OSSL_PROVIDER_load(on, "hybrid") == NULL) {
        OK(0, "phase F/G: load default+hybrid (cede on)");
        OSSL_LIB_CTX_free(on);
        return;
    }

    /* Snapshot the default provider's advertised code points. */
    g_def_cp_n = 0;
    OSSL_PROVIDER_get_capabilities(dflt, "TLS-GROUP", collect_cp, NULL);
#ifdef OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT
    OSSL_PROVIDER_get_capabilities(dflt, "TLS-SIGALG", collect_cp, NULL);
#endif

    /* A second context with ceding OFF gives the oracle "does the default even
     * serve this name?" independently of ceding: with ceding off, hybrid always
     * serves the name, and provider=default tells us whether default does. */
    off = fresh_ctx(0);
    if (off == NULL || OSSL_PROVIDER_load(off, "default") == NULL
            || OSSL_PROVIDER_load(off, "hybrid") == NULL) {
        OK(0, "phase F/G: load default+hybrid (cede off)");
        OSSL_LIB_CTX_free(on);
        OSSL_LIB_CTX_free(off);
        return;
    }

    /* --- KEMs --- */
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const HYBRID_KEM_INFO *r = &hybrid_kem_table[i];
        int hyb = kem_resolves(on, r->hybrid_name, "provider=hybrid");
        int def = kem_resolves(off, r->hybrid_name, "provider=default");
        unsigned int cp = (unsigned int)r->tls_codepoint;

        if (hyb) {
            /* Retained: default must NOT serve the same name, nor advertise the
             * same TLS code point. */
            if (kem_resolves(on, r->hybrid_name, "provider=default")
                    || (cp != 0 && default_has_cp(cp))) {
                overlap++;
                printf("    OVERLAP KEM %s (cp 0x%04x) retained yet default "
                       "serves it\n", r->hybrid_name, cp);
            }
        } else {
            /* Ceded: the default provider must actually serve it. */
            if (!def) {
                cede_unsound++;
                printf("    UNSOUND cede: KEM %s withdrawn but default does not "
                       "serve it\n", r->hybrid_name);
            }
        }
    }

    /* --- signatures --- */
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];
        int hyb = sig_resolves(on, r->hybrid_name, "provider=hybrid");
        int def = sig_resolves(off, r->hybrid_name, "provider=default");
        unsigned int cp = (unsigned int)r->tls_codepoint;

        if (hyb) {
            int def_name = sig_resolves(on, r->hybrid_name, "provider=default");
            int def_oid = r->oid != NULL
                && sig_resolves(on, r->oid, "provider=default");

            if (def_name || def_oid || (cp != 0 && default_has_cp(cp))) {
                overlap++;
                printf("    OVERLAP SIG %s (cp 0x%04x oid %s) retained yet "
                       "default serves it\n", r->hybrid_name, cp,
                       r->oid ? r->oid : "-");
            }
        } else {
            if (!def) {
                cede_unsound++;
                printf("    UNSOUND cede: SIG %s withdrawn but default does not "
                       "serve it\n", r->hybrid_name);
            }
        }
    }

    OK(overlap == 0,
       "phase F: retained algorithms never overlap the default (name/OID/code "
       "point)");
    OK(cede_unsound == 0,
       "phase G: an algorithm is ceded only when the default actually serves it");

    OSSL_LIB_CTX_free(on);
    OSSL_LIB_CTX_free(off);
}

/* ------------------------------------------------------------------ */
/* H. Foreign key I/O is not shadowed by the hybrid provider.         */
/* ------------------------------------------------------------------ */

/* PEM round-trip a key through SPKI (public) with hybrid loaded, proving the
 * hybrid provider does not shadow the foreign provider's encoders/decoders for
 * a key type it does not own. Returns 1 on a faithful round-trip. */
static int spki_roundtrip(OSSL_LIB_CTX *ctx, EVP_PKEY *key)
{
    BIO *mem = BIO_new(BIO_s_mem());
    EVP_PKEY *back = NULL;
    int ok = 0;

    if (mem == NULL)
        goto done;
    if (!PEM_write_bio_PUBKEY_ex(mem, key, ctx, NULL))
        goto done;
    back = PEM_read_bio_PUBKEY_ex(mem, NULL, NULL, NULL, ctx, NULL);
    ok = (back != NULL && EVP_PKEY_eq(back, key) == 1);
done:
    EVP_PKEY_free(back);
    BIO_free(mem);
    ERR_clear_error();
    return ok;
}

static void phase_foreign_key_io(void)
{
    OSSL_LIB_CTX *ctx = fresh_ctx(1);   /* ceding on: hybrid withdraws MLX etc. */
    EVP_PKEY *ec = NULL;
    int have_oqs;

    if (ctx == NULL || OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        OK(0, "phase H: load default+hybrid");
        OSSL_LIB_CTX_free(ctx);
        return;
    }
    /* oqsprovider is the genuine "third provider" when present. */
    have_oqs = OSSL_PROVIDER_load(ctx, "oqsprovider") != NULL;
    ERR_clear_error();

    /* Foreign (default-owned) key type: X25519. The hybrid provider registers
     * encoders only for its own hybrid names, so a plain X25519 SPKI must
     * round-trip through the default provider's codecs, unshadowed. */
    ec = EVP_PKEY_Q_keygen(ctx, NULL, "X25519");
    OK(ec != NULL, "phase H: keygen foreign X25519 with hybrid loaded");
    if (ec != NULL)
        OK(spki_roundtrip(ctx, ec),
           "phase H: foreign X25519 key I/O not shadowed by hybrid");
    EVP_PKEY_free(ec);

    /* When a real third provider is present, exercise one of ITS key types too
     * (a pure-PQ oqsprovider-only signature), proving we shadow no foreign
     * encoder. Try a few candidate names for build/version tolerance and use the
     * first that keygens; skip cleanly if none is available here. */
    if (have_oqs) {
        static const char *cand[] = { "falcon512", "mldsa44", "mayo1", NULL };
        EVP_PKEY *oq = NULL;
        const char *used = NULL;
        int i;

        for (i = 0; cand[i] != NULL && oq == NULL; i++) {
            oq = EVP_PKEY_Q_keygen(ctx, "provider=oqsprovider", cand[i]);
            ERR_clear_error();
            if (oq != NULL)
                used = cand[i];
        }
        if (oq != NULL) {
            OK(spki_roundtrip(ctx, oq),
               "phase H: foreign oqsprovider %s key I/O not shadowed by hybrid",
               used);
            EVP_PKEY_free(oq);
        } else {
            printf("  (phase H: oqsprovider present but no candidate keygen "
                   "succeeded; skipping foreign-PQ leg)\n");
        }
    }

    OSSL_LIB_CTX_free(ctx);
}

/* ------------------------------------------------------------------ */
/* I. Repeated load failure returns; it never hangs or loops forever. */
/* ------------------------------------------------------------------ */
static void phase_repeated_load_failure(void)
{
    OSSL_LIB_CTX *ctx = fresh_ctx(0);
    int i, all_null = 1;

    if (ctx == NULL) {
        OK(0, "phase I: libctx");
        return;
    }
    /* A provider that does not exist must fail promptly, every time. The bound
     * here is the assertion: if any iteration hung, the CTest TIMEOUT fires and
     * the test fails rather than the process wedging. */
    for (i = 0; i < 256; i++) {
        OSSL_PROVIDER *p = OSSL_PROVIDER_try_load(ctx, "hybrid-nonexistent-xyz",
                                                  0);

        if (p != NULL) {
            all_null = 0;
            OSSL_PROVIDER_unload(p);
        }
        ERR_clear_error();
    }
    OK(all_null, "phase I: repeated load of a missing provider always fails, "
       "returns (no hang/loop)");
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    g_mods = getenv("OPENSSL_MODULES");

    printf("Provider robustness under adverse load & coexistence (issue #47)\n");
    printf("================================================================\n");

    phase_ssl_ctx_new(1);
    phase_ssl_ctx_new(0);
    phase_load_before_default();
    phase_double_activation();
    phase_query_not_empty();
    phase_colliding_oid();
    phase_no_overlap_and_cede_soundness();
    phase_foreign_key_io();
    phase_repeated_load_failure();

    printf("\nResults: %d/%d passed", passed, tests);
    if (failed)
        printf(" (%d FAILED)", failed);
    printf("\n");
    return failed == 0 ? 0 : 1;
}
