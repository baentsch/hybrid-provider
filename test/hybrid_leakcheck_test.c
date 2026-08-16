/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dedicated leak-detection test with teeth (issue #47 follow-up to the #42
 * sanitizer leg).
 *
 * Why this test exists
 * --------------------
 * The general HYBRID_SANITIZE leg runs LSan with the fast unwinder, so every
 * leak stack is captured only as [malloc, CRYPTO_malloc]; the broad
 * `leak:libcrypto` suppression in test/lsan.supp then matches that CRYPTO_malloc
 * frame and masks essentially any leak — INCLUDING a future unfreed allocation
 * in this provider's own code (all provider heap goes through OPENSSL_malloc ->
 * CRYPTO_malloc). That leg therefore cannot, by itself, catch a newly introduced
 * provider leak.
 *
 * This test closes that gap. It is UNLOAD-CLEAN: it frees every object it makes
 * and unloads every provider before freeing the libctx, so the provider teardown
 * (and the libctx method-store cleanup) runs before LSan's end-of-run check. An
 * unload-clean run leaves nothing for the provider to leak, so it is run WITHOUT
 * the `leak:libcrypto` catch-all (CMake pins LSAN_OPTIONS to test/lsan_leakcheck.supp,
 * which suppresses only the genuine one-time init state of the un-instrumented PQ
 * dependencies). Consequently, a leak newly introduced in ANY exercised provider
 * path — keygen, key free, import/export, match, sign/verify, encaps/decaps,
 * encode/decode — surfaces unmasked and fails this test.
 *
 * It drives the full inventory (hybrid signatures + KEMs and, when built,
 * composite signatures + KEMs), so all four provider code modules
 * (hybrid_sig.c, hybrid_kem.c, composite_sig.c, composite_kem_*.c) plus the
 * shared keymgmt / encoder / decoder are exercised. Each algorithm self-skips if
 * its components are not fetchable in this build/version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include "hybrid_prov.h"
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
# include "composite_kem_prov.h"
#endif

static int tests, passed, failed, skipped;
#define OK(cond, ...) do { tests++; if (cond) { passed++; } \
    else { failed++; printf("  FAIL: "); printf(__VA_ARGS__); printf("\n"); \
           ERR_print_errors_fp(stdout); } } while (0)

#define PROP "provider=hybrid"

/* Keygen via the hybrid provider; NULL if the algorithm is not operable here. */
static EVP_PKEY *keygen(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, name, PROP);
    EVP_PKEY *k = NULL;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0)
        (void)EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    ERR_clear_error();       /* an inoperable algorithm is a skip, not a failure */
    return k;
}

/* Raw-param export then re-import of the PUBLIC key (keymgmt export/import
 * paths); returns a fresh key that must compare equal to the original, or NULL.
 * Public export is the raw-param path the provider supports across all families
 * (private-key serialization goes through the PKCS8 encoder, exercised
 * separately); this mirrors hybrid_param_test. */
static EVP_PKEY *todata_fromdata(OSSL_LIB_CTX *ctx, const char *name, EVP_PKEY *k)
{
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *fc = NULL;
    EVP_PKEY *k2 = NULL;

    if (EVP_PKEY_todata(k, EVP_PKEY_PUBLIC_KEY, &params) <= 0)
        goto end;
    if ((fc = EVP_PKEY_CTX_new_from_name(ctx, name, PROP)) == NULL
            || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &k2, EVP_PKEY_PUBLIC_KEY, params) <= 0)
        k2 = NULL;
end:
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(fc);
    return k2;
}

/* Encode `k` to DER in `structure`, decode it back, return the round-tripped key
 * (or NULL). Exercises the provider encoder + decoder allocation paths. */
static EVP_PKEY *der_roundtrip(OSSL_LIB_CTX *ctx, int selection,
                              const char *structure, EVP_PKEY *k)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(k, selection, "DER",
                                                        structure, PROP);
    OSSL_DECODER_CTX *d = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    size_t derlen = 0;
    EVP_PKEY *back = NULL;
    int dsel = (selection == EVP_PKEY_PUBLIC_KEY) ? EVP_PKEY_PUBLIC_KEY
                                                  : EVP_PKEY_KEYPAIR;

    if (e == NULL || OSSL_ENCODER_to_data(e, &der, &derlen) <= 0)
        goto end;
    d = OSSL_DECODER_CTX_new_for_pkey(&back, "DER", structure, NULL, dsel, ctx,
                                      PROP);
    p = der;
    if (d == NULL || OSSL_DECODER_from_data(d, &p, &derlen) <= 0)
        back = NULL;
end:
    OSSL_ENCODER_CTX_free(e);
    OSSL_DECODER_CTX_free(d);
    OPENSSL_free(der);
    return back;
}

/* Full battery for a signature key type. Silent skip if not operable. */
static void exercise_sig(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY *k = keygen(ctx, name), *k2 = NULL, *spki = NULL, *p8 = NULL;
    EVP_MD_CTX *md = NULL, *mv = NULL;
    unsigned char *sig = NULL;
    const unsigned char msg[] = "hybrid leak-check message";
    size_t siglen = 0;
    int ok = 1;

    if (k == NULL) {
        skipped++;
        return;
    }

    /* export/import + match */
    k2 = todata_fromdata(ctx, name, k);
    ok &= (k2 != NULL && EVP_PKEY_eq(k, k2) == 1);

    /* SPKI (public) and PKCS8 (keypair) encode->decode round-trips */
    spki = der_roundtrip(ctx, EVP_PKEY_PUBLIC_KEY, "SubjectPublicKeyInfo", k);
    ok &= (spki != NULL);
    p8 = der_roundtrip(ctx, EVP_PKEY_KEYPAIR, "PrivateKeyInfo", k);
    ok &= (p8 != NULL);

    /* sign then verify (pure/one-shot) */
    md = EVP_MD_CTX_new();
    if (md != NULL
            && EVP_DigestSignInit_ex(md, NULL, NULL, ctx, PROP, k, NULL) > 0
            && EVP_DigestSign(md, NULL, &siglen, msg, sizeof(msg)) > 0
            && (sig = OPENSSL_malloc(siglen)) != NULL
            && EVP_DigestSign(md, sig, &siglen, msg, sizeof(msg)) > 0) {
        mv = EVP_MD_CTX_new();
        ok &= (mv != NULL
               && EVP_DigestVerifyInit_ex(mv, NULL, NULL, ctx, PROP, k, NULL) > 0
               && EVP_DigestVerify(mv, sig, siglen, msg, sizeof(msg)) == 1);
    } else {
        ok = 0;
    }

    OK(ok, "sig %s: keygen/export/encode/sign round-trip", name);

    OPENSSL_free(sig);
    EVP_MD_CTX_free(md);
    EVP_MD_CTX_free(mv);
    EVP_PKEY_free(spki);
    EVP_PKEY_free(p8);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
}

/* Full battery for a KEM key type. Silent skip if not operable. */
static void exercise_kem(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY *k = keygen(ctx, name), *k2 = NULL, *spki = NULL, *p8 = NULL;
    EVP_PKEY_CTX *ec = NULL, *dc = NULL;
    unsigned char *ct = NULL, *ss = NULL, *ss2 = NULL;
    size_t ctlen = 0, sslen = 0, ss2len = 0;
    int ok = 1;

    if (k == NULL) {
        skipped++;
        return;
    }

    k2 = todata_fromdata(ctx, name, k);
    ok &= (k2 != NULL && EVP_PKEY_eq(k, k2) == 1);

    /* KEM key encoders are build-gated (HYBRID_KEM_ENCODERS) and only some KEMs
     * carry an OID, so treat SPKI/PKCS8 round-trips as best-effort: the point is
     * to run (and free) the encoder/decoder allocation paths without leaking; a
     * decline to encode is not a functional failure here. */
    spki = der_roundtrip(ctx, EVP_PKEY_PUBLIC_KEY, "SubjectPublicKeyInfo", k);
    p8 = der_roundtrip(ctx, EVP_PKEY_KEYPAIR, "PrivateKeyInfo", k);
    ERR_clear_error();

    /* encapsulate / decapsulate */
    ec = EVP_PKEY_CTX_new_from_pkey(ctx, k, PROP);
    dc = EVP_PKEY_CTX_new_from_pkey(ctx, k, PROP);
    if (ec != NULL && dc != NULL
            && EVP_PKEY_encapsulate_init(ec, NULL) > 0
            && EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) > 0
            && (ct = OPENSSL_malloc(ctlen)) != NULL
            && (ss = OPENSSL_malloc(sslen)) != NULL
            && EVP_PKEY_encapsulate(ec, ct, &ctlen, ss, &sslen) > 0
            && EVP_PKEY_decapsulate_init(dc, NULL) > 0
            && EVP_PKEY_decapsulate(dc, NULL, &ss2len, ct, ctlen) > 0
            && (ss2 = OPENSSL_malloc(ss2len)) != NULL
            && EVP_PKEY_decapsulate(dc, ss2, &ss2len, ct, ctlen) > 0) {
        ok &= (ss2len == sslen && memcmp(ss, ss2, sslen) == 0);
    } else {
        ok = 0;
    }

    OK(ok, "kem %s: keygen/export/encaps/decaps round-trip", name);

    OPENSSL_free(ct);
    OPENSSL_free(ss);
    OPENSSL_free(ss2);
    EVP_PKEY_CTX_free(ec);
    EVP_PKEY_CTX_free(dc);
    EVP_PKEY_free(spki);
    EVP_PKEY_free(p8);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(k);
}

int main(void)
{
    const char *mods = getenv("OPENSSL_MODULES");
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dflt = NULL, *hyb = NULL, *oqs = NULL;
    size_t i;

    if (ctx != NULL && mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (ctx == NULL
            || (dflt = OSSL_PROVIDER_load(ctx, "default")) == NULL
            || (hyb = OSSL_PROVIDER_load(ctx, "hybrid")) == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        OSSL_PROVIDER_unload(hyb);
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(ctx);
        return 1;
    }
    oqs = OSSL_PROVIDER_load(ctx, "oqsprovider");     /* best-effort */
    ERR_clear_error();

    printf("Leak-check: exercise + free every provider allocation path\n");
    printf("==========================================================\n");

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        exercise_sig(ctx, hybrid_sig_table[i].hybrid_name);
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        exercise_kem(ctx, hybrid_kem_table[i].hybrid_name);
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        exercise_sig(ctx, composite_sig_table[i].name);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        exercise_kem(ctx, composite_kem_table[i].name);
#endif

    /* Unload-clean shutdown: unload every provider we loaded so teardown runs
     * before the libctx (and LSan's leak check). This is what lets the test run
     * without the leak:libcrypto catch-all — see the file header. */
    OSSL_PROVIDER_unload(oqs);
    OSSL_PROVIDER_unload(hyb);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(ctx);

    printf("\nResults: %d/%d passed, %d skipped (inoperable here)",
           passed, tests, skipped);
    if (failed)
        printf(" (%d FAILED)", failed);
    printf("\n");
    return failed == 0 ? 0 : 1;
}
