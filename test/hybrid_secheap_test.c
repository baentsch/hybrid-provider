/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Secure-heap round-trip test (#126 / #129 follow-up).
 *
 * Why this test exists
 * --------------------
 * The signature private-key encoder (hybrid_encoder.c) serializes each component
 * by kind: a PQ half is pulled into an OPENSSL_secure_malloc() buffer, a classical
 * half comes back from the regular heap. Those temporaries must therefore be freed
 * with OPENSSL_secure_clear_free(), which dispatches correctly for BOTH heaps
 * (CRYPTO_secure_free falls back to CRYPTO_free for a non-secure pointer). Freeing
 * a secure-heap pointer with the plain OPENSSL_clear_free() instead calls free() on
 * an address inside the secure arena -- heap corruption / abort.
 *
 * The rest of the suite never calls CRYPTO_secure_malloc_init(), so OPENSSL_secure_
 * malloc() silently falls back to the regular heap there and the mismatch is inert.
 * This test initialises the secure heap first, so the PQ-component buffers really
 * land in the arena and a wrong free aborts here (and corrupts under ASan). It then
 * drives a PKCS#8 private-key encode -> decode round-trip for every serializable
 * signature row -- including the §3.4 PQ-first / EC-in-slot-2 rows, where slot 1 is
 * the secure-heap PQ buffer -- and asserts the decoded key compares equal.
 *
 * If the platform cannot provide a secure heap (e.g. mlock() denied by
 * RLIMIT_MEMLOCK in a restricted container), the round-trips still run for their
 * functional value, but the test reports that the targeted secure-heap coverage
 * was unavailable.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

static int tests, passed, failed, skipped;

#define PROP "provider=hybrid"

static EVP_PKEY *keygen(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, name, PROP);
    EVP_PKEY *k = NULL;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0)
        (void)EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    ERR_clear_error();           /* an inoperable algorithm is a skip, not a fail */
    return k;
}

/* PKCS#8 (keypair) DER encode -> decode via the hybrid provider; the encode is the
 * path that secure-malloc's and frees the per-component private buffers. */
static EVP_PKEY *p8_roundtrip(OSSL_LIB_CTX *ctx, EVP_PKEY *k)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(k, EVP_PKEY_KEYPAIR, "DER",
                                                        "PrivateKeyInfo", PROP);
    OSSL_DECODER_CTX *d = NULL;
    unsigned char *der = NULL;
    const unsigned char *p;
    size_t derlen = 0;
    EVP_PKEY *back = NULL;

    if (e == NULL || OSSL_ENCODER_to_data(e, &der, &derlen) <= 0)
        goto end;
    d = OSSL_DECODER_CTX_new_for_pkey(&back, "DER", "PrivateKeyInfo", NULL,
                                      EVP_PKEY_KEYPAIR, ctx, PROP);
    p = der;
    if (d == NULL || OSSL_DECODER_from_data(d, &p, &derlen) <= 0)
        back = NULL;
end:
    OSSL_ENCODER_CTX_free(e);
    OSSL_DECODER_CTX_free(d);
    OPENSSL_free(der);
    return back;
}

static void exercise(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY *k = keygen(ctx, name), *back = NULL;

    printf("  %-28s PKCS#8 round-trip (secure heap) ... ", name);
    fflush(stdout);

    if (k == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++;
        return;
    }
    tests++;
    back = p8_roundtrip(ctx, k);
    if (back != NULL && EVP_PKEY_eq(k, back) == 1) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        ERR_print_errors_fp(stdout);
        failed++;
    }
    EVP_PKEY_free(back);
    EVP_PKEY_free(k);
}

int main(void)
{
    const char *mods = getenv("OPENSSL_MODULES");
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *dflt = NULL, *hyb = NULL, *oqs = NULL;
    int sec;
    size_t i;

    /* Arena large enough to hold the largest component private buffer AND the
     * assembled blob at once (UOV uncompressed secret keys are ~405 KB, and the
     * buddy allocator rounds each up to a power-of-two block), with headroom; a
     * wrong free of any of it aborts below. Done before the libctx so the
     * provider's secure-malloc calls hit the arena. */
    (void)CRYPTO_secure_malloc_init((size_t)1 << 23, (size_t)1 << 4);
    sec = CRYPTO_secure_malloc_initialized();

    ctx = OSSL_LIB_CTX_new();
    if (ctx != NULL && mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (ctx == NULL
            || (dflt = OSSL_PROVIDER_load(ctx, "default")) == NULL
            || (hyb = OSSL_PROVIDER_load(ctx, "hybrid")) == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        OSSL_PROVIDER_unload(hyb);
        OSSL_PROVIDER_unload(dflt);
        OSSL_LIB_CTX_free(ctx);
        if (sec)
            CRYPTO_secure_malloc_done();
        return 1;
    }
    oqs = OSSL_PROVIDER_load(ctx, "oqsprovider");       /* best-effort */
    ERR_clear_error();

    printf("Secure-heap signature PKCS#8 round-trips (#129)\n");
    printf("===============================================\n");
    printf("secure heap: %s\n", sec ? "active"
           : "UNAVAILABLE (mlock denied?) -- functional run only");

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        /* Operation-only rows (no OID) have no PKCS#8 encoding. None ship today,
         * but the guard matches the rest of the suite (and #112's future rows). */
        if (hybrid_sig_table[i].oid == NULL)
            continue;
        exercise(ctx, hybrid_sig_table[i].hybrid_name);
    }

    OSSL_PROVIDER_unload(oqs);
    OSSL_PROVIDER_unload(hyb);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(ctx);
    if (sec)
        CRYPTO_secure_malloc_done();

    printf("\nResults: %d/%d passed, %d skipped", passed, tests, skipped);
    if (failed)
        printf(" (%d FAILED)", failed);
    if (!sec)
        printf("  [secure-heap coverage unavailable on this platform]");
    printf("\n");
    return failed == 0 ? 0 : 1;
}
