/*
 * Copyright 2026 The hybrid-provider Authors
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef HYBRID_TEST_PROV_UTIL_H
#define HYBRID_TEST_PROV_UTIL_H

#include <stddef.h>
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

/*
 * Explicitly loaded providers, recorded per libctx so they are unloaded before
 * that libctx is freed. OSSL_LIB_CTX_free does not drop the reference that
 * OSSL_PROVIDER_load returned: a provider still held that way is torn down only
 * at OPENSSL_cleanup, after LeakSanitizer's end-of-run check, so it and all it
 * holds (provctx, the libctx's cached methods) would be reported as leaked.
 *
 * Load with hybrid_test_load() (or wrap any other load in hybrid_test_track())
 * and release with hybrid_test_libctx_free() on every exit, SKIP included.
 * A NULL libctx is the default one: its loads are unloaded the same way and
 * the libctx itself is left alone. Not thread-safe: load and free from one
 * thread (other threads may use the loaded providers in between).
 */
#define HYBRID_TEST_MAX_LOADS 32

static struct {
    OSSL_LIB_CTX *ctx;
    OSSL_PROVIDER *prov;
} hybrid_test_loads[HYBRID_TEST_MAX_LOADS];
static size_t hybrid_test_nloads;

/*
 * Record `prov` (the result of a load into `ctx`) for hybrid_test_libctx_free.
 * Returns prov; NULL passes through unrecorded. If the table is full the
 * provider is unloaded at once and NULL returned, so the test fails loudly
 * rather than leaking.
 */
static inline OSSL_PROVIDER *hybrid_test_track(OSSL_LIB_CTX *ctx,
                                               OSSL_PROVIDER *prov)
{
    if (prov == NULL)
        return NULL;
    if (hybrid_test_nloads == HYBRID_TEST_MAX_LOADS) {
        fprintf(stderr, "hybrid_test_track: more than %d provider loads\n",
                HYBRID_TEST_MAX_LOADS);
        OSSL_PROVIDER_unload(prov);
        return NULL;
    }
    hybrid_test_loads[hybrid_test_nloads].ctx = ctx;
    hybrid_test_loads[hybrid_test_nloads].prov = prov;
    hybrid_test_nloads++;
    return prov;
}

static inline OSSL_PROVIDER *hybrid_test_load(OSSL_LIB_CTX *ctx,
                                              const char *name)
{
    return hybrid_test_track(ctx, OSSL_PROVIDER_load(ctx, name));
}

/* Unload ctx's recorded providers, newest first (a composing provider before
 * the providers it composes from). The libctx stays usable. */
static inline void hybrid_test_unload_all(OSSL_LIB_CTX *ctx)
{
    size_t i = hybrid_test_nloads, kept = 0;

    while (i-- > 0)
        if (hybrid_test_loads[i].ctx == ctx)
            OSSL_PROVIDER_unload(hybrid_test_loads[i].prov);
    for (i = 0; i < hybrid_test_nloads; i++)
        if (hybrid_test_loads[i].ctx != ctx)
            hybrid_test_loads[kept++] = hybrid_test_loads[i];
    hybrid_test_nloads = kept;
}

/* Unload ctx's recorded providers, then free ctx. NULL-safe. */
static inline void hybrid_test_libctx_free(OSSL_LIB_CTX *ctx)
{
    hybrid_test_unload_all(ctx);
    OSSL_LIB_CTX_free(ctx);
}

#endif /* HYBRID_TEST_PROV_UTIL_H */
