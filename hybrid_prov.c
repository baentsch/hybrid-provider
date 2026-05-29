/*
 * Copyright 2025 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/provider.h>

static OSSL_FUNC_provider_teardown_fn hybrid_teardown;
static OSSL_FUNC_provider_gettable_params_fn hybrid_gettable_params;
static OSSL_FUNC_provider_get_params_fn hybrid_get_params;
static OSSL_FUNC_provider_query_operation_fn hybrid_query;

static void hybrid_teardown(void *provctx)
{
    HYBRID_PROV_CTX *ctx = provctx;

    if (ctx != NULL)
        OPENSSL_free(ctx);
}

static const OSSL_PARAM *hybrid_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int hybrid_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "hybrid-provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
        return 0;
    return 1;
}

/* --- Algorithm tables --- */

static const OSSL_ALGORITHM hybrid_keymgmts[] = {
    { "X25519MLKEM768", "provider=hybrid",
      hybrid_x25519mlkem768_kmgmt_functions,
      "X25519+ML-KEM-768 hybrid key management" },
    { "X448MLKEM1024", "provider=hybrid",
      hybrid_x448mlkem1024_kmgmt_functions,
      "X448+ML-KEM-1024 hybrid key management" },
    { "SecP256r1MLKEM768", "provider=hybrid",
      hybrid_secp256r1mlkem768_kmgmt_functions,
      "P-256+ML-KEM-768 hybrid key management" },
    { "SecP384r1MLKEM1024", "provider=hybrid",
      hybrid_secp384r1mlkem1024_kmgmt_functions,
      "P-384+ML-KEM-1024 hybrid key management" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM hybrid_kems[] = {
    { "X25519MLKEM768", "provider=hybrid",
      hybrid_kem_functions,
      "X25519+ML-KEM-768 hybrid KEM" },
    { "X448MLKEM1024", "provider=hybrid",
      hybrid_kem_functions,
      "X448+ML-KEM-1024 hybrid KEM" },
    { "SecP256r1MLKEM768", "provider=hybrid",
      hybrid_kem_functions,
      "P-256+ML-KEM-768 hybrid KEM" },
    { "SecP384r1MLKEM1024", "provider=hybrid",
      hybrid_kem_functions,
      "P-384+ML-KEM-1024 hybrid KEM" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *
hybrid_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return hybrid_keymgmts;
    case OSSL_OP_KEM:
        return hybrid_kems;
    default:
        return NULL;
    }
}

/* --- Provider dispatch table --- */

static const OSSL_DISPATCH hybrid_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))hybrid_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))hybrid_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))hybrid_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))hybrid_query },
    { 0, NULL }
};

/* --- Provider entry point --- */

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    HYBRID_PROV_CTX *ctx;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

    *provctx = ctx;
    *out = hybrid_dispatch_table;
    return 1;
}
