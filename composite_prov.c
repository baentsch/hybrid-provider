/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) provider entry point + algorithm registration (issue #6).
 * A minimal provider exposing the composite signature family for keygen +
 * sign/verify; encoders/decoders and OID registration follow.
 */
#include "composite_prov.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

static OSSL_FUNC_provider_teardown_fn composite_teardown;
static OSSL_FUNC_provider_gettable_params_fn composite_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn composite_prov_get_params;
static OSSL_FUNC_provider_query_operation_fn composite_query;

static void composite_teardown(void *provctx)
{
    OPENSSL_free(provctx);
}

static const OSSL_PARAM *composite_prov_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
        OSSL_PARAM_END
    };
    return params;
}

static int composite_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "composite-provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1.0"))
        return 0;
    return 1;
}

/* --- Algorithm tables (generated from the master list) --- */

#define COMPOSITE_KMGMT_REG(cf, nm, ...) \
    { nm, "provider=composite", composite_##cf##_kmgmt_functions,             \
      "composite key management" },
static const OSSL_ALGORITHM composite_keymgmts[] = {
    COMPOSITE_SIG_LIST(COMPOSITE_KMGMT_REG)
    { NULL, NULL, NULL, NULL }
};
#undef COMPOSITE_KMGMT_REG

#define COMPOSITE_SIG_REG(cf, nm, ...) \
    { nm, "provider=composite", composite_sig_functions,                      \
      "composite signature" },
static const OSSL_ALGORITHM composite_signatures[] = {
    COMPOSITE_SIG_LIST(COMPOSITE_SIG_REG)
    { NULL, NULL, NULL, NULL }
};
#undef COMPOSITE_SIG_REG

static const OSSL_ALGORITHM *
composite_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return composite_keymgmts;
    case OSSL_OP_SIGNATURE:
        return composite_signatures;
    default:
        return NULL;
    }
}

static const OSSL_DISPATCH composite_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))composite_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))composite_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (void (*)(void))composite_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))composite_query },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    COMPOSITE_PROV_CTX *ctx;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        if (in->function_id == OSSL_FUNC_CORE_GET_LIBCTX)
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
    }
    if (c_get_libctx == NULL)
        return 0;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return 0;
    ctx->handle = handle;
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

    *provctx = ctx;
    *out = composite_dispatch_table;
    return 1;
}
