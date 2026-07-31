/*
 * Copyright 2026 hybrid-provider contributors
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

    if (ctx != NULL) {
        OPENSSL_free(ctx->pq_propq);
        OPENSSL_free(ctx->classic_propq);
        OPENSSL_free(ctx);
    }
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

/* KEM keymgmt registration rows, generated from the master list. */
#define HYBRID_KEM_KMGMT_REG(cf, nm, a1, grp, a1k, a2, slot, cp, ds)         \
    { nm, "provider=hybrid", hybrid_##cf##_kmgmt_functions,                   \
      ds " hybrid key management" },

static const OSSL_ALGORITHM hybrid_keymgmts[] = {
    /* KEM keymgmts */
    HYBRID_KEM_LIST(HYBRID_KEM_KMGMT_REG)
    /* Signature keymgmts */
    { "ed25519mldsa44", "provider=hybrid",
      hybrid_ed25519mldsa44_kmgmt_functions,
      "Ed25519+ML-DSA-44 hybrid key management" },
    { "ed25519mldsa65", "provider=hybrid",
      hybrid_ed25519mldsa65_kmgmt_functions,
      "Ed25519+ML-DSA-65 hybrid key management" },
    { "ed448mldsa87", "provider=hybrid",
      hybrid_ed448mldsa87_kmgmt_functions,
      "Ed448+ML-DSA-87 hybrid key management" },
    { "p256mldsa44", "provider=hybrid",
      hybrid_p256mldsa44_kmgmt_functions,
      "P-256+ML-DSA-44 hybrid key management" },
    { "p256mldsa65", "provider=hybrid",
      hybrid_p256mldsa65_kmgmt_functions,
      "P-256+ML-DSA-65 hybrid key management" },
    { "p384mldsa87", "provider=hybrid",
      hybrid_p384mldsa87_kmgmt_functions,
      "P-384+ML-DSA-87 hybrid key management" },
    { NULL, NULL, NULL, NULL }
};

/* KEM operation registration rows, generated from the master list. */
#define HYBRID_KEM_OP_REG(cf, nm, a1, grp, a1k, a2, slot, cp, ds)            \
    { nm, "provider=hybrid", hybrid_kem_functions, ds " hybrid KEM" },

static const OSSL_ALGORITHM hybrid_kems[] = {
    HYBRID_KEM_LIST(HYBRID_KEM_OP_REG)
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_KEM_OP_REG

static const OSSL_ALGORITHM hybrid_signatures[] = {
    { "ed25519mldsa44", "provider=hybrid",
      hybrid_sig_functions,
      "Ed25519+ML-DSA-44 hybrid signature" },
    { "ed25519mldsa65", "provider=hybrid",
      hybrid_sig_functions,
      "Ed25519+ML-DSA-65 hybrid signature" },
    { "ed448mldsa87", "provider=hybrid",
      hybrid_sig_functions,
      "Ed448+ML-DSA-87 hybrid signature" },
    { "p256mldsa44", "provider=hybrid",
      hybrid_sig_functions,
      "P-256+ML-DSA-44 hybrid signature" },
    { "p256mldsa65", "provider=hybrid",
      hybrid_sig_functions,
      "P-256+ML-DSA-65 hybrid signature" },
    { "p384mldsa87", "provider=hybrid",
      hybrid_sig_functions,
      "P-384+ML-DSA-87 hybrid signature" },
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
    case OSSL_OP_SIGNATURE:
        return hybrid_signatures;
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
    { OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
      (void (*)(void))hybrid_get_capabilities },
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
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
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

    /*
     * Read optional component property queries from the provider's config
     * section. The core hands the configured values back as UTF8 pointers;
     * duplicate them since the originals are not guaranteed to outlive this
     * call. Absent keys leave the pointers untouched (NULL).
     */
    if (c_get_params != NULL) {
        char *pq = NULL, *classic = NULL;
        OSSL_PARAM core_params[3];

        core_params[0] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_PQ_PROPQUERY, &pq, 0);
        core_params[1] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_CLASSIC_PROPQUERY, &classic, 0);
        core_params[2] = OSSL_PARAM_construct_end();

        if (c_get_params(handle, core_params)) {
            if (pq != NULL && (ctx->pq_propq = OPENSSL_strdup(pq)) == NULL)
                goto err;
            if (classic != NULL
                    && (ctx->classic_propq = OPENSSL_strdup(classic)) == NULL)
                goto err;
        }
    }

    *provctx = ctx;
    *out = hybrid_dispatch_table;
    return 1;

err:
    hybrid_teardown(ctx);
    return 0;
}
