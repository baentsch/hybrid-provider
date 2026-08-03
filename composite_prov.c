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
#include <openssl/err.h>

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

#define COMPOSITE_ENC_REG(cf, nm, ...) \
    { nm, "provider=composite,output=der,structure=SubjectPublicKeyInfo",     \
      composite_spki_der_encoder_functions, "composite SPKI DER encoder" },   \
    { nm, "provider=composite,output=pem,structure=SubjectPublicKeyInfo",     \
      composite_spki_pem_encoder_functions, "composite SPKI PEM encoder" },
static const OSSL_ALGORITHM composite_encoders[] = {
    COMPOSITE_SIG_LIST(COMPOSITE_ENC_REG)
    { NULL, NULL, NULL, NULL }
};
#undef COMPOSITE_ENC_REG

static const OSSL_ALGORITHM *
composite_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return composite_keymgmts;
    case OSSL_OP_SIGNATURE:
        return composite_signatures;
    case OSSL_OP_ENCODER:
        return composite_encoders;
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
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        case OSSL_FUNC_BIO_WRITE_EX:
            bio_write_ex = OSSL_FUNC_BIO_write_ex(in);
            break;
        default:
            break;
        }
    }
    if (c_get_libctx == NULL)
        return 0;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return 0;
    ctx->handle = handle;
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);
    ctx->bio_write_ex = bio_write_ex;

    /*
     * Register the composite OIDs so the X.509 / TLS layers can map a
     * signatureAlgorithm OID back to the algorithm (needed to label and verify
     * composite-signed certificates). Rows with a NULL oid (experimental tier)
     * are skipped. Harmless if already registered; marks keep any "already
     * exists" notices off the error stack.
     */
    if (c_obj_create != NULL && c_obj_add_sigid != NULL) {
        size_t i;

        ERR_set_mark();
        for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
            const COMPOSITE_SIG_INFO *info = &composite_sig_table[i];

            if (info->oid == NULL)
                continue;
            (void)c_obj_create(handle, info->oid, info->name, info->name);
            (void)c_obj_add_sigid(handle, info->name, "", info->name);
        }
        ERR_pop_to_mark();
    }

    *provctx = ctx;
    *out = composite_dispatch_table;
    return 1;
}
