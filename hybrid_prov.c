/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/provider.h>
#include <stdlib.h>

static OSSL_FUNC_provider_teardown_fn hybrid_teardown;
static OSSL_FUNC_provider_gettable_params_fn hybrid_gettable_params;
static OSSL_FUNC_provider_get_params_fn hybrid_get_params;
static OSSL_FUNC_provider_query_operation_fn hybrid_query;

static void hybrid_teardown(void *provctx)
{
    HYBRID_PROV_CTX *ctx = provctx;
    int i;

    if (ctx != NULL) {
        for (i = 0; i < ctx->n_comp_provs; i++)
            OSSL_PROVIDER_unload(ctx->comp_provs[i]);
        if (ctx->comp_owned)
            OSSL_LIB_CTX_free(ctx->comp_libctx);
        OPENSSL_free(ctx->pq_propq);
        OPENSSL_free(ctx->classic_propq);
        OPENSSL_free(ctx);
    }
}

/*
 * Set up a private component context from a space/comma-separated provider
 * list. On success ctx->comp_libctx points at the new context (comp_owned = 1);
 * when `providers` is empty the component context stays the application context.
 */
static int hybrid_setup_component_ctx(HYBRID_PROV_CTX *ctx,
                                      const char *providers, const char *path)
{
    char *list = NULL, *tok, *save = NULL;
    OSSL_LIB_CTX *cc = NULL;

    if (providers == NULL || *providers == '\0')
        return 1;   /* not configured: comp_libctx remains the app context */

    if ((cc = OSSL_LIB_CTX_new()) == NULL)
        return 0;
    if (path == NULL)
        path = getenv("OPENSSL_MODULES");
    if (path != NULL)
        OSSL_PROVIDER_set_default_search_path(cc, path);

    if ((list = OPENSSL_strdup(providers)) == NULL)
        goto err;
    for (tok = strtok_r(list, " \t,", &save); tok != NULL;
         tok = strtok_r(NULL, " \t,", &save)) {
        OSSL_PROVIDER *p;

        if (ctx->n_comp_provs >= HYBRID_MAX_COMPONENT_PROVIDERS)
            break;
        if ((p = OSSL_PROVIDER_load(cc, tok)) == NULL)
            goto err;
        ctx->comp_provs[ctx->n_comp_provs++] = p;
    }
    OPENSSL_free(list);

    ctx->comp_libctx = cc;
    ctx->comp_owned = 1;
    return 1;
err:
    OPENSSL_free(list);
    OSSL_LIB_CTX_free(cc);
    return 0;
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
#define HYBRID_KEM_KMGMT_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds)     \
    { nm, "provider=hybrid", hybrid_##cf##_kmgmt_functions,                   \
      ds " hybrid key management" },

/* SIG keymgmt registration rows, generated from the master list. */
#define HYBRID_SIG_KMGMT_REG(cf, nm, a1, grp, a2, lvl, oid, ds)              \
    { nm, "provider=hybrid", hybrid_##cf##_kmgmt_functions,                   \
      ds " hybrid key management" },

static const OSSL_ALGORITHM hybrid_keymgmts[] = {
    /* KEM keymgmts */
    HYBRID_KEM_LIST(HYBRID_KEM_KMGMT_REG)
    /* Signature keymgmts */
    HYBRID_SIG_LIST(HYBRID_SIG_KMGMT_REG)
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_SIG_KMGMT_REG
#undef HYBRID_KEM_KMGMT_REG

/* KEM operation registration rows, generated from the master list. */
#define HYBRID_KEM_OP_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds)        \
    { nm, "provider=hybrid", hybrid_kem_functions, ds " hybrid KEM" },

static const OSSL_ALGORITHM hybrid_kems[] = {
    HYBRID_KEM_LIST(HYBRID_KEM_OP_REG)
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_KEM_OP_REG

/* SIG operation registration rows, generated from the master list. */
#define HYBRID_SIG_OP_REG(cf, nm, a1, grp, a2, lvl, oid, ds)                 \
    { nm, "provider=hybrid", hybrid_sig_functions, ds " hybrid signature" },

static const OSSL_ALGORITHM hybrid_signatures[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_OP_REG)
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_SIG_OP_REG

/*
 * Encoders: SubjectPublicKeyInfo in DER and PEM, one pair per signature
 * algorithm (matched by key-type name + output/structure properties).
 */
#define HYBRID_SIG_ENC_REG(cf, nm, a1, grp, a2, lvl, oid, ds)                \
    { nm, "provider=hybrid,output=der,structure=SubjectPublicKeyInfo",       \
      hybrid_spki_der_encoder_functions, ds " SPKI DER encoder" },           \
    { nm, "provider=hybrid,output=pem,structure=SubjectPublicKeyInfo",       \
      hybrid_spki_pem_encoder_functions, ds " SPKI PEM encoder" },

static const OSSL_ALGORITHM hybrid_encoders[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_ENC_REG)
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_SIG_ENC_REG

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
    case OSSL_OP_ENCODER:
        return hybrid_encoders;
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
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
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

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->handle = handle;
    ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);
    ctx->bio_write_ex = bio_write_ex;

    /*
     * Read optional component property queries from the provider's config
     * section. The core hands the configured values back as UTF8 pointers;
     * duplicate them since the originals are not guaranteed to outlive this
     * call. Absent keys leave the pointers untouched (NULL).
     */
    if (c_get_params != NULL) {
        char *pq = NULL, *classic = NULL, *comp = NULL, *comp_path = NULL;
        OSSL_PARAM core_params[5];

        core_params[0] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_PQ_PROPQUERY, &pq, 0);
        core_params[1] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_CLASSIC_PROPQUERY, &classic, 0);
        core_params[2] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_COMPONENT_PROVIDERS, &comp, 0);
        core_params[3] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_COMPONENT_PATH, &comp_path, 0);
        core_params[4] = OSSL_PARAM_construct_end();

        if (c_get_params(handle, core_params)) {
            if (pq != NULL && (ctx->pq_propq = OPENSSL_strdup(pq)) == NULL)
                goto err;
            if (classic != NULL
                    && (ctx->classic_propq = OPENSSL_strdup(classic)) == NULL)
                goto err;
            if (!hybrid_setup_component_ctx(ctx, comp, comp_path))
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
