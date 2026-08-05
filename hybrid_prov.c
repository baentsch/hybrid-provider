/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/provider.h>
#include <stdlib.h>
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"   /* composite (LAMPS) capability, folded in here */
#endif

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
#define HYBRID_KEM_KMGMT_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid) \
    { nm, "provider=hybrid", hybrid_##cf##_kmgmt_functions,                   \
      ds " hybrid key management" },

/* SIG keymgmt registration rows, generated from the master list. */
#define HYBRID_SIG_KMGMT_REG(cf, nm, a1, grp, a2, lvl, oid, ds, cp)              \
    { nm, "provider=hybrid", hybrid_##cf##_kmgmt_functions,                   \
      ds " hybrid key management" },

#ifdef HYBRID_COMPOSITE
# define COMPOSITE_KMGMT_REG(cf, nm, ...) \
    { nm, "provider=hybrid", composite_##cf##_kmgmt_functions,                \
      "composite key management" },
#endif
static const OSSL_ALGORITHM hybrid_keymgmts[] = {
    /* KEM keymgmts */
    HYBRID_KEM_LIST(HYBRID_KEM_KMGMT_REG)
    /* Signature keymgmts */
    HYBRID_SIG_LIST(HYBRID_SIG_KMGMT_REG)
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_KMGMT_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_SIG_KMGMT_REG
#undef HYBRID_KEM_KMGMT_REG
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_KMGMT_REG
#endif

/* KEM operation registration rows, generated from the master list. */
#define HYBRID_KEM_OP_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid)   \
    { nm, "provider=hybrid", hybrid_kem_functions, ds " hybrid KEM" },

static const OSSL_ALGORITHM hybrid_kems[] = {
    HYBRID_KEM_LIST(HYBRID_KEM_OP_REG)
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_KEM_OP_REG

/* SIG operation registration rows, generated from the master list. */
#define HYBRID_SIG_OP_REG(cf, nm, a1, grp, a2, lvl, oid, ds, cp)                 \
    { nm, "provider=hybrid", hybrid_sig_functions, ds " hybrid signature" },

#ifdef HYBRID_COMPOSITE
# define COMPOSITE_SIG_OP_REG(cf, nm, ...) \
    { nm, "provider=hybrid", composite_sig_functions, "composite signature" },
#endif
static const OSSL_ALGORITHM hybrid_signatures[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_OP_REG)
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_SIG_OP_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_SIG_OP_REG
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_SIG_OP_REG
#endif

/*
 * Encoders: SubjectPublicKeyInfo in DER and PEM, one pair per signature
 * algorithm (matched by key-type name + output/structure properties).
 */
#define HYBRID_SIG_ENC_REG(cf, nm, a1, grp, a2, lvl, oid, ds, cp)                \
    { nm, "provider=hybrid,output=der,structure=SubjectPublicKeyInfo",       \
      hybrid_spki_der_encoder_functions, ds " SPKI DER encoder" },           \
    { nm, "provider=hybrid,output=pem,structure=SubjectPublicKeyInfo",       \
      hybrid_spki_pem_encoder_functions, ds " SPKI PEM encoder" },           \
    { nm, "provider=hybrid,output=der,structure=PrivateKeyInfo",             \
      hybrid_pkcs8_der_encoder_functions, ds " PKCS8 DER encoder" },         \
    { nm, "provider=hybrid,output=pem,structure=PrivateKeyInfo",             \
      hybrid_pkcs8_pem_encoder_functions, ds " PKCS8 PEM encoder" },         \
    { nm, "provider=hybrid,output=text",                                     \
      hybrid_text_encoder_functions, ds " text encoder" },

/*
 * KEM encoders. Gated by HYBRID_KEM_ENCODERS (off by default), mirroring
 * oqsprovider's OQS_KEM_ENCODERS build option: KEM key files are rarely used
 * and only a few hybrid KEMs have an assigned OID. The shared encoder code
 * handles both families; NULL-OID KEMs registered here simply decline to encode.
 */
#ifdef HYBRID_KEM_ENCODERS
# define HYBRID_KEM_ENC_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid)  \
    { nm, "provider=hybrid,output=der,structure=SubjectPublicKeyInfo",       \
      hybrid_spki_der_encoder_functions, ds " SPKI DER encoder" },           \
    { nm, "provider=hybrid,output=pem,structure=SubjectPublicKeyInfo",       \
      hybrid_spki_pem_encoder_functions, ds " SPKI PEM encoder" },           \
    { nm, "provider=hybrid,output=der,structure=PrivateKeyInfo",             \
      hybrid_pkcs8_der_encoder_functions, ds " PKCS8 DER encoder" },         \
    { nm, "provider=hybrid,output=pem,structure=PrivateKeyInfo",             \
      hybrid_pkcs8_pem_encoder_functions, ds " PKCS8 PEM encoder" },         \
    { nm, "provider=hybrid,output=text",                                     \
      hybrid_text_encoder_functions, ds " text encoder" },
#endif

#ifdef HYBRID_COMPOSITE
# define COMPOSITE_ENC_REG(cf, nm, ...)                                       \
    { nm, "provider=hybrid,output=der,structure=SubjectPublicKeyInfo",       \
      composite_spki_der_encoder_functions, "composite SPKI DER encoder" },  \
    { nm, "provider=hybrid,output=pem,structure=SubjectPublicKeyInfo",       \
      composite_spki_pem_encoder_functions, "composite SPKI PEM encoder" },  \
    { nm, "provider=hybrid,output=der,structure=PrivateKeyInfo",             \
      composite_pkcs8_der_encoder_functions, "composite PKCS8 DER encoder" },\
    { nm, "provider=hybrid,output=pem,structure=PrivateKeyInfo",             \
      composite_pkcs8_pem_encoder_functions, "composite PKCS8 PEM encoder" },\
    { nm, "provider=hybrid,output=text",                                     \
      composite_text_encoder_functions, "composite text encoder" },
#endif
static const OSSL_ALGORITHM hybrid_encoders[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_ENC_REG)
#ifdef HYBRID_KEM_ENCODERS
    HYBRID_KEM_LIST(HYBRID_KEM_ENC_REG)
#endif
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_ENC_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_ENC_REG
#endif
#undef HYBRID_SIG_ENC_REG
#ifdef HYBRID_KEM_ENCODERS
# undef HYBRID_KEM_ENC_REG
#endif

/* Decoders: DER SubjectPublicKeyInfo -> key, one per signature algorithm. */
#define HYBRID_SIG_DEC_REG(cf, nm, a1, grp, a2, lvl, oid, ds, cp)                \
    { nm, "provider=hybrid,input=der,structure=SubjectPublicKeyInfo",        \
      hybrid_spki_der_decoder_functions, ds " SPKI DER decoder" },           \
    { nm, "provider=hybrid,input=der,structure=PrivateKeyInfo",              \
      hybrid_pkcs8_der_decoder_functions, ds " PKCS8 DER decoder" },

#ifdef HYBRID_KEM_ENCODERS
# define HYBRID_KEM_DEC_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid)  \
    { nm, "provider=hybrid,input=der,structure=SubjectPublicKeyInfo",        \
      hybrid_spki_der_decoder_functions, ds " SPKI DER decoder" },           \
    { nm, "provider=hybrid,input=der,structure=PrivateKeyInfo",              \
      hybrid_pkcs8_der_decoder_functions, ds " PKCS8 DER decoder" },
#endif

#ifdef HYBRID_COMPOSITE
# define COMPOSITE_DEC_REG(cf, nm, ...)                                       \
    { nm, "provider=hybrid,input=der,structure=SubjectPublicKeyInfo",        \
      composite_spki_der_decoder_functions, "composite SPKI DER decoder" },  \
    { nm, "provider=hybrid,input=der,structure=PrivateKeyInfo",              \
      composite_pkcs8_der_decoder_functions, "composite PKCS8 DER decoder" },
#endif
static const OSSL_ALGORITHM hybrid_decoders[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_DEC_REG)
#ifdef HYBRID_KEM_ENCODERS
    HYBRID_KEM_LIST(HYBRID_KEM_DEC_REG)
#endif
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_DEC_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_DEC_REG
#endif
#undef HYBRID_SIG_DEC_REG
#ifdef HYBRID_KEM_ENCODERS
# undef HYBRID_KEM_DEC_REG
#endif

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
    case OSSL_OP_DECODER:
        return hybrid_decoders;
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
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;
    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    OSSL_FUNC_BIO_write_ex_fn *bio_write_ex = NULL;
    OSSL_FUNC_BIO_read_ex_fn *bio_read_ex = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
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
        case OSSL_FUNC_BIO_READ_EX:
            bio_read_ex = OSSL_FUNC_BIO_read_ex(in);
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
    ctx->bio_read_ex = bio_read_ex;

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

    /*
     * Register the hybrid signature OIDs so the X.509 / TLS layers can map a
     * signatureAlgorithm OID back to the algorithm — required to verify
     * hybrid-signed certificates and the TLS CertificateVerify message. Uses the
     * core OBJ up-calls (libctx-scoped, provider-clean; the same mechanism
     * oqsprovider uses). If an OID is already registered (e.g. oqsprovider is
     * also loaded, sharing these OIDs and names) the calls are harmless; marks
     * keep any resulting "already exists" notices off the error stack.
     */
    if (c_obj_create != NULL && c_obj_add_sigid != NULL) {
        ERR_set_mark();
#define HYBRID_SIG_OID_REG(cf, nm, a1, grp, a2, lvl, oid, ds, cp)             \
        (void)c_obj_create(handle, oid, nm, nm);                             \
        (void)c_obj_add_sigid(handle, nm, "", nm);
        HYBRID_SIG_LIST(HYBRID_SIG_OID_REG)
#undef HYBRID_SIG_OID_REG
#ifdef HYBRID_COMPOSITE
        {   /* composite: skip the experimental rows (NULL oid) */
            size_t ci;

            for (ci = 0; ci < COMPOSITE_SIG_ALG_COUNT; ci++) {
                const COMPOSITE_SIG_INFO *cin = &composite_sig_table[ci];

                if (cin->oid == NULL)
                    continue;
                (void)c_obj_create(handle, cin->oid, cin->name, cin->name);
                (void)c_obj_add_sigid(handle, cin->name, "", cin->name);
            }
        }
#endif
        ERR_pop_to_mark();
    }

    *provctx = ctx;
    *out = hybrid_dispatch_table;
    return 1;

err:
    hybrid_teardown(ctx);
    return 0;
}
