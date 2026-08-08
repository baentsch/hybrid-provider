/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/provider.h>
#include <stdlib.h>
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"       /* composite (LAMPS) signatures, folded in here */
# include "composite_kem_prov.h"   /* composite (LAMPS) ML-KEM, folded in here */
#endif

static void hybrid_cede_reset(void);   /* cede state teardown, defined below */

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
    hybrid_cede_reset();
}

/* Parse a boolean-ish string; return `dflt` for NULL/empty/unrecognized. */
static int hybrid_parse_bool(const char *s, int dflt)
{
    if (s == NULL || *s == '\0')
        return dflt;
    if (strcmp(s, "0") == 0 || OPENSSL_strcasecmp(s, "no") == 0
            || OPENSSL_strcasecmp(s, "off") == 0
            || OPENSSL_strcasecmp(s, "false") == 0)
        return 0;
    if (strcmp(s, "1") == 0 || OPENSSL_strcasecmp(s, "yes") == 0
            || OPENSSL_strcasecmp(s, "on") == 0
            || OPENSSL_strcasecmp(s, "true") == 0)
        return 1;
    return dflt;
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
# define COMPOSITE_KEM_KMGMT_REG(cf, nm, ...) \
    { nm, "provider=hybrid", composite_##cf##_kem_kmgmt_functions,            \
      "composite ML-KEM key management" },
#endif
static const OSSL_ALGORITHM hybrid_keymgmts[] = {
    /* KEM keymgmts */
    HYBRID_KEM_LIST(HYBRID_KEM_KMGMT_REG)
    /* Signature keymgmts */
    HYBRID_SIG_LIST(HYBRID_SIG_KMGMT_REG)
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_KMGMT_REG)
    COMPOSITE_KEM_LIST(COMPOSITE_KEM_KMGMT_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_SIG_KMGMT_REG
#undef HYBRID_KEM_KMGMT_REG
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_KMGMT_REG
# undef COMPOSITE_KEM_KMGMT_REG
#endif

/* KEM operation registration rows, generated from the master list. */
#define HYBRID_KEM_OP_REG(cf, nm, a1, grp, a1k, a2, slot, cp, sb, ds, oid)   \
    { nm, "provider=hybrid", hybrid_kem_functions, ds " hybrid KEM" },

#ifdef HYBRID_COMPOSITE
# define COMPOSITE_KEM_OP_REG(cf, nm, ...) \
    { nm, "provider=hybrid", composite_kem_functions, "composite ML-KEM" },
#endif
static const OSSL_ALGORITHM hybrid_kems[] = {
    HYBRID_KEM_LIST(HYBRID_KEM_OP_REG)
#ifdef HYBRID_COMPOSITE
    COMPOSITE_KEM_LIST(COMPOSITE_KEM_OP_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#undef HYBRID_KEM_OP_REG
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_KEM_OP_REG
#endif

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
# define COMPOSITE_KEM_ENC_REG(cf, nm, ...)                                   \
    { nm, "provider=hybrid,output=der,structure=SubjectPublicKeyInfo",       \
      composite_kem_spki_der_encoder_functions,                              \
      "composite ML-KEM SPKI DER encoder" },                                 \
    { nm, "provider=hybrid,output=pem,structure=SubjectPublicKeyInfo",       \
      composite_kem_spki_pem_encoder_functions,                              \
      "composite ML-KEM SPKI PEM encoder" },                                 \
    { nm, "provider=hybrid,output=der,structure=PrivateKeyInfo",             \
      composite_kem_pkcs8_der_encoder_functions,                             \
      "composite ML-KEM PKCS8 DER encoder" },                                \
    { nm, "provider=hybrid,output=pem,structure=PrivateKeyInfo",             \
      composite_kem_pkcs8_pem_encoder_functions,                             \
      "composite ML-KEM PKCS8 PEM encoder" },                                \
    { nm, "provider=hybrid,output=text",                                     \
      composite_kem_text_encoder_functions, "composite ML-KEM text encoder" },
#endif
static const OSSL_ALGORITHM hybrid_encoders[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_ENC_REG)
#ifdef HYBRID_KEM_ENCODERS
    HYBRID_KEM_LIST(HYBRID_KEM_ENC_REG)
#endif
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_ENC_REG)
    COMPOSITE_KEM_LIST(COMPOSITE_KEM_ENC_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_ENC_REG
# undef COMPOSITE_KEM_ENC_REG
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
# define COMPOSITE_KEM_DEC_REG(cf, nm, ...)                                   \
    { nm, "provider=hybrid,input=der,structure=SubjectPublicKeyInfo",        \
      composite_kem_spki_der_decoder_functions,                              \
      "composite ML-KEM SPKI DER decoder" },                                 \
    { nm, "provider=hybrid,input=der,structure=PrivateKeyInfo",              \
      composite_kem_pkcs8_der_decoder_functions,                             \
      "composite ML-KEM PKCS8 DER decoder" },
#endif
static const OSSL_ALGORITHM hybrid_decoders[] = {
    HYBRID_SIG_LIST(HYBRID_SIG_DEC_REG)
#ifdef HYBRID_KEM_ENCODERS
    HYBRID_KEM_LIST(HYBRID_KEM_DEC_REG)
#endif
#ifdef HYBRID_COMPOSITE
    COMPOSITE_SIG_LIST(COMPOSITE_DEC_REG)
    COMPOSITE_KEM_LIST(COMPOSITE_KEM_DEC_REG)
#endif
    { NULL, NULL, NULL, NULL }
};
#ifdef HYBRID_COMPOSITE
# undef COMPOSITE_DEC_REG
# undef COMPOSITE_KEM_DEC_REG
#endif
#undef HYBRID_SIG_DEC_REG
#ifdef HYBRID_KEM_ENCODERS
# undef HYBRID_KEM_DEC_REG
#endif

/*
 * Cede-to-default (see HYBRID_CONF_CEDE_TO_DEFAULT). Mirrors oqsprovider's
 * rt_disabled_algs idiom: one small file-scope list of withdrawn algorithm
 * names is the single source of truth. hybrid_query returns filtered copies of
 * the static tables and the capability advertisers consult hybrid_is_ceded();
 * both keep the provider from offering what the default provider already does.
 * File-scope (not per-provctx) because, like oqsprovider, one loaded instance
 * decides this once — hybrid_apply_cede() resets the state on each init.
 */
static const char *hybrid_ceded[HYBRID_KEM_ALG_COUNT + HYBRID_SIG_ALG_COUNT
#ifdef HYBRID_COMPOSITE
        + COMPOSITE_SIG_ALG_COUNT + COMPOSITE_KEM_ALG_COUNT
#endif
    ];
static size_t hybrid_n_ceded;
static int hybrid_filter_enabled;
static OSSL_ALGORITHM *hybrid_keymgmts_rt, *hybrid_kems_rt,
    *hybrid_signatures_rt, *hybrid_encoders_rt, *hybrid_decoders_rt;

int hybrid_is_ceded(const char *name)
{
    size_t i;

    if (name != NULL)
        for (i = 0; i < hybrid_n_ceded; i++)
            if (strcmp(hybrid_ceded[i], name) == 0)
                return 1;
    return 0;
}

/* Record `name` (a static-lifetime master-table pointer) as ceded, if new.
 * hybrid_ceded is sized to hold every algorithm, so this never overflows. */
static void hybrid_mark_ceded(const char *name)
{
    if (name != NULL && !hybrid_is_ceded(name))
        hybrid_ceded[hybrid_n_ceded++] = name;
}

/* Free the filtered tables and clear the ceded state (teardown / re-init). */
static void hybrid_cede_reset(void)
{
    OPENSSL_free(hybrid_keymgmts_rt);
    OPENSSL_free(hybrid_kems_rt);
    OPENSSL_free(hybrid_signatures_rt);
    OPENSSL_free(hybrid_encoders_rt);
    OPENSSL_free(hybrid_decoders_rt);
    hybrid_keymgmts_rt = hybrid_kems_rt = hybrid_signatures_rt =
        hybrid_encoders_rt = hybrid_decoders_rt = NULL;
    hybrid_n_ceded = 0;
    hybrid_filter_enabled = 0;
}

/* OSSL_PROVIDER_do_all callback: capture the loaded "default" provider, if any.
 * Returns 0 to stop the walk once found. */
static int hybrid_find_default_cb(OSSL_PROVIDER *prov, void *arg)
{
    const char *nm = OSSL_PROVIDER_get0_name(prov);

    if (nm != NULL && strcmp(nm, "default") == 0) {
        *(OSSL_PROVIDER **)arg = prov;
        return 0;
    }
    return 1;
}

/* Cede any KEM the default provider advertises as a TLS group under the same
 * name or code point (OSSL_PROVIDER_get_capabilities callback). */
static int hybrid_cede_group_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;
    unsigned int id = 0;
    const char *nm = NULL;
    size_t i;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_ID)) != NULL)
        (void)OSSL_PARAM_get_uint(p, &id);
    if ((p = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME)) != NULL
            && p->data_type == OSSL_PARAM_UTF8_STRING)
        nm = p->data;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if ((id != 0 && (unsigned int)hybrid_kem_table[i].tls_codepoint == id)
                || (nm != NULL
                    && strcmp(nm, hybrid_kem_table[i].hybrid_name) == 0))
            hybrid_mark_ceded(hybrid_kem_table[i].hybrid_name);
    (void)arg;
    return 1;
}

/* Cede any hybrid/composite signature the default provider advertises as a TLS
 * sigalg under the same name, code point or OID. */
static int hybrid_cede_sigalg_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p;
    unsigned int cp = 0;
    const char *nm = NULL, *oid = NULL;
    size_t i;

    if ((p = OSSL_PARAM_locate_const(params,
            OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT)) != NULL)
        (void)OSSL_PARAM_get_uint(p, &cp);
    if ((p = OSSL_PARAM_locate_const(params,
            OSSL_CAPABILITY_TLS_SIGALG_NAME)) != NULL
            && p->data_type == OSSL_PARAM_UTF8_STRING)
        nm = p->data;
    if ((p = OSSL_PARAM_locate_const(params,
            OSSL_CAPABILITY_TLS_SIGALG_OID)) != NULL
            && p->data_type == OSSL_PARAM_UTF8_STRING)
        oid = p->data;

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];

        if ((cp != 0 && (unsigned int)r->tls_codepoint == cp)
                || (nm != NULL && strcmp(nm, r->hybrid_name) == 0)
                || (oid != NULL && r->oid != NULL && strcmp(oid, r->oid) == 0))
            hybrid_mark_ceded(r->hybrid_name);
    }
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const COMPOSITE_SIG_INFO *r = &composite_sig_table[i];

        if ((cp != 0 && (unsigned int)r->tls_codepoint == cp)
                || (nm != NULL && strcmp(nm, r->name) == 0)
                || (oid != NULL && r->oid != NULL && strcmp(oid, r->oid) == 0))
            hybrid_mark_ceded(r->name);
    }
#endif
    (void)arg;
    return 1;
}

/* Cede every algorithm the default provider resolves by a direct fetch (KEM by
 * name; signature by name, else by OID) — catching those it serves without a
 * TLS capability (e.g. a KEM with no group, or a certificate-only signature). */
static void hybrid_cede_by_fetch(OSSL_LIB_CTX *libctx)
{
    size_t i;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        EVP_KEM *k = EVP_KEM_fetch(libctx, hybrid_kem_table[i].hybrid_name,
                                   "provider=default");

        if (k != NULL)
            hybrid_mark_ceded(hybrid_kem_table[i].hybrid_name);
        EVP_KEM_free(k);
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(libctx, r->hybrid_name,
                                               "provider=default");

        if (s == NULL && r->oid != NULL)
            s = EVP_SIGNATURE_fetch(libctx, r->oid, "provider=default");
        if (s != NULL)
            hybrid_mark_ceded(r->hybrid_name);
        EVP_SIGNATURE_free(s);
    }
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const COMPOSITE_SIG_INFO *r = &composite_sig_table[i];
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(libctx, r->name,
                                               "provider=default");

        if (s == NULL && r->oid != NULL)
            s = EVP_SIGNATURE_fetch(libctx, r->oid, "provider=default");
        if (s != NULL)
            hybrid_mark_ceded(r->name);
        EVP_SIGNATURE_free(s);
    }
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++) {
        const COMPOSITE_KEM_INFO *r = &composite_kem_table[i];
        EVP_KEM *k = EVP_KEM_fetch(libctx, r->name, "provider=default");

        if (k == NULL && r->oid != NULL)
            k = EVP_KEM_fetch(libctx, r->oid, "provider=default");
        if (k != NULL)
            hybrid_mark_ceded(r->name);
        EVP_KEM_free(k);
    }
#endif
}

/* Heap copy of `src` minus every entry whose name is ceded (names are single,
 * non-aliased tokens in our tables, so strcmp is exact). NULL on OOM. */
static OSSL_ALGORITHM *hybrid_filter_algs(const OSSL_ALGORITHM *src)
{
    size_t count = 0, i, j = 0;
    OSSL_ALGORITHM *out;

    while (src[count].algorithm_names != NULL)
        count++;
    if ((out = OPENSSL_malloc((count + 1) * sizeof(*out))) == NULL)
        return NULL;
    for (i = 0; i < count; i++)
        if (!hybrid_is_ceded(src[i].algorithm_names))
            out[j++] = src[i];
    out[j] = src[count];   /* the {NULL,...} terminator */
    return out;
}

/*
 * Withdraw everything the default provider already serves in `libctx`. Matching
 * is by any identifier we might share with it — algorithm name, TLS code point
 * or OID — so it is not a fixed list but tracks whatever the default provider
 * offers now (the standardized hybrid KEM groups) or later (e.g. native
 * composite signatures). Runs at init: this provider is not yet active in the
 * store, so the probing fetches/capability queries cannot recurse into
 * hybrid_query. Returns 0 only on allocation failure.
 */
static int hybrid_apply_cede(OSSL_LIB_CTX *libctx)
{
    OSSL_PROVIDER *def = NULL;

    hybrid_cede_reset();
    OSSL_PROVIDER_do_all(libctx, hybrid_find_default_cb, &def);
    if (def == NULL)
        return 1;   /* no default provider here: nothing to cede */

    /* Probing pushes "unable to fetch" errors for absent identifiers; a miss is
     * the expected case, so keep them off the caller's error stack. */
    ERR_set_mark();
    hybrid_cede_by_fetch(libctx);
    (void)OSSL_PROVIDER_get_capabilities(def, "TLS-GROUP",
                                         hybrid_cede_group_cb, NULL);
    (void)OSSL_PROVIDER_get_capabilities(def, "TLS-SIGALG",
                                         hybrid_cede_sigalg_cb, NULL);
    ERR_pop_to_mark();

    if (hybrid_n_ceded == 0)
        return 1;

    hybrid_keymgmts_rt = hybrid_filter_algs(hybrid_keymgmts);
    hybrid_kems_rt = hybrid_filter_algs(hybrid_kems);
    hybrid_signatures_rt = hybrid_filter_algs(hybrid_signatures);
    hybrid_encoders_rt = hybrid_filter_algs(hybrid_encoders);
    hybrid_decoders_rt = hybrid_filter_algs(hybrid_decoders);
    if (hybrid_keymgmts_rt == NULL || hybrid_kems_rt == NULL
            || hybrid_signatures_rt == NULL || hybrid_encoders_rt == NULL
            || hybrid_decoders_rt == NULL) {
        hybrid_cede_reset();
        return 0;
    }
    hybrid_filter_enabled = 1;
    return 1;
}

static const OSSL_ALGORITHM *
hybrid_query(void *provctx, int operation_id, int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return hybrid_filter_enabled ? hybrid_keymgmts_rt : hybrid_keymgmts;
    case OSSL_OP_KEM:
        return hybrid_filter_enabled ? hybrid_kems_rt : hybrid_kems;
    case OSSL_OP_SIGNATURE:
        return hybrid_filter_enabled ? hybrid_signatures_rt : hybrid_signatures;
    case OSSL_OP_ENCODER:
        return hybrid_filter_enabled ? hybrid_encoders_rt : hybrid_encoders;
    case OSSL_OP_DECODER:
        return hybrid_filter_enabled ? hybrid_decoders_rt : hybrid_decoders;
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
    int cede_to_default;

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
    /* Cede-to-default lever, resolved below: config key first, then the env var
     * (which wins when set). On by default. */
    cede_to_default = 1;

    if (c_get_params != NULL) {
        char *pq = NULL, *classic = NULL, *comp = NULL, *comp_path = NULL;
        char *cede = NULL;
        OSSL_PARAM core_params[6];

        core_params[0] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_PQ_PROPQUERY, &pq, 0);
        core_params[1] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_CLASSIC_PROPQUERY, &classic, 0);
        core_params[2] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_COMPONENT_PROVIDERS, &comp, 0);
        core_params[3] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_COMPONENT_PATH, &comp_path, 0);
        core_params[4] = OSSL_PARAM_construct_utf8_ptr(
            HYBRID_CONF_CEDE_TO_DEFAULT, &cede, 0);
        core_params[5] = OSSL_PARAM_construct_end();

        if (c_get_params(handle, core_params)) {
            if (pq != NULL && (ctx->pq_propq = OPENSSL_strdup(pq)) == NULL)
                goto err;
            if (classic != NULL
                    && (ctx->classic_propq = OPENSSL_strdup(classic)) == NULL)
                goto err;
            if (cede != NULL)
                cede_to_default = hybrid_parse_bool(cede, cede_to_default);
            if (!hybrid_setup_component_ctx(ctx, comp, comp_path))
                goto err;
        }
    }

    /* Environment variable overrides the config key when set. Then withdraw the
     * algorithms the default provider already serves in this context. */
    cede_to_default = hybrid_parse_bool(getenv(HYBRID_ENV_CEDE_TO_DEFAULT),
                                        cede_to_default);
    if (cede_to_default && !hybrid_apply_cede(ctx->libctx))
        goto err;

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
        {   /* composite ML-KEM: register the OID<->name mapping only (a KEM is
             * not a signature, so no add_sigid). Lets the X.509 / CLI layers map
             * a composite-KEM SPKI OID back to the algorithm name. */
            size_t ki;

            for (ki = 0; ki < COMPOSITE_KEM_ALG_COUNT; ki++)
                (void)c_obj_create(handle, composite_kem_table[ki].oid,
                                   composite_kem_table[ki].name,
                                   composite_kem_table[ki].name);
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
