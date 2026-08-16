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

static OSSL_FUNC_provider_teardown_fn hybrid_teardown;
static OSSL_FUNC_provider_gettable_params_fn hybrid_gettable_params;
static OSSL_FUNC_provider_get_params_fn hybrid_get_params;
static OSSL_FUNC_provider_query_operation_fn hybrid_query;

static void hybrid_teardown(void *provctx)
{
    HYBRID_PROV_CTX *ctx = provctx;
    int i;

    if (ctx == NULL)
        return;
    for (i = 0; i < ctx->n_comp_provs; i++)
        OSSL_PROVIDER_unload(ctx->comp_provs[i]);
    if (ctx->comp_owned)
        OSSL_LIB_CTX_free(ctx->comp_libctx);
    OPENSSL_free(ctx->pq_propq);
    OPENSSL_free(ctx->classic_propq);
    /* Per-instance cede state (immutable after init) — this instance owns it. */
    OPENSSL_free(ctx->ceded);
    OPENSSL_free(ctx->keymgmts_rt);
    OPENSSL_free(ctx->kems_rt);
    OPENSSL_free(ctx->signatures_rt);
    OPENSSL_free(ctx->encoders_rt);
    OPENSSL_free(ctx->decoders_rt);
    OPENSSL_free(ctx);
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
 * Concurrency model
 * -----------------
 * This provider keeps NO shared mutable runtime state, so its operational paths
 * take no locks:
 *
 *   - The cede-to-default runtime tables (the withdrawn-name list and the
 *     filtered query tables) are PER-PROVCTX (in HYBRID_PROV_CTX): built once
 *     during OSSL_provider_init, before *provctx is handed back, and immutable
 *     until teardown (which the core runs only once the instance is no longer
 *     queryable). No reader/writer window ever overlaps, so hybrid_query and
 *     hybrid_is_ceded read them lock-free, and one instance's load/unload never
 *     touches another's tables. The cede decision is re-evaluated per init (per
 *     libctx + lever). The probe that computes it calls out of the provider (EVP
 *     fetches, capability callbacks) into a stack-local set, holding no lock and
 *     writing only to per-provctx memory no other thread can yet see.
 *
 *   - Component sizes are compile-time constants (hybrid_kem_sizes[] /
 *     hybrid_sig_sizes[]) copied into each key at construction, so there is no
 *     lazily-computed, shared size cache to synchronize.
 *
 * Everything else per key/context is either immutable after construction or
 * owned by a single operation. See test/hybrid_threads_test.c.
 */

/*
 * Cede-to-default (see HYBRID_CONF_CEDE_TO_DEFAULT). Mirrors oqsprovider's
 * rt_disabled_algs idiom: a small list of withdrawn algorithm names drives
 * everything. hybrid_query returns filtered copies of the static tables and the
 * capability advertisers consult hybrid_is_ceded(); both keep the provider from
 * offering what the default provider already does.
 *
 * The list and the filtered tables live in HYBRID_PROV_CTX — per instance, not
 * global — computed at init and immutable thereafter (see the locking-discipline
 * comment above). A withdrawal set (HYBRID_CEDE_SET) is first built on the stack
 * by the probing phase, which calls out into EVP and capability callbacks and so
 * must touch no shared state; the result is then copied into the provctx.
 */
#ifdef HYBRID_COMPOSITE
# define HYBRID_COMPOSITE_CEDE_EXTRA + COMPOSITE_SIG_ALG_COUNT + COMPOSITE_KEM_ALG_COUNT
#else
# define HYBRID_COMPOSITE_CEDE_EXTRA
#endif
#define HYBRID_CEDE_MAX (HYBRID_KEM_ALG_COUNT + HYBRID_SIG_ALG_COUNT             \
        HYBRID_COMPOSITE_CEDE_EXTRA)

typedef struct {
    const char *names[HYBRID_CEDE_MAX];
    size_t n;
} HYBRID_CEDE_SET;

static int cede_set_has(const HYBRID_CEDE_SET *set, const char *name)
{
    size_t i;

    if (name != NULL)
        for (i = 0; i < set->n; i++)
            if (strcmp(set->names[i], name) == 0)
                return 1;
    return 0;
}

/* Record `name` (a static-lifetime master-table pointer) as ceded, if new.
 * `names` is sized to hold every algorithm, so this never overflows. */
static void cede_set_add(HYBRID_CEDE_SET *set, const char *name)
{
    if (name != NULL && !cede_set_has(set, name))
        set->names[set->n++] = name;
}

int hybrid_is_ceded(void *provctx, const char *name)
{
    HYBRID_PROV_CTX *ctx = provctx;
    size_t i;

    if (ctx != NULL && name != NULL)
        for (i = 0; i < ctx->n_ceded; i++)
            if (strcmp(ctx->ceded[i], name) == 0)
                return 1;
    return 0;
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
 * name or code point (OSSL_PROVIDER_get_capabilities callback; arg is the set). */
static int hybrid_cede_group_cb(const OSSL_PARAM params[], void *arg)
{
    HYBRID_CEDE_SET *set = arg;
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
            cede_set_add(set, hybrid_kem_table[i].hybrid_name);
    return 1;
}

/* Cede any hybrid/composite signature the default provider advertises as a TLS
 * sigalg under the same name, code point or OID (arg is the set). */
static int hybrid_cede_sigalg_cb(const OSSL_PARAM params[], void *arg)
{
    HYBRID_CEDE_SET *set = arg;
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
            cede_set_add(set, r->hybrid_name);
    }
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const COMPOSITE_SIG_INFO *r = &composite_sig_table[i];

        if ((cp != 0 && (unsigned int)r->tls_codepoint == cp)
                || (nm != NULL && strcmp(nm, r->name) == 0)
                || (oid != NULL && r->oid != NULL && strcmp(oid, r->oid) == 0))
            cede_set_add(set, r->name);
    }
#endif
    return 1;
}

/* Cede every algorithm the default provider resolves by a direct fetch (KEM by
 * name; signature by name, else by OID) — catching those it serves without a
 * TLS capability (e.g. a KEM with no group, or a certificate-only signature). */
static void hybrid_cede_by_fetch(OSSL_LIB_CTX *libctx, HYBRID_CEDE_SET *set)
{
    size_t i;

    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        EVP_KEM *k = EVP_KEM_fetch(libctx, hybrid_kem_table[i].hybrid_name,
                                   "provider=default");

        if (k != NULL)
            cede_set_add(set, hybrid_kem_table[i].hybrid_name);
        EVP_KEM_free(k);
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *r = &hybrid_sig_table[i];
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(libctx, r->hybrid_name,
                                               "provider=default");

        if (s == NULL && r->oid != NULL)
            s = EVP_SIGNATURE_fetch(libctx, r->oid, "provider=default");
        if (s != NULL)
            cede_set_add(set, r->hybrid_name);
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
            cede_set_add(set, r->name);
        EVP_SIGNATURE_free(s);
    }
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++) {
        const COMPOSITE_KEM_INFO *r = &composite_kem_table[i];
        EVP_KEM *k = EVP_KEM_fetch(libctx, r->name, "provider=default");

        if (k == NULL && r->oid != NULL)
            k = EVP_KEM_fetch(libctx, r->oid, "provider=default");
        if (k != NULL)
            cede_set_add(set, r->name);
        EVP_KEM_free(k);
    }
#endif
}

/* Heap copy of `src` minus every entry in the withdrawal set (names are single,
 * non-aliased tokens in our tables, so strcmp is exact). NULL on OOM. */
static OSSL_ALGORITHM *hybrid_filter_algs(const HYBRID_CEDE_SET *set,
                                          const OSSL_ALGORITHM *src)
{
    size_t count = 0, i, j = 0;
    OSSL_ALGORITHM *out;

    while (src[count].algorithm_names != NULL)
        count++;
    if ((out = OPENSSL_malloc((count + 1) * sizeof(*out))) == NULL)
        return NULL;
    for (i = 0; i < count; i++)
        if (!cede_set_has(set, src[i].algorithm_names))
            out[j++] = src[i];
    out[j] = src[count];   /* the {NULL,...} terminator */
    return out;
}

#ifdef HYBRID_COMPOSITE
/*
 * Withdraw the composite algorithms that require the 3.5 ML-DSA/ML-KEM seed API.
 * The standardized composite tiers serialize the PQ private key AS its seed
 * (draft mandate), which needs OpenSSL 3.5; below that the seed API is absent, so
 * on <3.5 mark every standardized composite signature and every standardized
 * composite ML-KEM (both seed-based, tier STANDARD) as ceded. That leaves the
 * experimental tiers — which serialize the raw private key (present since 3.0) —
 * advertised. Compiles to nothing on >=3.5. Independent of cede-to-default: these
 * are withdrawn because we cannot honor them, not because the default provider
 * serves them.
 */
static void hybrid_withdraw_seedless_composites(HYBRID_CEDE_SET *set)
{
#if !COMPOSITE_SEED_AVAILABLE
    size_t i;

    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        if (composite_sig_table[i].tier == COMPOSITE_TIER_STANDARD)
            cede_set_add(set, composite_sig_table[i].name);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        if (composite_kem_table[i].tier == COMPOSITE_KEM_TIER_STANDARD)
            cede_set_add(set, composite_kem_table[i].name);
#else
    (void)set;
#endif
}
#endif /* HYBRID_COMPOSITE */

/*
 * Compute the withdrawal set for this init into `set`, on the stack. Two
 * independent sources:
 *   1. seed-less composites — always withdrawn below 3.5 (we cannot honor them);
 *   2. cede-to-default — when `cede`, withdraw everything the default provider
 *      already serves in `libctx`, matched by any shared identifier (name, TLS
 *      code point or OID), tracking whatever it offers now (the hybrid KEM
 *      groups) or later (e.g. native composite signatures).
 * Touches NO shared state and holds NO lock: the fetches and capability queries
 * here are calls out of the provider (and could re-enter it), so they must run
 * lock-free. Runs at init, before this provider is active in the store, so they
 * cannot recurse into hybrid_query.
 */
static void hybrid_probe_cede(OSSL_LIB_CTX *libctx, int cede,
                              HYBRID_CEDE_SET *set)
{
    set->n = 0;

#ifdef HYBRID_COMPOSITE
    hybrid_withdraw_seedless_composites(set);
#endif

    if (cede) {
        OSSL_PROVIDER *def = NULL;

        OSSL_PROVIDER_do_all(libctx, hybrid_find_default_cb, &def);
        if (def != NULL) {
            /* Probing pushes "unable to fetch" errors for absent identifiers; a
             * miss is the expected case, so keep them off the error stack. */
            ERR_set_mark();
            hybrid_cede_by_fetch(libctx, set);
            (void)OSSL_PROVIDER_get_capabilities(def, "TLS-GROUP",
                                                 hybrid_cede_group_cb, set);
            (void)OSSL_PROVIDER_get_capabilities(def, "TLS-SIGALG",
                                                 hybrid_cede_sigalg_cb, set);
            ERR_pop_to_mark();
        }
    }
}

/*
 * Compute this instance's withdrawal set and, if non-empty, build its
 * per-provctx cede tables. Probing runs lock-free (it calls out of the provider)
 * into a stack-local set; the results are then written into `ctx`, which no
 * other thread can observe until init returns. Runs once per init, so the cede
 * decision is re-evaluated per libctx + lever. Returns 0 only on allocation
 * failure; the caller's error path (hybrid_teardown) frees any partial state.
 */
static int hybrid_apply_cede(HYBRID_PROV_CTX *ctx, int cede)
{
    HYBRID_CEDE_SET set;
    size_t i;

    hybrid_probe_cede(ctx->libctx, cede, &set);
    if (set.n == 0)
        return 1;               /* nothing withdrawn: serve the static tables */

    ctx->ceded = OPENSSL_malloc(set.n * sizeof(*ctx->ceded));
    if (ctx->ceded == NULL)
        return 0;
    for (i = 0; i < set.n; i++)
        ctx->ceded[i] = set.names[i];
    ctx->n_ceded = set.n;

    ctx->keymgmts_rt = hybrid_filter_algs(&set, hybrid_keymgmts);
    ctx->kems_rt = hybrid_filter_algs(&set, hybrid_kems);
    ctx->signatures_rt = hybrid_filter_algs(&set, hybrid_signatures);
    ctx->encoders_rt = hybrid_filter_algs(&set, hybrid_encoders);
    ctx->decoders_rt = hybrid_filter_algs(&set, hybrid_decoders);
    if (ctx->keymgmts_rt == NULL || ctx->kems_rt == NULL
            || ctx->signatures_rt == NULL || ctx->encoders_rt == NULL
            || ctx->decoders_rt == NULL)
        return 0;
    ctx->filter_enabled = 1;
    return 1;
}

/*
 * Return the algorithm table for an operation. The tables are fully populated
 * before this can ever run: the static tables are compile-time constants and the
 * per-provctx filtered tables are built by hybrid_apply_cede() during
 * OSSL_provider_init, BEFORE *provctx is handed back — so the core cannot consult
 * this callback until the answer is complete. We therefore never return an
 * empty/partial result that OpenSSL would cache and thereby disable us for the
 * process (issue #47), and it is safe to leave *no_cache = 0 (let the core cache
 * the fetch — the narrow, legitimate opposite of the blanket no_cache tax
 * discussed in the performance write-up).
 */
static const OSSL_ALGORITHM *
hybrid_query(void *provctx, int operation_id, int *no_cache)
{
    HYBRID_PROV_CTX *ctx = provctx;
    int filtered = (ctx != NULL && ctx->filter_enabled);

    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return filtered ? ctx->keymgmts_rt : hybrid_keymgmts;
    case OSSL_OP_KEM:
        return filtered ? ctx->kems_rt : hybrid_kems;
    case OSSL_OP_SIGNATURE:
        return filtered ? ctx->signatures_rt : hybrid_signatures;
    case OSSL_OP_ENCODER:
        return filtered ? ctx->encoders_rt : hybrid_encoders;
    case OSSL_OP_DECODER:
        return filtered ? ctx->decoders_rt : hybrid_decoders;
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

    /* Environment variable overrides the config key when set. Then apply
     * withdrawals: the seed-less composites (always, below 3.5) and — when
     * enabled — everything the default provider already serves in this context. */
    cede_to_default = hybrid_parse_bool(getenv(HYBRID_ENV_CEDE_TO_DEFAULT),
                                        cede_to_default);
    /* Compute this instance's cede tables before returning *provctx. */
    if (!hybrid_apply_cede(ctx, cede_to_default))
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
        {   /* composite signatures: register OID<->name for the rows we serve.
             * Skip rows with no OID, and — below 3.5, where the standardized tier
             * is not served (no seed API) — skip the standardized rows too. */
            size_t ci;

            for (ci = 0; ci < COMPOSITE_SIG_ALG_COUNT; ci++) {
                const COMPOSITE_SIG_INFO *cin = &composite_sig_table[ci];

                if (cin->oid == NULL)
                    continue;
                if (!COMPOSITE_SEED_AVAILABLE
                        && cin->tier == COMPOSITE_TIER_STANDARD)
                    continue;
                (void)c_obj_create(handle, cin->oid, cin->name, cin->name);
                (void)c_obj_add_sigid(handle, cin->name, "", cin->name);
            }
        }
        {   /* composite ML-KEM: register the OID<->name mapping only (a KEM is
             * not a signature, so no add_sigid). Lets the X.509 / CLI layers map
             * a composite-KEM SPKI OID back to the algorithm name. Skip the
             * standardized (seed-based) rows below 3.5, where they are not
             * served; the experimental raw-private rows are registered always. */
            size_t ki;

            for (ki = 0; ki < COMPOSITE_KEM_ALG_COUNT; ki++) {
                const COMPOSITE_KEM_INFO *kin = &composite_kem_table[ki];

                if (!COMPOSITE_SEED_AVAILABLE
                        && kin->tier == COMPOSITE_KEM_TIER_STANDARD)
                    continue;
                (void)c_obj_create(handle, kin->oid, kin->name, kin->name);
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
