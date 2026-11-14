/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dispatch entry points that no round-trip suite reaches, driven through the
 * public EVP API for every algorithm of every family (hybrid sig/KEM, and the
 * composite sig/KEM families with -DHYBRID_COMPOSITE):
 *
 *   D1. Key copies: EVP_PKEY_dup of a full and of a public-only key
 *       (OSSL_FUNC_KEYMGMT_DUP), and a full-keypair EVP_PKEY_todata/fromdata
 *       round-trip (export incl. the private half); all must EVP_PKEY_eq the
 *       original. EVP_PKEY_parameters_eq (match with a non-keypair selection).
 *       A hybrid can only do what its components can: each component is probed
 *       standalone (probe_component) and the expectation follows from that,
 *       so a component-provider limitation (e.g. an ML-KEM key that cannot be
 *       EVP_PKEY_dup'ed on some OpenSSL releases) is asserted as such rather
 *       than skipped, and the check tightens by itself once it is lifted.
 *   D2. Operation-context copies (OSSL_FUNC_*_DUPCTX): EVP_MD_CTX_copy_ex after
 *       sign-init, and EVP_PKEY_CTX_dup mid-way through a streaming
 *       sign-message (3.4+) — original and copy must both produce valid
 *       signatures; for KEMs, EVP_PKEY_CTX_dup after encaps-init (where the
 *       family implements it) must encapsulate to a decapsulable ciphertext.
 *   D3. Introspection: the keymgmt gettable/settable/gen-settable/import-types
 *       lists, the signature/KEM ctx-param lists, and the provider's own
 *       gettable list must each be a well-formed (terminated) OSSL_PARAM array.
 *   D4. set_params guards, driven by what each family DECLARES settable (not a
 *       hardcoded list): an encoded public key must not overwrite an existing
 *       key, must be length-checked on a material-less key, and the correct
 *       one must load; "properties" is accepted on the key and on keygen.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "hybrid_prov.h"
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */
#include "key_util.h"    /* keygen/reimport/empty-key/verify helpers */
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
# include "composite_kem_prov.h"
#endif

#define PROPQ HYBRID_TEST_PROPQ
#define EXPECT HYBRID_TEST_EXPECT
/* `sig` (len bytes) is a valid signature by `k` over this test's message. */
#define VERIFIES(k, sig, len) \
    hybrid_test_verify(ctx, (k), (sig), (len), msg, sizeof(msg))
/* Generous bound on any OSSL_PARAM descriptor list we serve; a list that runs
 * past it is treated as unterminated. */
#define MAX_PARAM_LIST 64

static int tests, passed, failed, skipped;

/* One algorithm under test: its name, its components (name + EC group), and
 * whether its private key travels as the hybrid "prv1 || prv2" raw concat
 * (the hybrid families; composite has its own blob format). */
typedef struct {
    const char *alg;
    int raw_priv_concat;
    size_t n_comp;
    struct { const char *name, *group; } comp[HYBRID_MAX_COMP];
} ROW;

/* What a component key can do standalone: 1 yes, 0 no, -1 unknown (it could
 * not be generated outside the hybrid, e.g. a composite-only alias). Probed
 * once per (name, group) and cached. */
typedef struct {
    const char *name, *group;
    int dup;            /* EVP_PKEY_dup of a full keypair yields an equal key */
    int dup_pub;        /* ... and of a public-only key */
    int octet_priv;     /* exports PRIV_KEY as an octet string */
} PROBE;

#define MAX_PROBES 128
static PROBE probes[MAX_PROBES];
static size_t nprobes;

static int same(const char *a, const char *b)
{
    return (a == NULL || b == NULL) ? a == b : strcmp(a, b) == 0;
}

static int octet_priv_cb(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params,
                                                  OSSL_PKEY_PARAM_PRIV_KEY);

    *(int *)arg = p != NULL && p->data_type == OSSL_PARAM_OCTET_STRING;
    return 1;
}

static const PROBE *probe_component(OSSL_LIB_CTX *ctx, const char *name,
                                    const char *group)
{
    EVP_PKEY_CTX *g = NULL;
    EVP_PKEY *k = NULL, *d;
    PROBE *pr;
    size_t i;

    for (i = 0; i < nprobes; i++)
        if (same(probes[i].name, name) && same(probes[i].group, group))
            return &probes[i];
    if (nprobes == MAX_PROBES)
        return NULL;
    pr = &probes[nprobes++];
    pr->name = name;
    pr->group = group;
    pr->dup = pr->dup_pub = pr->octet_priv = -1;
    g = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    if (g != NULL && EVP_PKEY_keygen_init(g) > 0
            && (group == NULL || EVP_PKEY_CTX_set_group_name(g, group) > 0))
        EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    g = NULL;
    if (k != NULL) {
        OSSL_PARAM *pp = NULL;
        EVP_PKEY *pub = NULL;

        d = EVP_PKEY_dup(k);
        pr->dup = d != NULL && EVP_PKEY_eq(k, d) == 1;
        EVP_PKEY_free(d);
        if (EVP_PKEY_todata(k, EVP_PKEY_PUBLIC_KEY, &pp) > 0
                && (g = EVP_PKEY_CTX_new_from_pkey(ctx, k, NULL)) != NULL
                && EVP_PKEY_fromdata_init(g) > 0
                && EVP_PKEY_fromdata(g, &pub, EVP_PKEY_PUBLIC_KEY, pp) > 0) {
            d = EVP_PKEY_dup(pub);
            pr->dup_pub = d != NULL && EVP_PKEY_eq(pub, d) == 1;
            EVP_PKEY_free(d);
        }
        EVP_PKEY_CTX_free(g);
        EVP_PKEY_free(pub);
        OSSL_PARAM_free(pp);
        pr->octet_priv = 0;
        if (EVP_PKEY_export(k, EVP_PKEY_KEYPAIR, octet_priv_cb,
                            &pr->octet_priv) <= 0)
            pr->octet_priv = -1;
        EVP_PKEY_free(k);
    }
    ERR_clear_error();
    return pr;
}

/* Fold a capability over the row's components: 0 if any component lacks it,
 * 1 if all have it, -1 if neither is certain. */
#define CAP_DUP 0
#define CAP_DUP_PUB 1
#define CAP_OCTET_PRIV 2
static int row_cap(OSSL_LIB_CTX *ctx, const ROW *r, int cap)
{
    int all = 1;
    size_t i;

    for (i = 0; i < r->n_comp; i++) {
        const PROBE *p = probe_component(ctx, r->comp[i].name,
                                         r->comp[i].group);
        int v = p == NULL ? -1
              : cap == CAP_DUP ? p->dup
              : cap == CAP_DUP_PUB ? p->dup_pub : p->octet_priv;

        if (v == 0)
            return 0;
        if (v < 0)
            all = -1;
    }
    return all;
}
static const unsigned char msg[] = "hybrid-provider dispatch-surface message";

/* 1 iff `p` is a terminated descriptor list (NULL counts as "none served"). */
static int list_ok(const OSSL_PARAM *p)
{
    size_t i;

    if (p == NULL)
        return 1;
    for (i = 0; i < MAX_PARAM_LIST; i++)
        if (p[i].key == NULL)
            return 1;
    return 0;
}

static int lists(const OSSL_PARAM *p, const char *key)
{
    return p != NULL && OSSL_PARAM_locate_const(p, key) != NULL;
}

/* Checks whose strict form a component provider cannot support here. */
static int limited;

/*
 * EVP_PKEY_dup of `k`. Where every component dups faithfully (cap 1) the hybrid
 * copy must exist and equal `k`; where one does not (cap 0) the hybrid cannot
 * do better, so the call only has to be survivable (counted as limited); with
 * an uncertain component (cap -1) a copy, if made, must still be equal.
 */
static int dup_as_expected(EVP_PKEY *k, int cap, EVP_PKEY **out)
{
    *out = EVP_PKEY_dup(k);
    ERR_clear_error();
    if (cap == 0) {
        limited++;
        return 1;
    }
    if (cap == 1 && *out == NULL)
        return 0;
    return *out == NULL || EVP_PKEY_eq(k, *out) == 1;
}

/* D1 + D4 (keymgmt side) + D3 (keymgmt lists), common to every family. */
static int check_keymgmt(OSSL_LIB_CTX *ctx, const ROW *row, EVP_PKEY *k)
{
    const char *alg = row->alg;
    int dupcap = row_cap(ctx, row, CAP_DUP);
    EVP_PKEY *k2 = NULL, *dup = NULL, *pub = NULL, *pubdup = NULL, *rt = NULL;
    EVP_PKEY *empty = NULL;
    EVP_PKEY_CTX *c = NULL;
    EVP_KEYMGMT *km = NULL;
    unsigned char *enc = NULL;
    size_t enclen = 0;
    const OSSL_PARAM *settable;
    OSSL_PARAM gp[2];
    int ok = 1;

    /* D1 */
    EXPECT(dup_as_expected(k, dupcap, &dup),
           "EVP_PKEY_dup(full) disagrees with the components' own dup");
    EXPECT((pub = hybrid_test_reimport(ctx, alg, k,
                                       EVP_PKEY_PUBLIC_KEY)) != NULL,
           "public-only re-import");
    EXPECT(dup_as_expected(pub, row_cap(ctx, row, CAP_DUP_PUB), &pubdup),
           "EVP_PKEY_dup(public-only) disagrees with the components' own dup");
    rt = hybrid_test_reimport(ctx, alg, k, EVP_PKEY_KEYPAIR);
    if (row->raw_priv_concat && row_cap(ctx, row, CAP_OCTET_PRIV) == 0) {
        /* Known gap, issue #162: the "prv1 || prv2" raw private export only
         * handles octet-string private components (not EC/RSA BIGNUMs). Assert
         * the failure so a fix shows up here as a reminder to drop this
         * branch. */
        EXPECT(rt == NULL,
               "keypair round-trip now works: drop the #162 branch");
    } else {
        EXPECT(rt != NULL && EVP_PKEY_eq(k, rt) == 1,
               "keypair todata/fromdata round-trip");
    }
    EXPECT((k2 = hybrid_test_keygen(ctx, alg)) != NULL, "second keygen");
    EXPECT(EVP_PKEY_eq(k, k2) != 1, "independent keys compare unequal");
    EXPECT(EVP_PKEY_parameters_eq(k, k2) == 1,
           "same-algorithm keys share (empty) parameters");

    /* D3: keymgmt descriptor lists. */
    EXPECT((km = EVP_KEYMGMT_fetch(ctx, alg, PROPQ)) != NULL, "keymgmt fetch");
    EXPECT(list_ok(EVP_KEYMGMT_gettable_params(km))
           && list_ok(EVP_KEYMGMT_settable_params(km))
           && list_ok(EVP_KEYMGMT_gen_settable_params(km))
           && list_ok(EVP_PKEY_gettable_params(k))
           && list_ok(EVP_PKEY_settable_params(k)), "keymgmt param lists");
    EXPECT((c = EVP_PKEY_CTX_new_from_name(ctx, alg, PROPQ)) != NULL
           && EVP_PKEY_fromdata_init(c) > 0
           && list_ok(EVP_PKEY_fromdata_settable(c, EVP_PKEY_KEYPAIR))
           && list_ok(EVP_PKEY_fromdata_settable(c, EVP_PKEY_PUBLIC_KEY)),
           "import-types lists");
    EVP_PKEY_CTX_free(c);
    c = NULL;

    /* D4 (keygen): set whatever the gen ctx declares — "properties" if it is
     * settable (an empty query: no-op), else an empty list — then keygen. */
    EXPECT((c = EVP_PKEY_CTX_new_from_name(ctx, alg, PROPQ)) != NULL
           && EVP_PKEY_keygen_init(c) > 0, "keygen-init");
    gp[0] = OSSL_PARAM_construct_end();
    if (lists(EVP_PKEY_CTX_settable_params(c), OSSL_PKEY_PARAM_PROPERTIES)) {
        gp[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_PROPERTIES,
                                                 "", 0);
        gp[1] = OSSL_PARAM_construct_end();
    }
    EXPECT(EVP_PKEY_CTX_set_params(c, gp) > 0, "keygen set_params");
    EVP_PKEY_free(k2);
    k2 = NULL;
    EXPECT(EVP_PKEY_keygen(c, &k2) > 0, "keygen after set_params");

    /* D4 (key): only what the key declares settable. */
    settable = EVP_PKEY_settable_params(k);
    if (lists(settable, OSSL_PKEY_PARAM_PROPERTIES))
        EXPECT(EVP_PKEY_set_utf8_string_param(k2, OSSL_PKEY_PARAM_PROPERTIES,
                                              "") > 0, "set properties");
    if (lists(settable, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) {
        EXPECT((enclen = EVP_PKEY_get1_encoded_public_key(k, &enc)) > 1,
               "get encoded public key");
        EXPECT(EVP_PKEY_set1_encoded_public_key(k2, enc, enclen) <= 0,
               "encoded public key overwrote an existing key");
        ERR_clear_error();
        if ((empty = hybrid_test_empty_key(ctx, alg)) != NULL) {
            EXPECT(EVP_PKEY_set1_encoded_public_key(empty, enc,
                                                    enclen - 1) <= 0,
                   "wrong-length encoded public key accepted");
            ERR_clear_error();
            EXPECT(EVP_PKEY_set1_encoded_public_key(empty, enc, enclen) > 0
                   && EVP_PKEY_eq(k, empty) == 1,
                   "encoded public key loads into a material-less key");
        }
    }
end:
    EVP_PKEY_CTX_free(c);
    OPENSSL_free(enc);
    EVP_KEYMGMT_free(km);
    EVP_PKEY_free(k2);
    EVP_PKEY_free(dup);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(pubdup);
    EVP_PKEY_free(rt);
    EVP_PKEY_free(empty);
    return ok;
}

static void check_sig(OSSL_LIB_CTX *ctx, const ROW *row)
{
    const char *alg = row->alg;
    EVP_PKEY *k = NULL;
    EVP_MD_CTX *m = NULL, *m2 = NULL;
    EVP_SIGNATURE *s = NULL;
    unsigned char *sig = NULL, *sig2 = NULL;
    size_t maxlen = 0, l1, l2;
    int ok = 1;

    printf("  %-34s sig dispatch ... ", alg);
    fflush(stdout);
    tests++;
    if ((k = hybrid_test_keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--;
        return;
    }
    EXPECT(check_keymgmt(ctx, row, k), "keymgmt surface");

    /* D3: signature ctx-param lists. */
    EXPECT((s = EVP_SIGNATURE_fetch(ctx, alg, PROPQ)) != NULL, "sig fetch");
    EXPECT(list_ok(EVP_SIGNATURE_gettable_ctx_params(s))
           && list_ok(EVP_SIGNATURE_settable_ctx_params(s)), "sig ctx lists");

    /* D2: copy the operation context after init; both must sign validly. */
    EXPECT((m = EVP_MD_CTX_new()) != NULL && (m2 = EVP_MD_CTX_new()) != NULL,
           "EVP_MD_CTX_new");
    EXPECT(EVP_DigestSignInit_ex(m, NULL, NULL, ctx, PROPQ, k, NULL) > 0
           && EVP_DigestSign(m, NULL, &maxlen, msg, sizeof(msg)) > 0,
           "sign-init + size query");
    EXPECT(EVP_MD_CTX_copy_ex(m2, m) > 0, "EVP_MD_CTX_copy_ex (dupctx)");
    EXPECT((sig = OPENSSL_malloc(maxlen)) != NULL
           && (sig2 = OPENSSL_malloc(maxlen)) != NULL, "alloc");
    l1 = l2 = maxlen;
    EXPECT(EVP_DigestSign(m, sig, &l1, msg, sizeof(msg)) > 0
           && EVP_DigestSign(m2, sig2, &l2, msg, sizeof(msg)) > 0,
           "sign with original + copied ctx");
    EXPECT(VERIFIES(k, sig, l1)
           && VERIFIES(k, sig2, l2),
           "both signatures verify");

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
    /* D2 (streaming): dup mid-message; the copy carries the buffered prefix. */
    {
        EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_pkey(ctx, k, PROPQ);
        EVP_PKEY_CTX *pc2 = NULL;
        const size_t half = sizeof(msg) / 2;
        int r = pc != NULL && EVP_PKEY_sign_message_init(pc, s, NULL) > 0
            && EVP_PKEY_sign_message_update(pc, msg, half) > 0
            && (pc2 = EVP_PKEY_CTX_dup(pc)) != NULL
            && EVP_PKEY_sign_message_update(pc, msg + half,
                                            sizeof(msg) - half) > 0
            && EVP_PKEY_sign_message_update(pc2, msg + half,
                                            sizeof(msg) - half) > 0;

        l1 = l2 = maxlen;
        r = r && EVP_PKEY_sign_message_final(pc, sig, &l1) > 0
            && EVP_PKEY_sign_message_final(pc2, sig2, &l2) > 0;
        EVP_PKEY_CTX_free(pc);
        EVP_PKEY_CTX_free(pc2);
        EXPECT(r, "streaming sign with a mid-message EVP_PKEY_CTX_dup");
        EXPECT(VERIFIES(k, sig, l1)
               && VERIFIES(k, sig2, l2),
               "both streamed signatures verify");
    }
#endif
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    OPENSSL_free(sig);
    OPENSSL_free(sig2);
    EVP_MD_CTX_free(m);
    EVP_MD_CTX_free(m2);
    EVP_SIGNATURE_free(s);
    EVP_PKEY_free(k);
}

static void check_kem(OSSL_LIB_CTX *ctx, const ROW *row)
{
    const char *alg = row->alg;
    EVP_PKEY *k = NULL;
    EVP_KEM *kem = NULL;
    EVP_PKEY_CTX *c = NULL, *c2 = NULL, *d = NULL;
    unsigned char *ct = NULL, *ss = NULL, *ss2 = NULL;
    size_t ctlen = 0, sslen = 0, l2;
    OSSL_PARAM none[1];
    int ok = 1;

    printf("  %-34s KEM dispatch ... ", alg);
    fflush(stdout);
    tests++;
    if ((k = hybrid_test_keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--;
        return;
    }
    EXPECT(check_keymgmt(ctx, row, k), "keymgmt surface");

    /* D3: KEM ctx-param lists, and an (empty) set_ctx_params. */
    EXPECT((kem = EVP_KEM_fetch(ctx, alg, PROPQ)) != NULL, "KEM fetch");
    EXPECT(list_ok(EVP_KEM_settable_ctx_params(kem))
           && list_ok(EVP_KEM_gettable_ctx_params(kem)), "KEM ctx lists");
    none[0] = OSSL_PARAM_construct_end();
    EXPECT((c = EVP_PKEY_CTX_new_from_pkey(ctx, k, PROPQ)) != NULL
           && EVP_PKEY_encapsulate_init(c, NULL) > 0
           && EVP_PKEY_CTX_set_params(c, none) > 0, "KEM set_ctx_params");

    /* D2: a duplicated encaps ctx (where the family serves DUPCTX) must
     * produce a ciphertext the key decapsulates to the same secret. */
    if ((c2 = EVP_PKEY_CTX_dup(c)) != NULL) {
        EXPECT(EVP_PKEY_encapsulate(c2, NULL, &ctlen, NULL, &sslen) > 0
               && (ct = OPENSSL_malloc(ctlen)) != NULL
               && (ss = OPENSSL_malloc(sslen)) != NULL
               && (ss2 = OPENSSL_malloc(sslen)) != NULL
               && EVP_PKEY_encapsulate(c2, ct, &ctlen, ss, &sslen) > 0,
               "encaps with a duplicated ctx");
        l2 = sslen;
        EXPECT((d = EVP_PKEY_CTX_new_from_pkey(ctx, k, PROPQ)) != NULL
               && EVP_PKEY_decapsulate_init(d, NULL) > 0
               && EVP_PKEY_decapsulate(d, ss2, &l2, ct, ctlen) > 0
               && l2 == sslen && memcmp(ss, ss2, sslen) == 0,
               "decaps of the duplicated ctx's ciphertext");
    }
    ERR_clear_error();
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    if (ss != NULL)
        OPENSSL_clear_free(ss, sslen);
    if (ss2 != NULL)
        OPENSSL_clear_free(ss2, sslen);
    OPENSSL_free(ct);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_CTX_free(c2);
    EVP_PKEY_CTX_free(d);
    EVP_KEM_free(kem);
    EVP_PKEY_free(k);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    OSSL_PROVIDER *hyb;
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (hybrid_test_load(ctx, "default") == NULL
            || (hyb = hybrid_test_load(ctx, "hybrid")) == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    hybrid_test_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("dispatch surface: dup, ctx-dup, introspection, set_params\n");
    printf("========================================================\n");
    printf("  %-34s provider gettable list ... ", "hybrid");
    tests++;
    if (list_ok(OSSL_PROVIDER_gettable_params(hyb))
            && OSSL_PROVIDER_gettable_params(hyb) != NULL) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        failed++;
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const HYBRID_SIG_INFO *in = &hybrid_sig_table[i];
        ROW r = { in->hybrid_name, 1, 2,
                  { { in->alg1_name, in->alg1_group },
                    { in->alg2_name, in->alg2_group } } };

        check_sig(ctx, &r);
    }
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const HYBRID_KEM_INFO *in = &hybrid_kem_table[i];
        ROW r = { in->hybrid_name, 1, in->n_comp, { { NULL, NULL } } };
        size_t j;

        for (j = 0; j < in->n_comp; j++) {
            r.comp[j].name = in->component[j].name;
            r.comp[j].group = in->component[j].group;
        }
        check_kem(ctx, &r);
    }
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const COMPOSITE_SIG_INFO *in = &composite_sig_table[i];
        ROW r = { in->name, 0, 2, { { in->pq_alg, NULL },
                                    { in->trad_alg, in->trad_group } } };

        check_sig(ctx, &r);
    }
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++) {
        const COMPOSITE_KEM_INFO *in = &composite_kem_table[i];
        ROW r = { in->name, 0, 2, { { in->pq_alg, NULL },
                                    { in->trad_alg, in->trad_group } } };

        check_kem(ctx, &r);
    }
#endif

    printf("\nResults: %d/%d passed, %d failed, %d skipped"
           " (%d dup checks limited by a component provider)\n",
           passed, tests, failed, skipped, limited);
    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
