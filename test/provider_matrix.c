/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Cross-provider interoperability + performance matrix.
 *
 * Loads the OpenSSL default provider alongside every other provider on the
 * module path that can serve the same PQ primitives -- wolfProvider
 * (libwolfprov), mldsa-native-provider (mldsanative), oqsprovider -- plus the
 * hybrid provider, and:
 *
 *   A. prints which providers loaded and what they serve;
 *   B. proves interop, using OpenSSL's automatic cross-provider key
 *      export/import: a key generated (or a signature made, or a ciphertext
 *      produced) under one provider is verified / decapsulated under every
 *      other provider and the result must match. Covered:
 *        - ML-DSA sign x verify across all providers (same key, every pair);
 *        - ML-KEM encaps/decaps across all providers (shared secret equality);
 *        - hybrid-KEM wire compatibility: the hybrid provider's composed
 *          X25519MLKEM768/... decapsulated by the default and wolfProvider
 *          native MLX groups, and vice versa.
 *   C. performance:
 *        - C1 "naked" PQ primitives side by side: every provider that serves a
 *          given ML-DSA / ML-KEM variant, keygen/sign/verify or
 *          keygen/encaps/decaps;
 *        - C2 hybrid & composite figures, with the PQ component sourced from each
 *          provider in turn (config-driven pq-propquery; classical half pinned
 *          to the default provider so only the PQ source varies);
 *        - C3 composed algorithm: the hybrid provider's composition next to any
 *          other provider that serves the SAME name natively. On OpenSSL >=3.5
 *          oqsprovider lands here -- it cedes the standardized ML-KEM/ML-DSA to
 *          the default provider but still serves the exotic hybrids the hybrid
 *          provider composes (p384_mlkem768, p256_mldsa44, ...).
 *
 * Nothing is hardcoded to a single provider: the provider set is discovered on
 * the module path, the algorithm inventory comes from the provider's own
 * tables, and every row is probed and skipped if the running mix cannot serve
 * it. budget_ms (argv[1], default 200) is the per-op timing budget.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include "../hybrid_prov.h"
#ifdef HYBRID_COMPOSITE
# include "../composite_prov.h"
# include "../composite_kem_prov.h"
#endif
#include "bench_util.h"

static double g_budget_ms = 200.0;
static const char *g_module_dir = ".";

/* Candidate component providers, by the name they are LOADED under (which is
 * what a "provider=NAME" property query matches). hybrid is handled separately. */
typedef struct {
    const char *load;   /* load name: config section / OSSL_PROVIDER_load / .so  */
    const char *query;  /* the value a "provider=" property query must use --    */
                        /* NOT always the load name: wolfProvider hardcodes      */
                        /* provider=wolfprov on its algorithms (module is        */
                        /* libwolfprov.so), so the two genuinely differ.         */
    const char *disp;   /* human label for the report                           */
    const char *module; /* module file (NULL for the built-in default)          */
    int         native_mlx; /* implements the standardized IETF MLX groups as    */
                        /* first-class native groups (default, wolfProvider) --  */
                        /* the peers B3 compares the hybrid composition against.  */
                        /* NOT oqsprovider: its hybrids are its own construction  */
                        /* and hybrid<->oqs interop is covered by hybrid_oqs_test.*/
    int         serves_kem;
    int         serves_sig;
    int         loaded;
} PROV;

static PROV provs[] = {
    { "default",     "default",     "default (OpenSSL master)", NULL,             1, 0, 0, 0 },
    { "libwolfprov", "wolfprov",    "wolfProvider",             "libwolfprov.so", 1, 0, 0, 0 },
    { "mldsanative", "mldsanative", "mldsa-native-provider",    "mldsanative.so", 0, 0, 0, 0 },
    { "oqsprovider", "oqsprovider", "oqsprovider",              "oqsprovider.so", 0, 0, 0, 0 },
};
#define NPROV (sizeof(provs) / sizeof(provs[0]))

static int module_exists(const char *file)
{
    char path[1024];

    if (file == NULL)
        return 1;               /* built-in default */
    snprintf(path, sizeof(path), "%s/%s", g_module_dir, file);
    return access(path, R_OK) == 0;
}

/*
 * Write an openssl.cnf that activates the default provider, the hybrid provider
 * (with its PQ component steered to pq_source and its classical component pinned
 * to the default provider), and every other candidate module present on the
 * path. A fresh libctx loaded from this cnf has all providers coexisting.
 */
static OSSL_LIB_CTX *make_libctx(const char *pq_source)
{
    char cnf[] = "/tmp/provmatrix.XXXXXX";
    int fd = mkstemp(cnf);
    FILE *f;
    OSSL_LIB_CTX *libctx = NULL;
    size_t i;

    if (fd < 0)
        return NULL;
    close(fd);
    if ((f = fopen(cnf, "w")) == NULL) {
        remove(cnf);
        return NULL;
    }
    fprintf(f, "openssl_conf = c\n[c]\nproviders = p\n[p]\n");
    fprintf(f, "default = s_default\nhybrid = s_hybrid\n");
    for (i = 1; i < NPROV; i++)          /* skip default (index 0) */
        if (provs[i].loaded)
            fprintf(f, "%s = s_%s\n", provs[i].load, provs[i].load);
    fprintf(f, "[s_default]\nactivate = 1\n");
    fprintf(f, "[s_hybrid]\nmodule = %s/hybrid.so\nactivate = 1\n",
            g_module_dir);
    if (pq_source != NULL)
        fprintf(f, "pq-propquery = provider=%s\nclassic-propquery = provider=default\n",
                pq_source);
    for (i = 1; i < NPROV; i++)
        if (provs[i].loaded)
            fprintf(f, "[s_%s]\nmodule = %s/%s\nactivate = 1\n",
                    provs[i].load, g_module_dir, provs[i].module);
    fclose(f);

    if ((libctx = OSSL_LIB_CTX_new()) == NULL
            || !OSSL_LIB_CTX_load_config(libctx, cnf)) {
        OSSL_LIB_CTX_free(libctx);
        libctx = NULL;
    }
    remove(cnf);
    return libctx;
}

/* Can `libctx` serve `name` from provider `load` (via a keygen probe)? */
static int serves(OSSL_LIB_CTX *libctx, const char *name, const char *load)
{
    char propq[64];
    EVP_PKEY_CTX *c;
    int ok;

    snprintf(propq, sizeof(propq), "provider=%s", load);
    c = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
    ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;
    EVP_PKEY_CTX_free(c);
    if (!ok)
        ERR_clear_error();
    return ok;
}

/* Minimum per-op keygen latency (ms) over the budget; -1.0 if unavailable. */
static double time_keygen(OSSL_LIB_CTX *libctx, const char *name,
                          const char *propq)
{
    double best = -1.0, tend = bench_now_ms() + g_budget_ms;

    do {
        double t0 = bench_now_ms(), dt;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(libctx, name, propq);
        EVP_PKEY *k = NULL;

        if (c == NULL || EVP_PKEY_keygen_init(c) <= 0
                || EVP_PKEY_keygen(c, &k) <= 0) {
            EVP_PKEY_free(k);
            EVP_PKEY_CTX_free(c);
            ERR_clear_error();
            return -1.0;
        }
        dt = bench_now_ms() - t0;
        EVP_PKEY_free(k);
        EVP_PKEY_CTX_free(c);
        if (best < 0.0 || dt < best)
            best = dt;
    } while (bench_now_ms() < tend);
    return best;
}

/* ---- distinct PQ-primitive inventory, collected from the provider tables ---- */

static const char *kem_pq[8];
static size_t n_kem_pq;
static const char *sig_pq[8];
static size_t n_sig_pq;

static void add_uniq(const char **arr, size_t *n, size_t cap, const char *v)
{
    size_t i;

    if (v == NULL)
        return;
    for (i = 0; i < *n; i++)
        if (strcmp(arr[i], v) == 0)
            return;
    if (*n < cap)
        arr[(*n)++] = v;
}

static void collect_pq_inventory(void)
{
    /*
     * The naked side-by-side uses the full standardized parameter sets under
     * their canonical names: FIPS-203 ML-KEM {512,768,1024} and FIPS-204 ML-DSA
     * {44,65,87}. These are exactly the PQ components the hybrid/composite tables
     * compose with (those tables also carry the "MLKEM512" TLS alias for the
     * mlkem512 hybrids, which resolves to the same key type). Any provider that
     * does not serve a given variant is simply skipped per row.
     */
    add_uniq(kem_pq, &n_kem_pq, 8, "ML-KEM-512");
    add_uniq(kem_pq, &n_kem_pq, 8, "ML-KEM-768");
    add_uniq(kem_pq, &n_kem_pq, 8, "ML-KEM-1024");
    add_uniq(sig_pq, &n_sig_pq, 8, "ML-DSA-44");
    add_uniq(sig_pq, &n_sig_pq, 8, "ML-DSA-65");
    add_uniq(sig_pq, &n_sig_pq, 8, "ML-DSA-87");
}

/*
 * The name a provider actually registers a canonical variant under can differ:
 * oqsprovider below OpenSSL 3.5 serves ML-KEM as "mlkem512/768/1024" with no
 * canonical "ML-KEM-*" alias (its ML-DSA does carry the "ML-DSA-*" alias, so
 * signatures need no mapping). Return the name `query`'s provider serves this
 * canonical variant under -- the canonical name, else the oqs-style alias --
 * or NULL if it serves neither.
 */
static const char *kem_served_name(OSSL_LIB_CTX *libctx, const char *canon,
                                   const char *query)
{
    static const struct { const char *canon, *alt; } alias[] = {
        { "ML-KEM-512", "mlkem512" },
        { "ML-KEM-768", "mlkem768" },
        { "ML-KEM-1024", "mlkem1024" },
    };
    size_t i;

    if (serves(libctx, canon, query))
        return canon;
    for (i = 0; i < sizeof(alias) / sizeof(alias[0]); i++)
        if (strcmp(alias[i].canon, canon) == 0
                && serves(libctx, alias[i].alt, query))
            return alias[i].alt;
    return NULL;
}

/* =========================== B. interoperability =========================== */

static int interop_failures;

static const unsigned char interop_msg[] =
    "provider-matrix cross-provider interop message";
#define INTEROP_MSG_LEN (sizeof(interop_msg) - 1)

/* Pure-ML-DSA sign of interop_msg under propq; caller frees *sig. */
static int mldsa_sign(OSSL_LIB_CTX *libctx, EVP_PKEY *key, const char *propq,
                      unsigned char **sig, size_t *siglen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = 0;

    if (m != NULL
            && EVP_DigestSignInit_ex(m, NULL, NULL, libctx, propq, key, NULL) > 0
            && EVP_DigestSign(m, NULL, siglen, interop_msg, INTEROP_MSG_LEN) > 0
            && (*sig = OPENSSL_malloc(*siglen)) != NULL
            && EVP_DigestSign(m, *sig, siglen, interop_msg, INTEROP_MSG_LEN) > 0)
        ok = 1;
    EVP_MD_CTX_free(m);
    if (!ok)
        ERR_clear_error();
    return ok;
}

static void interop_mldsa(OSSL_LIB_CTX *libctx)
{
    size_t v, s, r;

    printf("\n[B1] ML-DSA cross-provider sign x verify "
           "(key+signature from the row provider, verified by the column)\n");
    for (v = 0; v < n_sig_pq; v++) {
        int any = 0;

        printf("  %s\n", sig_pq[v]);
        printf("    %-26s", "sign \\ verify");
        for (r = 0; r < NPROV; r++)
            if (provs[r].loaded && serves(libctx, sig_pq[v], provs[r].query))
                printf(" %-13s", provs[r].query);
        printf("\n");
        for (s = 0; s < NPROV; s++) {
            EVP_PKEY *key;
            unsigned char *sig = NULL;
            size_t siglen = 0;
            char propq[64];

            if (!provs[s].loaded || !serves(libctx, sig_pq[v], provs[s].query))
                continue;
            any = 1;
            snprintf(propq, sizeof(propq), "provider=%s", provs[s].query);
            key = bench_gen_key(libctx, sig_pq[v], propq);
            if (key == NULL || !mldsa_sign(libctx, key, propq, &sig, &siglen)) {
                printf("    %-26s (sign failed)\n", provs[s].query);
                EVP_PKEY_free(key);
                OPENSSL_free(sig);
                interop_failures++;
                continue;
            }
            printf("    %-26s", provs[s].query);
            for (r = 0; r < NPROV; r++) {
                EVP_MD_CTX *mctx;
                char vpropq[64];
                int ok;

                if (!provs[r].loaded || !serves(libctx, sig_pq[v], provs[r].query))
                    continue;
                snprintf(vpropq, sizeof(vpropq), "provider=%s", provs[r].query);
                mctx = EVP_MD_CTX_new();
                ok = mctx != NULL
                     && EVP_DigestVerifyInit_ex(mctx, NULL, NULL, libctx,
                                                vpropq, key, NULL) > 0
                     && EVP_DigestVerify(mctx, sig, siglen,
                                         interop_msg, INTEROP_MSG_LEN) > 0;
                EVP_MD_CTX_free(mctx);
                printf(" %-13s", ok ? "OK" : "FAIL");
                if (!ok)
                    interop_failures++;
                ERR_clear_error();
            }
            printf("\n");
            EVP_PKEY_free(key);
            OPENSSL_free(sig);
        }
        if (!any)
            printf("    (no provider serves this variant)\n");
    }
}

static void interop_mlkem(OSSL_LIB_CTX *libctx)
{
    size_t v, s, d;

    printf("\n[B2] ML-KEM cross-provider encaps/decaps "
           "(key+ciphertext from the row provider, decapsulated by the column; "
           "cell = shared-secret match)\n");
    for (v = 0; v < n_kem_pq; v++) {
        int any = 0;

        printf("  %s\n", kem_pq[v]);
        printf("    %-26s", "encaps \\ decaps");
        for (d = 0; d < NPROV; d++)
            if (provs[d].loaded
                    && kem_served_name(libctx, kem_pq[v], provs[d].query) != NULL)
                printf(" %-13s", provs[d].query);
        printf("\n");
        for (s = 0; s < NPROV; s++) {
            EVP_PKEY *key;
            EVP_PKEY_CTX *ectx;
            unsigned char *ct = NULL, *ss_e = NULL;
            size_t ctlen = 0, sslen = 0;
            char propq[64];
            const char *sn;

            if (!provs[s].loaded
                    || (sn = kem_served_name(libctx, kem_pq[v], provs[s].query))
                           == NULL)
                continue;
            any = 1;
            snprintf(propq, sizeof(propq), "provider=%s", provs[s].query);
            key = bench_gen_key(libctx, sn, propq);
            ectx = key ? EVP_PKEY_CTX_new_from_pkey(libctx, key, propq) : NULL;
            if (ectx == NULL || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0
                    || EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &sslen) <= 0
                    || (ct = OPENSSL_malloc(ctlen)) == NULL
                    || (ss_e = OPENSSL_malloc(sslen)) == NULL
                    || EVP_PKEY_encapsulate(ectx, ct, &ctlen, ss_e, &sslen) <= 0) {
                printf("    %-26s (encaps failed)\n", provs[s].query);
                interop_failures++;
                goto next;
            }
            printf("    %-26s", provs[s].query);
            for (d = 0; d < NPROV; d++) {
                EVP_PKEY_CTX *dctx;
                unsigned char *ss_d = NULL;
                size_t dlen = sslen;
                char dpropq[64];
                int ok = 0;

                if (!provs[d].loaded
                        || kem_served_name(libctx, kem_pq[v], provs[d].query)
                               == NULL)
                    continue;
                snprintf(dpropq, sizeof(dpropq), "provider=%s", provs[d].query);
                dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, dpropq);
                ss_d = OPENSSL_malloc(sslen);
                if (dctx != NULL && ss_d != NULL
                        && EVP_PKEY_decapsulate_init(dctx, NULL) > 0
                        && EVP_PKEY_decapsulate(dctx, ss_d, &dlen, ct, ctlen) > 0)
                    ok = dlen == sslen && memcmp(ss_d, ss_e, sslen) == 0;
                printf(" %-13s", ok ? "OK" : "FAIL");
                if (!ok)
                    interop_failures++;
                OPENSSL_free(ss_d);
                EVP_PKEY_CTX_free(dctx);
                ERR_clear_error();
            }
            printf("\n");
next:
            OPENSSL_free(ct);
            OPENSSL_free(ss_e);
            EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(key);
        }
        if (!any)
            printf("    (no provider serves this variant)\n");
    }
}

/*
 * Export a key's raw public bytes. The native MLX and hybrid keys expose this
 * as OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY (the concatenated wire form); it is
 * re-imported below via OSSL_PKEY_PARAM_PUB_KEY (fromdata). Caller frees.
 */
static int export_pub(EVP_PKEY *k, unsigned char **buf, size_t *len)
{
    if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        NULL, 0, len) != 1
            || (*buf = OPENSSL_malloc(*len)) == NULL)
        return 0;
    return EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                           *buf, *len, len) == 1;
}

/*
 * Import raw public bytes as `name` under `propq` (public-only key). Providers
 * disagree on the fromdata key for a composed public key: the native MLX and
 * hybrid keymgmts take OSSL_PKEY_PARAM_PUB_KEY, while oqsprovider's hybrids take
 * OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY. Try both so the import works whichever
 * provider owns `name`.
 */
static EVP_PKEY *import_pub(OSSL_LIB_CTX *ctx, const char *name,
                            const char *propq, const unsigned char *buf,
                            size_t len)
{
    static const char *keys[] = { OSSL_PKEY_PARAM_PUB_KEY,
                                  OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY };
    size_t i;

    for (i = 0; i < 2; i++) {
        EVP_PKEY_CTX *ic = EVP_PKEY_CTX_new_from_name(ctx, name, propq);
        EVP_PKEY *k = NULL;
        OSSL_PARAM params[2];

        params[0] = OSSL_PARAM_construct_octet_string((char *)keys[i],
                                                      (void *)buf, len);
        params[1] = OSSL_PARAM_construct_end();
        if (ic != NULL && EVP_PKEY_fromdata_init(ic) > 0
                && EVP_PKEY_fromdata(ic, &k, EVP_PKEY_PUBLIC_KEY, params) > 0) {
            EVP_PKEY_CTX_free(ic);
            return k;
        }
        EVP_PKEY_CTX_free(ic);
        EVP_PKEY_free(k);
        ERR_clear_error();
    }
    return NULL;
}

static int do_encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *pub, const char *propq,
                     unsigned char **ct, size_t *ctlen,
                     unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *e = EVP_PKEY_CTX_new_from_pkey(ctx, pub, propq);
    int ok = 0;

    if (e != NULL && EVP_PKEY_encapsulate_init(e, NULL) > 0
            && EVP_PKEY_encapsulate(e, NULL, ctlen, NULL, sslen) > 0
            && (*ct = OPENSSL_malloc(*ctlen)) != NULL
            && (*ss = OPENSSL_malloc(*sslen)) != NULL
            && EVP_PKEY_encapsulate(e, *ct, ctlen, *ss, sslen) > 0)
        ok = 1;
    EVP_PKEY_CTX_free(e);
    if (!ok)
        ERR_clear_error();
    return ok;
}

static int do_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *priv, const char *propq,
                     const unsigned char *ct, size_t ctlen,
                     unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *d = EVP_PKEY_CTX_new_from_pkey(ctx, priv, propq);
    size_t cap = 0;
    int ok = 0;

    if (d != NULL && EVP_PKEY_decapsulate_init(d, NULL) > 0
            && EVP_PKEY_decapsulate(d, NULL, &cap, ct, ctlen) > 0
            && (*ss = OPENSSL_malloc(cap)) != NULL) {
        *sslen = cap;
        if (EVP_PKEY_decapsulate(d, *ss, sslen, ct, ctlen) > 0)
            ok = 1;
    }
    EVP_PKEY_CTX_free(d);
    if (!ok)
        ERR_clear_error();
    return ok;
}

/*
 * Wire-compat one way: export the public key of `src` (a full keypair under
 * src_propq), import it into the `peer` provider, encapsulate there, then
 * decapsulate with the original `src` private key. Returns 1 iff the two shared
 * secrets match. This is the canonical export/import interop path (same as
 * hybrid_test), robust for the EC-based SecP* hybrids where relying on an
 * implicit single-object cross-provider switch is not.
 */
static int wire_compat(OSSL_LIB_CTX *ctx, const char *name, EVP_PKEY *src,
                       const char *src_propq, const char *peer_propq)
{
    unsigned char *pub = NULL, *ct = NULL, *ss_p = NULL, *ss_s = NULL;
    size_t publen = 0, ctlen = 0, ssplen = 0, sslen = 0;
    EVP_PKEY *peer = NULL;
    int ok = 0;

    if (!export_pub(src, &pub, &publen)
            || (peer = import_pub(ctx, name, peer_propq, pub, publen)) == NULL)
        goto end;
    if (!do_encaps(ctx, peer, peer_propq, &ct, &ctlen, &ss_p, &ssplen))
        goto end;
    if (!do_decaps(ctx, src, src_propq, ct, ctlen, &ss_s, &sslen))
        goto end;
    ok = sslen == ssplen && memcmp(ss_s, ss_p, sslen) == 0;
end:
    OPENSSL_free(pub);
    OPENSSL_free(ct);
    OPENSSL_free(ss_p);
    OPENSSL_free(ss_s);
    EVP_PKEY_free(peer);
    ERR_clear_error();
    return ok;
}

/*
 * Hybrid-KEM wire compatibility: for every hybrid KEM the hybrid provider and a
 * native peer (default and/or wolfProvider) both serve, the hybrid provider's
 * composed key must interoperate with the native MLX group both ways -- the
 * drop-in-for-the-native-hybrid proof, now across providers. Uses explicit
 * public-key export/import (see wire_compat).
 */
static void interop_hybrid_kem(OSSL_LIB_CTX *libctx)
{
    size_t i, p;

    printf("\n[B3] Hybrid-KEM wire compatibility: hybrid-provider composition "
           "vs native MLX, via public-key export/import (shared-secret match)\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *name = hybrid_kem_table[i].hybrid_name;
        EVP_PKEY *hkey;
        int printed = 0;

        if (!serves(libctx, name, "hybrid"))
            continue;
        hkey = bench_gen_key(libctx, name, "provider=hybrid");
        if (hkey == NULL) {
            ERR_clear_error();
            continue;
        }
        for (p = 0; p < NPROV; p++) {
            char npropq[64];
            EVP_PKEY *nkey;
            int a, b;

            /*
             * Only compare against providers that implement the SAME
             * standardized IETF MLX groups natively (default, wolfProvider).
             * oqsprovider's hybrids are its own construction (and it serves
             * standalone ML-KEM only below 3.5, so serves_kem is not a stable
             * discriminator across versions); hybrid<->oqs interop is covered
             * by hybrid_oqs_test, and its timings appear in C3.
             */
            if (!provs[p].loaded || !provs[p].native_mlx
                    || !serves(libctx, name, provs[p].query))
                continue;
            snprintf(npropq, sizeof(npropq), "provider=%s", provs[p].query);
            /* A: native encapsulates to the hybrid-composed key; hybrid decaps */
            a = wire_compat(libctx, name, hkey, "provider=hybrid", npropq);
            /* B: hybrid encapsulates to a native-generated key; native decaps  */
            nkey = bench_gen_key(libctx, name, npropq);
            b = nkey != NULL
                && wire_compat(libctx, name, nkey, npropq, "provider=hybrid");
            EVP_PKEY_free(nkey);
            if (!printed) {
                printf("  %-20s", name);
                printed = 1;
            }
            printf("  vs %s: native-encaps/hybrid-decaps=%s "
                   "hybrid-encaps/native-decaps=%s", provs[p].query,
                   a ? "OK" : "FAIL", b ? "OK" : "FAIL");
            if (!a || !b)
                interop_failures++;
        }
        if (printed)
            printf("\n");
        EVP_PKEY_free(hkey);
    }
}

/* =========================== C. performance =========================== */

static void perf_naked(OSSL_LIB_CTX *libctx)
{
    size_t v, p;

    printf("\n[C1] Naked PQ primitives, per provider (min per-op latency, ms; "
           "budget %.0f ms)\n", g_budget_ms);

    printf("  -- ML-DSA (keygen / sign / verify) --\n");
    for (v = 0; v < n_sig_pq; v++) {
        printf("  %s\n", sig_pq[v]);
        for (p = 0; p < NPROV; p++) {
            char propq[64];
            EVP_PKEY *key;
            unsigned char *sig = NULL;
            size_t siglen = 0;
            double kg, sg, vf;

            if (!provs[p].loaded || !serves(libctx, sig_pq[v], provs[p].query))
                continue;
            snprintf(propq, sizeof(propq), "provider=%s", provs[p].query);
            kg = time_keygen(libctx, sig_pq[v], propq);
            key = bench_gen_key(libctx, sig_pq[v], propq);
            sg = vf = -1.0;
            if (key != NULL
                    && bench_make_sig(libctx, key, NULL, propq, &sig, &siglen)) {
                sg = bench_time_sign(libctx, key, NULL, propq);
                vf = bench_time_verify(libctx, key, NULL, propq, sig, siglen);
            }
            printf("    %-26s keygen %8.4f  sign %8.4f  verify %8.4f\n",
                   provs[p].disp, kg, sg, vf);
            OPENSSL_free(sig);
            EVP_PKEY_free(key);
        }
    }

    printf("  -- ML-KEM (keygen / encaps / decaps) --\n");
    for (v = 0; v < n_kem_pq; v++) {
        printf("  %s\n", kem_pq[v]);
        for (p = 0; p < NPROV; p++) {
            char propq[64];
            EVP_PKEY *key;
            double kg, en, de;
            const char *fn = kem_served_name(libctx, kem_pq[v], provs[p].query);

            if (!provs[p].loaded || fn == NULL)
                continue;
            snprintf(propq, sizeof(propq), "provider=%s", provs[p].query);
            kg = time_keygen(libctx, fn, propq);
            key = bench_gen_key(libctx, fn, propq);
            en = key ? bench_time_kem_encaps(libctx, key, propq) : -1.0;
            de = key ? bench_time_kem_decaps(libctx, key, propq) : -1.0;
            printf("    %-26s keygen %8.4f  encaps %8.4f  decaps %8.4f\n",
                   provs[p].disp, kg, en, de);
            EVP_PKEY_free(key);
        }
    }
}

/* One timed KEM row for `name` under provider `query`; prints if served. */
static void perf_kem_row(OSSL_LIB_CTX *libctx, const char *name,
                         const char *query, const char *label)
{
    char propq[64];
    EVP_PKEY *key;
    double kg, en, de;

    if (!serves(libctx, name, query))
        return;
    snprintf(propq, sizeof(propq), "provider=%s", query);
    kg = time_keygen(libctx, name, propq);
    if ((key = bench_gen_key(libctx, name, propq)) == NULL) {
        ERR_clear_error();
        return;
    }
    en = bench_time_kem_encaps(libctx, key, propq);
    de = bench_time_kem_decaps(libctx, key, propq);
    printf("    %-34s %-26s keygen %8.4f  encaps %8.4f  decaps %8.4f\n",
           name, label, kg, en, de);
    EVP_PKEY_free(key);
}

/* One timed signature row for `name` under provider `query`; prints if served. */
static void perf_sig_row(OSSL_LIB_CTX *libctx, const char *name,
                         const char *query, const char *label)
{
    char propq[64];
    EVP_PKEY *key;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    double kg, sg = -1.0, vf = -1.0;

    if (!serves(libctx, name, query))
        return;
    snprintf(propq, sizeof(propq), "provider=%s", query);
    kg = time_keygen(libctx, name, propq);
    if ((key = bench_gen_key(libctx, name, propq)) == NULL) {
        ERR_clear_error();
        return;
    }
    if (bench_make_sig(libctx, key, NULL, propq, &sig, &siglen)) {
        sg = bench_time_sign(libctx, key, NULL, propq);
        vf = bench_time_verify(libctx, key, NULL, propq, sig, siglen);
    }
    printf("    %-34s %-26s keygen %8.4f  sign   %8.4f  verify %8.4f\n",
           name, label, kg, sg, vf);
    OPENSSL_free(sig);
    EVP_PKEY_free(key);
}

/* Is `name` served natively by at least one non-hybrid provider here? */
static int has_native_peer(OSSL_LIB_CTX *libctx, const char *name)
{
    size_t p;

    for (p = 0; p < NPROV; p++)
        if (provs[p].loaded && serves(libctx, name, provs[p].query))
            return 1;
    return 0;
}

/*
 * C3: for every composed algorithm the hybrid provider serves AND at least one
 * other provider serves natively under the same name, print the hybrid
 * provider's composition next to each native implementation. On OpenSSL >=3.5
 * this is where oqsprovider contributes: it cedes the standardized ML-KEM/ML-DSA
 * to the default provider but still serves the exotic hybrids (p384_mlkem768,
 * x448_mlkem768, p256_mldsa44, ...) that the hybrid provider also composes, so
 * the two implementations of the same name sit side by side.
 */
static void perf_native_peers(OSSL_LIB_CTX *libctx)
{
    size_t i, p;

    printf("\n[C3] Composed algorithm: hybrid-provider composition vs native "
           "peer providers (min per-op latency, ms; budget %.0f ms)\n",
           g_budget_ms);

    printf("  -- hybrid KEMs --\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *name = hybrid_kem_table[i].hybrid_name;

        if (!serves(libctx, name, "hybrid") || !has_native_peer(libctx, name))
            continue;
        perf_kem_row(libctx, name, "hybrid", "hybrid-provider");
        for (p = 0; p < NPROV; p++)
            if (provs[p].loaded)
                perf_kem_row(libctx, name, provs[p].query, provs[p].disp);
    }

    printf("  -- hybrid signatures --\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *name = hybrid_sig_table[i].hybrid_name;

        if (!serves(libctx, name, "hybrid") || !has_native_peer(libctx, name))
            continue;
        perf_sig_row(libctx, name, "hybrid", "hybrid-provider");
        for (p = 0; p < NPROV; p++)
            if (provs[p].loaded)
                perf_sig_row(libctx, name, provs[p].query, provs[p].disp);
    }
}

/* Time one composed KEM/sig under provider=hybrid; prints a row if available. */
static void perf_one_composed_kem(OSSL_LIB_CTX *libctx, const char *name,
                                  const char *src_disp)
{
    EVP_PKEY *key;
    double kg, en, de;

    if (!serves(libctx, name, "hybrid"))
        return;
    kg = time_keygen(libctx, name, "provider=hybrid");
    key = bench_gen_key(libctx, name, "provider=hybrid");
    if (key == NULL) {
        ERR_clear_error();
        return;
    }
    en = bench_time_kem_encaps(libctx, key, "provider=hybrid");
    de = bench_time_kem_decaps(libctx, key, "provider=hybrid");
    printf("    %-34s PQ=%-24s keygen %8.4f  encaps %8.4f  decaps %8.4f\n",
           name, src_disp, kg, en, de);
    EVP_PKEY_free(key);
}

static void perf_one_composed_sig(OSSL_LIB_CTX *libctx, const char *name,
                                  const char *src_disp)
{
    EVP_PKEY *key;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    double kg, sg = -1.0, vf = -1.0;

    if (!serves(libctx, name, "hybrid"))
        return;
    kg = time_keygen(libctx, name, "provider=hybrid");
    key = bench_gen_key(libctx, name, "provider=hybrid");
    if (key == NULL) {
        ERR_clear_error();
        return;
    }
    if (bench_make_sig(libctx, key, NULL, "provider=hybrid", &sig, &siglen)) {
        sg = bench_time_sign(libctx, key, NULL, "provider=hybrid");
        vf = bench_time_verify(libctx, key, NULL, "provider=hybrid", sig, siglen);
    }
    printf("    %-34s PQ=%-24s keygen %8.4f  sign   %8.4f  verify %8.4f\n",
           name, src_disp, kg, sg, vf);
    OPENSSL_free(sig);
    EVP_PKEY_free(key);
}

/*
 * Hybrid & composite performance with the PQ component sourced from each
 * provider in turn. Each source gets its own libctx whose hybrid provider is
 * configured pq-propquery=provider=<source> (classical pinned to default), so
 * the only thing that varies between rows of the same algorithm is which
 * provider computes the PQ half.
 */
static void perf_composed(void)
{
    size_t p, i;

    printf("\n[C2] Hybrid & composite performance, PQ component per provider "
           "(min per-op latency, ms; budget %.0f ms)\n", g_budget_ms);

    printf("  -- hybrid KEMs --\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *name = hybrid_kem_table[i].hybrid_name;

        for (p = 0; p < NPROV; p++) {
            OSSL_LIB_CTX *lc;

            if (!provs[p].loaded || !provs[p].serves_kem)
                continue;
            if ((lc = make_libctx(provs[p].query)) == NULL)
                continue;
            perf_one_composed_kem(lc, name, provs[p].disp);
            OSSL_LIB_CTX_free(lc);
        }
    }

    printf("  -- hybrid signatures --\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        const char *name = hybrid_sig_table[i].hybrid_name;

        for (p = 0; p < NPROV; p++) {
            OSSL_LIB_CTX *lc;

            if (!provs[p].loaded || !provs[p].serves_sig)
                continue;
            if ((lc = make_libctx(provs[p].query)) == NULL)
                continue;
            perf_one_composed_sig(lc, name, provs[p].disp);
            OSSL_LIB_CTX_free(lc);
        }
    }

#ifdef HYBRID_COMPOSITE
    printf("  -- composite signatures --\n");
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        const char *name = composite_sig_table[i].name;

        for (p = 0; p < NPROV; p++) {
            OSSL_LIB_CTX *lc;

            if (!provs[p].loaded || !provs[p].serves_sig)
                continue;
            if ((lc = make_libctx(provs[p].query)) == NULL)
                continue;
            perf_one_composed_sig(lc, name, provs[p].disp);
            OSSL_LIB_CTX_free(lc);
        }
    }

    printf("  -- composite KEMs --\n");
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++) {
        const char *name = composite_kem_table[i].name;

        for (p = 0; p < NPROV; p++) {
            OSSL_LIB_CTX *lc;

            if (!provs[p].loaded || !provs[p].serves_kem)
                continue;
            if ((lc = make_libctx(provs[p].query)) == NULL)
                continue;
            perf_one_composed_kem(lc, name, provs[p].disp);
            OSSL_LIB_CTX_free(lc);
        }
    }
#endif
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *base;
    size_t i, v;

    if (argc > 1 && atof(argv[1]) > 0.0)
        g_budget_ms = atof(argv[1]);
    bench_set_budget_ms(g_budget_ms);
    if (getenv("OPENSSL_MODULES") != NULL)
        g_module_dir = getenv("OPENSSL_MODULES");

    /* Keep the hybrid provider serving its own MLX groups (do not cede them to
     * the default provider) so the hybrid-vs-native interop in B3 has both
     * sides to compare. */
    setenv("HYBRID_CEDE_TO_DEFAULT", "0", 1);

    /* Discover which candidate modules are present before building any cnf. */
    for (i = 1; i < NPROV; i++)
        provs[i].loaded = module_exists(provs[i].module);
    provs[0].loaded = 1;        /* built-in default */

    collect_pq_inventory();

    base = make_libctx(NULL);   /* baseline: hybrid PQ from default */
    if (base == NULL) {
        fprintf(stderr, "failed to build base libctx (module path = %s)\n",
                g_module_dir);
        return 1;
    }

    /* Confirm each candidate actually loaded + record what it serves. */
    printf("Cross-provider interop + performance matrix\n");
    printf("OpenSSL %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("Module path: %s\n", g_module_dir);
    printf("Providers:\n");
    for (i = 0; i < NPROV; i++) {
        int avail = provs[i].loaded
                    && OSSL_PROVIDER_available(base, provs[i].load);

        provs[i].loaded = avail;
        if (!avail)
            continue;
        for (v = 0; v < n_kem_pq && !provs[i].serves_kem; v++)
            provs[i].serves_kem =
                kem_served_name(base, kem_pq[v], provs[i].query) != NULL;
        for (v = 0; v < n_sig_pq && !provs[i].serves_sig; v++)
            provs[i].serves_sig = serves(base, sig_pq[v], provs[i].query);
        printf("  %-26s loaded  [%s%s%s]\n", provs[i].disp,
               provs[i].serves_sig ? "ML-DSA " : "",
               provs[i].serves_kem ? "ML-KEM" : "",
               (!provs[i].serves_sig && !provs[i].serves_kem)
                   ? "no standalone ML-KEM/ML-DSA; composed-only (see C3)" : "");
    }
    printf("  %-26s %s\n", "hybrid-provider",
           OSSL_PROVIDER_available(base, "hybrid") ? "loaded" : "NOT LOADED");

    /* B. interop */
    interop_mldsa(base);
    interop_mlkem(base);
    interop_hybrid_kem(base);

    /* C. performance */
    perf_naked(base);
    perf_native_peers(base);
    OSSL_LIB_CTX_free(base);
    perf_composed();

    printf("\n===========================================================\n");
    if (interop_failures == 0)
        printf("INTEROP: all cross-provider checks passed.\n");
    else
        printf("INTEROP: %d cross-provider check(s) FAILED.\n", interop_failures);
    return interop_failures == 0 ? 0 : 1;
}
