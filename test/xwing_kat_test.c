/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * X-Wing KEM KAT interop test (issue #110) — the real cross-implementation
 * check for the provider's first non-concatenation combiner. It DECAPSULATES
 * the reference ciphertexts from draft-connolly-cfrg-xwing-kem under the draft's
 * own decapsulation keys and asserts the 32-byte shared secret equals the
 * draft's — proving our strongly-binding combiner is byte-compatible with the
 * reference across the whole construction (ML-KEM-768 decapsulation, the X25519
 * shared secret, the slot split of the concatenated ciphertext, and the SHA3-256
 * combiner input order ss_M || ss_X || ct_X || pk_X || XWingLabel), since
 * decapsulation recomputes the secret from ciphertext bytes we did not produce.
 * Self-consistent encap/decap within one provider cannot establish that.
 *
 * Two vendored oracles feed this (both distilled from the draft, see their
 * regen scripts):
 *   - test/xwing_kat.txt       the upstream vectors verbatim (sk pk ct ss), a
 *                              pure mirror guarded buildlessly by
 *                              scripts/check-xwing-kat-drift.sh;
 *   - test/xwing_kat_keys.txt  the EXPANDED decapsulation key per vector
 *                              (ML-KEM-768 dk || X25519 scalar), derived offline
 *                              by test/regen_xwing_kat_keys.py.
 *
 * Because the expanded key is vendored, the test raw-imports it (no seed API)
 * and therefore runs wherever ML-KEM-768 resolves — oqsprovider on 3.0-3.4, the
 * default provider on 3.5+ — i.e. whenever X-Wing itself is available, not only
 * on 3.5+. When the default provider's ML-KEM seed API IS present (3.5+) the test
 * additionally re-derives each key from its seed and asserts it equals the
 * vendored blob, so xwing_kat_keys.txt cannot silently rot (XWING_HAVE_SEED_API).
 *
 * If ML-KEM-768 cannot be resolved at all (neither default-native nor
 * oqsprovider), X-Wing is unavailable and the whole suite SKIPs rather than
 * fails — mirroring the other cross-provider blocks.
 *
 * Scope: this file is ONLY the draft KAT — decapsulate the published vectors.
 * That is X-Wing-specific by nature (vectors exist only for the one standardized
 * X25519+ML-KEM-768 instantiation), so its constants hardcode those components;
 * see the note at the #defines. The generic property that every served KEM —
 * incl. the experimental X-Wing-style component pairs — simply round-trips in
 * this provider is already covered, table-driven, by hybrid_leakcheck_test
 * (keygen/encaps/decaps with shared-secret match over the whole inventory); it is
 * not duplicated here.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "hybrid_prov.h"   /* HYBRID_XWING_SS_LEN + hybrid_kem_sizes[] cross-check */

/*
 * The constants below hardcode X-Wing's exact components (ML-KEM-768 + X25519).
 * That is deliberate and confined to the KAT path: the reference vectors exist
 * ONLY for the draft's one standardized instantiation, and the key/ciphertext
 * byte layout is inherently component-specific. There is nothing to generalize
 * here: no other component pair has published vectors. The *component-agnostic*
 * side of X-Wing is tested separately by hybrid_leakcheck_test, which drives
 * every X-Wing-combiner row (incl. the experimental non-draft pairs) purely
 * through provider-reported sizes and hardcodes none of this.
 *
 * X-Wing component sizes (draft §4): ML-KEM-768 dk + X25519 scalar, slot 0 =
 * ML-KEM first in the hybrid private-key blob (matches HYBRID_KEM_LIST).
 */
#define MLKEM768_PRV   2400
#define X25519_PRV       32
#define XWING_PRV_BLOB (MLKEM768_PRV + X25519_PRV)
#define MLKEM768_CT    1088
#define XWING_SEED_LEN   32                                /* sk */
/* X-Wing shared-secret length: HYBRID_XWING_SS_LEN from hybrid_prov.h (shared
 * with the combiner implementation), not re-defined here. */

#ifdef XWING_HAVE_SEED_API
/* X-Wing decapsulation-key expansion (draft §5.2, expandDecapsulationKey):
 * SHAKE-256(sk) -> ML-KEM-768 (d||z) seed, then the X25519 scalar. Used only for
 * the 3.5+ coherence self-check of the vendored xwing_kat_keys.txt. */
# define MLKEM768_SEED_LEN  64                              /* d || z */
# define XWING_EXPANDED_LEN (MLKEM768_SEED_LEN + X25519_PRV)/* = 96 */
#endif

static int tests, passed, failed, skipped;

static unsigned char *hexdec(const char *h, size_t *outlen)
{
    size_t L = strlen(h), i;
    unsigned char *b;

    if (L % 2 != 0 || (b = OPENSSL_malloc(L / 2)) == NULL)
        return NULL;
    for (i = 0; i < L / 2; i++) {
        unsigned v;

        if (sscanf(h + 2 * i, "%2x", &v) != 1) {
            OPENSSL_free(b);
            return NULL;
        }
        b[i] = (unsigned char)v;
    }
    *outlen = L / 2;
    return b;
}

#ifdef XWING_HAVE_SEED_API
/* SHAKE-256(in, outlen) — the X-Wing decapsulation-key expansion XOF. */
static int shake256(OSSL_LIB_CTX *ctx, const unsigned char *in, size_t inlen,
                    unsigned char *out, size_t outlen)
{
    EVP_MD *md = EVP_MD_fetch(ctx, "SHAKE256", NULL);
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = md != NULL && m != NULL
             && EVP_DigestInit_ex(m, md, NULL) > 0
             && EVP_DigestUpdate(m, in, inlen) > 0
             && EVP_DigestFinalXOF(m, out, outlen) > 0;

    EVP_MD_CTX_free(m);
    EVP_MD_free(md);
    return ok;
}

/* Build an ML-KEM-768 key from its 64-byte (d||z) seed via the default
 * provider, then export the 2400-byte decapsulation key. Returns 0 if seed
 * import is unsupported (leaves *out untouched). */
static int mlkem768_dk_from_seed(OSSL_LIB_CTX *ctx, const unsigned char *seed64,
                                 unsigned char *out, size_t outcap, size_t *outlen)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(ctx, "ML-KEM-768",
                                                    "provider=default");
    EVP_PKEY *pk = NULL;
    OSSL_PARAM params[2];
    int ok = 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED,
                                                  (void *)seed64, MLKEM768_SEED_LEN);
    params[1] = OSSL_PARAM_construct_end();
    if (pctx == NULL
            || EVP_PKEY_fromdata_init(pctx) <= 0
            || EVP_PKEY_fromdata(pctx, &pk, EVP_PKEY_KEYPAIR, params) <= 0)
        goto end;
    ok = EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PRIV_KEY,
                                         out, outcap, outlen) > 0;
end:
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(pctx);
    ERR_clear_error();
    return ok;
}

/* 3.5+ self-check: re-derive the expanded blob from the seed and confirm the
 * vendored xwing_kat_keys.txt entry matches, so it cannot silently go stale.
 * Returns 1 ok, 0 mismatch; skips quietly if seed import is unavailable. */
static int coherence_ok(OSSL_LIB_CTX *ctx, const unsigned char *sk, size_t sklen,
                        const unsigned char *blob, size_t bloblen)
{
    unsigned char expanded[XWING_EXPANDED_LEN], dk[MLKEM768_PRV];
    size_t dklen = 0;
    int ok = 1;

    if (sklen != XWING_SEED_LEN || bloblen != XWING_PRV_BLOB)
        return 0;
    if (!shake256(ctx, sk, sklen, expanded, sizeof(expanded)))
        return 0;
    if (!mlkem768_dk_from_seed(ctx, expanded, dk, sizeof(dk), &dklen)
            || dklen != MLKEM768_PRV)
        return 1;   /* no seed import here — trust the vendored blob */
    ok = memcmp(dk, blob, MLKEM768_PRV) == 0
         && memcmp(expanded + MLKEM768_SEED_LEN, blob + MLKEM768_PRV,
                   X25519_PRV) == 0;
    OPENSSL_cleanse(expanded, sizeof(expanded));
    OPENSSL_cleanse(dk, sizeof(dk));
    return ok;
}
#endif /* XWING_HAVE_SEED_API */

static void check(OSSL_LIB_CTX *ctx, const char *skh, const char *pkh,
                  const char *cth, const char *ssh, const char *blobh)
{
    unsigned char *sk = NULL, *pk = NULL, *ct = NULL, *ss = NULL, *blob = NULL;
    unsigned char *out = NULL;
    size_t sklen = 0, pklen = 0, ctlen = 0, sslen = 0, bloblen = 0, outlen = 0;
    EVP_PKEY_CTX *fc = NULL, *dc = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];

    tests++;
    printf("X-Wing vector ... ");

    sk = hexdec(skh, &sklen);
    pk = hexdec(pkh, &pklen);
    ct = hexdec(cth, &ctlen);
    ss = hexdec(ssh, &sslen);
    blob = blobh != NULL ? hexdec(blobh, &bloblen) : NULL;
    if (sk == NULL || pk == NULL || ct == NULL || ss == NULL || blob == NULL
            || sklen != XWING_SEED_LEN || sslen != HYBRID_XWING_SS_LEN
            || ctlen != MLKEM768_CT + X25519_PRV || bloblen != XWING_PRV_BLOB) {
        printf("FAIL (bad vector or missing expanded key — "
               "regenerate test/xwing_kat_keys.txt)\n");
        failed++;
        goto done;
    }

#ifdef XWING_HAVE_SEED_API
    if (!coherence_ok(ctx, sk, sklen, blob, bloblen)) {
        printf("FAIL (xwing_kat_keys.txt disagrees with the seed — "
               "regenerate test/xwing_kat_keys.txt)\n");
        failed++;
        goto done;
    }
#endif

    /* Import the draft's decapsulation key directly: hybrid X-Wing private blob,
     * slot order [ML-KEM dk | X25519 scalar]. Raw import, so no seed API. */
    fc = EVP_PKEY_CTX_new_from_name(ctx, "X-Wing", "provider=hybrid");
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                  blob, bloblen);
    params[1] = OSSL_PARAM_construct_end();
    if (fc == NULL
            || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &key, EVP_PKEY_KEYPAIR, params) <= 0) {
        printf("FAIL (import X-Wing key)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }

    dc = EVP_PKEY_CTX_new_from_pkey(ctx, key, "provider=hybrid");
    if (dc == NULL
            || EVP_PKEY_decapsulate_init(dc, NULL) <= 0
            || EVP_PKEY_decapsulate(dc, NULL, &outlen, ct, ctlen) <= 0
            || outlen != HYBRID_XWING_SS_LEN
            || (out = OPENSSL_malloc(outlen)) == NULL
            || EVP_PKEY_decapsulate(dc, out, &outlen, ct, ctlen) <= 0) {
        printf("FAIL (decapsulate)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }

    if (outlen != sslen || memcmp(out, ss, sslen) != 0) {
        printf("FAIL (shared secret mismatch vs reference)\n");
        failed++;
        goto done;
    }

    /*
     * Also import the reference public (encapsulation) key and confirm the
     * combiner-aware size query: X-Wing reports a 32-byte shared secret (not the
     * 64-byte component concatenation) and the 1120-byte ciphertext. This
     * exercises the public-key import path and the reported sizes using bytes
     * from the draft, not ones we produced.
     */
    {
        EVP_PKEY_CTX *pfc = EVP_PKEY_CTX_new_from_name(ctx, "X-Wing",
                                                       "provider=hybrid");
        EVP_PKEY *pub = NULL;
        EVP_PKEY_CTX *ec = NULL;
        OSSL_PARAM pp[2];
        size_t qct = 0, qss = 0;
        int ok;

        pp[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  pk, pklen);
        pp[1] = OSSL_PARAM_construct_end();
        ok = pfc != NULL
             && EVP_PKEY_fromdata_init(pfc) > 0
             && EVP_PKEY_fromdata(pfc, &pub, EVP_PKEY_PUBLIC_KEY, pp) > 0
             && (ec = EVP_PKEY_CTX_new_from_pkey(ctx, pub, "provider=hybrid")) != NULL
             && EVP_PKEY_encapsulate_init(ec, NULL) > 0
             && EVP_PKEY_encapsulate(ec, NULL, &qct, NULL, &qss) > 0
             && qct == ctlen && qss == HYBRID_XWING_SS_LEN;
        EVP_PKEY_CTX_free(ec);
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(pfc);
        if (!ok) {
            printf("FAIL (public-key import / size query)\n");
            ERR_print_errors_fp(stdout);
            failed++;
            goto done;
        }
    }

    printf("PASS\n");
    passed++;

done:
    OPENSSL_clear_free(out, outlen);
    OPENSSL_free(sk);
    OPENSSL_free(pk);
    OPENSSL_free(ct);
    OPENSSL_free(ss);
    OPENSSL_clear_free(blob, bloblen);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(fc);
    EVP_PKEY_CTX_free(dc);
}

/* Can X-Wing resolve its ML-KEM-768 component here? Probe with a keygen through
 * the hybrid provider: success proves both halves resolve (default-native or
 * oqsprovider). If not, X-Wing is unavailable and the KAT SKIPs. */
static int xwing_available(OSSL_LIB_CTX *ctx)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, "X-Wing", "provider=hybrid");
    EVP_PKEY *k = NULL;
    int ok = c != NULL
             && EVP_PKEY_keygen_init(c) > 0
             && EVP_PKEY_generate(c, &k) > 0;

    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

/* Load the expanded-key oracle: fill sks[i]/blobs[i] with the hex columns of
 * test/xwing_kat_keys.txt. Returns the number of rows, or -1 on open error. */
static int load_keys(const char *path, char **sks, char **blobs, int max)
{
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int i = 0;

    if (f == NULL)
        return -1;
    while (i < max && (n = getline(&line, &cap, f)) > 0) {
        char *save, *skh, *blobh;

        if (line[0] == '#' || line[0] == '\n')
            continue;
        skh = strtok_r(line, " \t\r\n", &save);
        blobh = strtok_r(NULL, " \t\r\n", &save);
        if (skh != NULL && blobh != NULL) {
            sks[i] = OPENSSL_strdup(skh);
            blobs[i] = OPENSSL_strdup(blobh);
            i++;
        }
    }
    free(line);
    fclose(f);
    return i;
}

/* Expanded private blob for the vector whose seed is skh, or NULL if absent. */
static const char *blob_for(const char *skh, char **sks, char **blobs, int nkeys)
{
    for (int i = 0; i < nkeys; i++)
        if (strcmp(skh, sks[i]) == 0)
            return blobs[i];
    return NULL;
}

#define MAX_VECTORS 64

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    const char *katfile = argc > 1 ? argv[1] : "xwing_kat.txt";
    const char *keyfile = argc > 2 ? argv[2] : "xwing_kat_keys.txt";
    char *sks[MAX_VECTORS], *blobs[MAX_VECTORS];
    int nkeys, i;
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    /* oqsprovider is optional: it supplies ML-KEM-768 below 3.5. Ignore load
     * failure (default-native ML-KEM covers 3.5+). */
    (void)OSSL_PROVIDER_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("X-Wing KAT interop vs draft-connolly-cfrg-xwing-kem-11 reference vectors\n");
    printf("======================================================================\n");

    /* If X-Wing's ML-KEM-768 half cannot be resolved, the algorithm is simply
     * not available here — skip, do not fail. */
    if (!xwing_available(ctx)) {
        printf("SKIP (X-Wing unavailable: no ML-KEM-768 from default or oqsprovider)\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }

    /* The reconstruction #defines above must be compile-time constants, so they
     * can't be read from the central size table directly — but they must not
     * silently diverge from it. Tie them together: the authoritative X-Wing
     * component sizes are hybrid_kem_sizes[xwing], which hybrid_sizes_test
     * re-derives from live keygens. If they disagree, one side changed without
     * the other. */
    {
        const HYBRID_SIZES *xw = &hybrid_kem_sizes[HYBRID_KEM_IDX_xwing];

        if (MLKEM768_PRV != xw->a2_prv || MLKEM768_CT != xw->a2_ct
                || X25519_PRV != xw->a1_prv) {
            fprintf(stderr, "KAT size constants disagree with "
                            "hybrid_kem_sizes[xwing] — update them together\n");
            return 1;
        }
    }

    nkeys = load_keys(keyfile, sks, blobs, MAX_VECTORS);
    if (nkeys < 0) {
        fprintf(stderr, "cannot open expanded-key oracle: %s\n", keyfile);
        return 1;
    }

    if ((f = fopen(katfile, "r")) == NULL) {
        fprintf(stderr, "cannot open KAT file: %s\n", katfile);
        return 1;
    }
    while ((n = getline(&line, &cap, f)) > 0) {
        char *save, *skh, *pkh, *cth, *ssh;

        if (line[0] == '#' || line[0] == '\n')
            continue;
        skh = strtok_r(line, " \t\r\n", &save);
        pkh = strtok_r(NULL, " \t\r\n", &save);
        cth = strtok_r(NULL, " \t\r\n", &save);
        ssh = strtok_r(NULL, " \t\r\n", &save);
        if (skh && pkh && cth && ssh)
            check(ctx, skh, pkh, cth, ssh, blob_for(skh, sks, blobs, nkeys));
    }
    free(line);
    fclose(f);

    for (i = 0; i < nkeys; i++) {
        OPENSSL_free(sks[i]);
        OPENSSL_free(blobs[i]);
    }

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
