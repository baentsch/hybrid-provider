/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) KAT interop test (issue #6) — the real draft-19 cross-
 * implementation check against the reference test vectors of
 * draft-ietf-lamps-pq-composite-sigs (lamps-wg/draft-composite-sigs,
 * src/testvectors.json, distilled into test/composite_kat.txt). EVERY field the
 * draft ships is exercised, per vector:
 *
 *   K1. `s` (over m, empty ctx) verifies under the reference `pk`.
 *   K2. `sWithContext` verifies under `pk` with the draft's `ctx`.
 *   K3. ...and the context is bound: `sWithContext` fails without ctx, and `s`
 *       fails with it.
 *   K4. `sk` (raw private key) imports, and its public key equals `pk`.
 *   K5. a fresh signature by `sk` under `ctx` verifies under `pk` (ML-DSA
 *       signing is randomized, so there is no byte-exact signing KAT).
 *   K6. `sk_pkcs8` decodes to the same key: public equals `pk`, and the raw
 *       private export equals `sk` byte-for-byte.
 *   K7. `x5c` decodes, carries `pk`, and its self-signature verifies.
 *
 * Verifying reference signatures proves our combiner byte-compatible with the
 * reference across the whole construction — prefix, per-algorithm label,
 * len(ctx) || ctx, prehash, RSA-PSS params, ML-DSA context, component split and
 * encoding — which self-consistent sign/verify cannot establish.
 *
 * Needs ML-DSA from the default provider (3.5+); self-skips otherwise.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/decoder.h>
#include <openssl/x509.h>
#include "composite_prov.h"   /* composite_sig_table: map KAT name -> PQ component */
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */

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

/* Look up a combo's table row by its registered name. */
static const COMPOSITE_SIG_INFO *find_info(const char *name)
{
    size_t i;

    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        if (strcmp(composite_sig_table[i].name, name) == 0)
            return &composite_sig_table[i];
    return NULL;
}

/*
 * Is this combo's PQ component available? Probed per row from the table
 * (info->pq_alg) rather than hardwired to one ML-DSA level, so the gate tracks
 * whichever PQ algorithms the default provider actually offers (none on 3.4, and
 * correctly distinguishing e.g. ML-DSA-44 vs -65 vs -87 as they land).
 */
static int pq_available(OSSL_LIB_CTX *ctx, const char *pq_alg)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, pq_alg, "provider=default");
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

/* One decoded KAT row (all hex fields of a composite_kat.txt line). */
typedef struct {
    const char *name;
    unsigned char *pk, *s, *sc, *sk, *p8, *crt;
    size_t pklen, slen, sclen, sklen, p8len, crtlen;
} KAT;

#define PROPQ "provider=hybrid"
/* A vector row: name + the FIELDS of regen_composite_kat.py (pk s sWithContext
 * sk sk_pkcs8 x5c). */
#define KAT_COLS 7
#define EXPECT(cond, what)                                                 \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL (%s)\n", what);                                   \
            ERR_print_errors_fp(stdout);                                   \
            ok = 0;                                                        \
            goto end;                                                      \
        }                                                                  \
    } while (0)

/* Init params carrying context string `cs` (NULL: none). */
static const OSSL_PARAM *ctx_params(OSSL_PARAM p[2], const unsigned char *cs,
                                    size_t cslen)
{
    if (cs == NULL)
        return NULL;
    p[0] = OSSL_PARAM_construct_octet_string(
               OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)cs, cslen);
    p[1] = OSSL_PARAM_construct_end();
    return p;
}

/* 1 iff `sig` verifies over msg under `key` with context string `cs`. */
static int verifies(OSSL_LIB_CTX *ctx, EVP_PKEY *key,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *msg, size_t msglen,
                    const unsigned char *cs, size_t cslen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    OSSL_PARAM p[2];
    int r = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, PROPQ, key,
                                   ctx_params(p, cs, cslen)) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, msglen) == 1;

    EVP_MD_CTX_free(m);
    ERR_clear_error();
    return r;
}

/* Import a raw key blob as `name` (`param` PUB_KEY or PRIV_KEY). */
static EVP_PKEY *import_raw(OSSL_LIB_CTX *ctx, const char *name,
                            const char *param, int selection,
                            unsigned char *blob, size_t len)
{
    EVP_PKEY_CTX *fc = EVP_PKEY_CTX_new_from_name(ctx, name, PROPQ);
    EVP_PKEY *key = NULL;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_octet_string(param, blob, len);
    p[1] = OSSL_PARAM_construct_end();
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &key, selection, p) <= 0)
        key = NULL;
    EVP_PKEY_CTX_free(fc);
    return key;
}

/* 1 iff `key`'s exported raw private key equals want[0..wantlen). */
static int priv_equals(EVP_PKEY *key, const unsigned char *want,
                       size_t wantlen)
{
    OSSL_PARAM *params = NULL;
    const OSSL_PARAM *p;
    const void *got;
    size_t gotlen = 0;
    int r = EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &params) > 0
        && (p = OSSL_PARAM_locate_const(params,
                                        OSSL_PKEY_PARAM_PRIV_KEY)) != NULL
        && OSSL_PARAM_get_octet_string_ptr(p, &got, &gotlen) == 1
        && gotlen == wantlen && memcmp(got, want, wantlen) == 0;

    OSSL_PARAM_free(params);
    return r;
}

/* Decode a DER PrivateKeyInfo as `name` with the hybrid provider. */
static EVP_PKEY *decode_p8(OSSL_LIB_CTX *ctx, const char *name,
                           const unsigned char *der, size_t len)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *dc = OSSL_DECODER_CTX_new_for_pkey(
        &key, "DER", "PrivateKeyInfo", name, EVP_PKEY_KEYPAIR, ctx, PROPQ);

    if (dc == NULL || !OSSL_DECODER_from_data(dc, &der, &len)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(dc);
    return key;
}

static void check(OSSL_LIB_CTX *ctx, const KAT *k,
                  const unsigned char *msg, size_t msglen,
                  const unsigned char *cs, size_t cslen)
{
    const COMPOSITE_SIG_INFO *info = find_info(k->name);
    EVP_PKEY *pub = NULL, *prv = NULL, *p8 = NULL;
    EVP_MD_CTX *m = NULL;
    X509 *x = NULL;
    const unsigned char *q;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    OSSL_PARAM p[2];
    int ok = 1;

    tests++;
    printf("  %-22s all draft vector fields ... ", k->name);
    fflush(stdout);

    if (info == NULL) {
        printf("FAIL (KAT name not in composite table)\n");
        failed++;
        return;
    }
    if (!pq_available(ctx, info->pq_alg)) {
        printf("SKIP (%s unavailable)\n", info->pq_alg);
        skipped++; tests--;
        return;
    }
    EXPECT((pub = import_raw(ctx, k->name, OSSL_PKEY_PARAM_PUB_KEY,
                             EVP_PKEY_PUBLIC_KEY, k->pk, k->pklen)) != NULL,
           "pk import");
    /* K1-K3 */
    EXPECT(verifies(ctx, pub, k->s, k->slen, msg, msglen, NULL, 0),
           "K1: s does not verify");
    EXPECT(verifies(ctx, pub, k->sc, k->sclen, msg, msglen, cs, cslen),
           "K2: sWithContext does not verify under ctx");
    EXPECT(!verifies(ctx, pub, k->sc, k->sclen, msg, msglen, NULL, 0),
           "K3: sWithContext verifies without ctx");
    EXPECT(!verifies(ctx, pub, k->s, k->slen, msg, msglen, cs, cslen),
           "K3: s verifies under ctx");
    /* K4-K5 */
    EXPECT((prv = import_raw(ctx, k->name, OSSL_PKEY_PARAM_PRIV_KEY,
                             EVP_PKEY_KEYPAIR, k->sk, k->sklen)) != NULL,
           "K4: sk import");
    EXPECT(EVP_PKEY_eq(prv, pub) == 1, "K4: sk's public key != pk");
    EXPECT((m = EVP_MD_CTX_new()) != NULL
           && EVP_DigestSignInit_ex(m, NULL, NULL, ctx, PROPQ, prv,
                                    ctx_params(p, cs, cslen)) > 0
           && EVP_DigestSign(m, NULL, &siglen, msg, msglen) > 0
           && (sig = OPENSSL_malloc(siglen)) != NULL
           && EVP_DigestSign(m, sig, &siglen, msg, msglen) > 0,
           "K5: sign with sk under ctx");
    EXPECT(verifies(ctx, pub, sig, siglen, msg, msglen, cs, cslen),
           "K5: our signature does not verify under pk");
    /* K6 */
    EXPECT((p8 = decode_p8(ctx, k->name, k->p8, k->p8len)) != NULL,
           "K6: sk_pkcs8 decode");
    EXPECT(EVP_PKEY_eq(p8, pub) == 1, "K6: sk_pkcs8 public key != pk");
    EXPECT(priv_equals(p8, k->sk, k->sklen), "K6: sk_pkcs8 private != sk");
    /* K7 */
    /* Decode in the test's libctx, where the hybrid provider is loaded. */
    q = k->crt;
    EXPECT((x = X509_new_ex(ctx, PROPQ)) != NULL
           && d2i_X509(&x, &q, (long)k->crtlen) != NULL
           && q == k->crt + k->crtlen, "K7: x5c decode");
    EXPECT(EVP_PKEY_eq(X509_get0_pubkey(x), pub) == 1,
           "K7: x5c public key != pk");
    EXPECT(X509_verify(x, pub) == 1, "K7: x5c self-signature");
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    ERR_clear_error();
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    X509_free(x);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(prv);
    EVP_PKEY_free(p8);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    const char *katfile = argc > 1 ? argv[1] : "composite_kat.txt";
    FILE *f;
    char *line = NULL;
    size_t cap = 0, msglen = 0, cslen = 0;
    unsigned char *msg = NULL, *cs = NULL;
    ssize_t n;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (hybrid_test_load(ctx, "default") == NULL
            || hybrid_test_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    ERR_clear_error();

    if ((f = fopen(katfile, "r")) == NULL) {
        fprintf(stderr, "cannot open KAT file: %s\n", katfile);
        hybrid_test_libctx_free(ctx);
        return 1;
    }

    printf("composite (LAMPS) KAT interop vs draft-19 reference vectors\n");
    printf("(K1-K7: s, sWithContext+ctx binding, sk, sk_pkcs8, x5c)\n");
    printf("==========================================================\n");
    while ((n = getline(&line, &cap, f)) > 0) {
        char *save, *t, *tok[KAT_COLS + 1] = { NULL };
        unsigned char **dst[KAT_COLS - 1];
        size_t *dlen[KAT_COLS - 1], i, nt = 0;
        KAT k = { 0 };

        if (line[0] == '#' || line[0] == '\n')
            continue;
        /* Collect up to one column more than a row has, so extras show. */
        for (t = strtok_r(line, " \t\r\n", &save);
             t != NULL && nt <= KAT_COLS;
             t = strtok_r(NULL, " \t\r\n", &save))
            tok[nt++] = t;
        if (nt >= 2 && strcmp(tok[0], "m") == 0) {
            OPENSSL_free(msg);
            msg = hexdec(tok[1], &msglen);
            continue;
        }
        if (nt >= 2 && strcmp(tok[0], "ctx") == 0) {
            OPENSSL_free(cs);
            cs = hexdec(tok[1], &cslen);
            continue;
        }
        tests++;
        if (nt != KAT_COLS || msg == NULL || cs == NULL) {
            printf("  %-22s FAIL (malformed KAT line, or m/ctx missing)\n",
                   tok[0] != NULL ? tok[0] : "?");
            failed++;
            continue;
        }
        tests--;                               /* check() counts the row */
        dst[0] = &k.pk; dst[1] = &k.s; dst[2] = &k.sc;
        dst[3] = &k.sk; dst[4] = &k.p8; dst[5] = &k.crt;
        dlen[0] = &k.pklen; dlen[1] = &k.slen; dlen[2] = &k.sclen;
        dlen[3] = &k.sklen; dlen[4] = &k.p8len; dlen[5] = &k.crtlen;
        k.name = tok[0];
        for (i = 0; i < KAT_COLS - 1; i++)
            if ((*dst[i] = hexdec(tok[i + 1], dlen[i])) == NULL)
                break;
        if (i == KAT_COLS - 1) {
            check(ctx, &k, msg, msglen, cs, cslen);
        } else {
            printf("  %-22s FAIL (bad hex in KAT)\n", k.name);
            tests++;
            failed++;
        }
        for (i = 0; i < KAT_COLS - 1; i++)
            OPENSSL_free(*dst[i]);
    }
    OPENSSL_free(msg);
    OPENSSL_free(cs);
    free(line);
    fclose(f);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
