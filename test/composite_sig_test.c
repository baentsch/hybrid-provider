/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) combiner self-consistency test (issue #6, first slice).
 *
 * Exercises composite_sign()/composite_verify() directly with EVP-generated
 * component keys — no provider registration yet. For each combo in the master
 * table it generates the PQ + classical components (from the default provider,
 * or oqsprovider for the experimental tier), signs a message, verifies it (must
 * pass), then tampers a byte and verifies again (must fail). A signature made
 * under a context string verifies only under that same context string (it is
 * bound into M'), and an over-long one is refused. M' itself is checked
 * byte-for-byte against the draft's two worked samples (with and without ctx).
 * Combos whose
 * components are unavailable (e.g. ML-DSA on 3.4, or mayo2 without oqsprovider)
 * self-skip.
 *
 * This proves the combiner plumbing + component delegation; it does NOT prove
 * wire-format interop (that needs Bouncy Castle / OpenSSL-native as a peer).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "composite_prov.h"
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */

static int tests, passed, failed, skipped;

static EVP_PKEY *keygen_pq(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info,
                           const char *propq)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, info->pq_alg, propq);
    EVP_PKEY *k = NULL;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0)
        EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

static EVP_PKEY *keygen_trad(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const char *p = "provider=default";

    if (strcmp(info->trad_alg, "EC") == 0)
        return EVP_PKEY_Q_keygen(ctx, p, "EC", info->trad_group);
    if (strcmp(info->trad_alg, "ED25519") == 0
            || strcmp(info->trad_alg, "ED448") == 0)
        return EVP_PKEY_Q_keygen(ctx, p, info->trad_alg);
    /* RSA / RSA-PSS: a plain RSA key, PSS applied at signing time. */
    return EVP_PKEY_Q_keygen(ctx, p, "RSA", (size_t)COMPOSITE_RSA_TRAD_BITS);
}

static void check(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info)
{
    const char *pqprop = info->tier == COMPOSITE_TIER_EXPERIMENTAL
                             ? "provider=oqsprovider" : "provider=default";
    const unsigned char msg[] = "composite LAMPS combiner self-consistency";
    /* The signing context, and near misses that must not verify: another
     * case, one byte short, one byte longer, one byte changed, a single byte,
     * empty, and none. */
    static const unsigned char ctxa[] = "Context-A";
    static const struct {
        const char *what;
        const unsigned char *v;
        size_t len;
    } wrong[] = {
        { "lowercased", (const unsigned char *)"context-a", sizeof(ctxa) - 1 },
        { "truncated", ctxa, sizeof(ctxa) - 2 },
        { "extended", ctxa, sizeof(ctxa) },              /* + its NUL byte */
        { "last byte changed", (const unsigned char *)"Context-B",
          sizeof(ctxa) - 1 },
        { "one byte", ctxa, 1 },
        { "empty", ctxa, 0 },
        { "none", NULL, 0 },
    };
    unsigned char longctx[COMPOSITE_SIG_CTX_MAX + 1] = { 0 };
    size_t w;
    EVP_PKEY *pq = NULL, *trad = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;

    tests++;
    printf("  %-22s %s ... ", info->name,
           info->tier == COMPOSITE_TIER_EXPERIMENTAL ? "(exp)" : "(std)");
    fflush(stdout);

    if ((pq = keygen_pq(ctx, info, pqprop)) == NULL
            || (trad = keygen_trad(ctx, info)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }
    if (!composite_sign(info, pq, trad, ctx, pqprop, "provider=default",
                        msg, sizeof(msg) - 1, NULL, 0, &sig, &siglen)) {
        printf("FAIL (sign)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (!composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                          msg, sizeof(msg) - 1, NULL, 0, sig, siglen)) {
        printf("FAIL (verify good)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    /* Tamper the last byte (in the traditional component) — must reject. */
    sig[siglen - 1] ^= 0x01;
    if (composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                         msg, sizeof(msg) - 1, NULL, 0, sig, siglen)) {
        printf("FAIL (tampered signature verified)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();

    /* Context string: bound into M', so only the same one verifies. */
    OPENSSL_free(sig);
    sig = NULL;
    if (!composite_sign(info, pq, trad, ctx, pqprop, "provider=default",
                        msg, sizeof(msg) - 1, ctxa, sizeof(ctxa) - 1, &sig,
                        &siglen)) {
        printf("FAIL (sign under a context string)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (!composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                          msg, sizeof(msg) - 1, ctxa, sizeof(ctxa) - 1, sig,
                          siglen)) {
        printf("FAIL (verify under the signing context string)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    for (w = 0; w < sizeof(wrong) / sizeof(wrong[0]); w++) {
        if (composite_verify(info, pq, trad, ctx, pqprop, "provider=default",
                             msg, sizeof(msg) - 1, wrong[w].v, wrong[w].len,
                             sig, siglen)) {
            printf("FAIL (verified under a %s context string)\n",
                   wrong[w].what);
            failed++;
            goto done;
        }
        ERR_clear_error();
    }
    OPENSSL_free(sig);
    sig = NULL;
    if (composite_sign(info, pq, trad, ctx, pqprop, "provider=default",
                       msg, sizeof(msg) - 1, longctx, sizeof(longctx),
                       &sig, &siglen)) {
        printf("FAIL (over-long context string accepted)\n");
        failed++;
        goto done;
    }
    ERR_clear_error();
    printf("PASS (sig=%zu)\n", siglen);
    passed++;
done:
    OPENSSL_free(sig);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}

/*
 * The draft's worked M' samples, verbatim (draft-ietf-lamps-pq-composite-
 * sigs-19 src/messageFormatSample_noctx.md and _ctx.md, included in its
 * appendix): id-MLDSA65-ECDSA-P256-SHA512, M = 00..09.
 */
#define MPRIME_SAMPLE_ALG "mldsa65_ecdsa_p256"
#define MPRIME_PH "0f89ee1fcb7b0a4f7809d1267a029719004c5a5e5ec323a7c3523a20974f" \
    "9a3f202f56fadba4cd9e8d654ab9f2e96dc5c795ea176fa20ede8d854c342f903533"
#define MPRIME_HEAD "436f6d706f73697465416c676f726974686d5369676e61747572" \
    "657332303235434f4d505349472d4d4c44534136352d45434453412d503235362d" \
    "534841353132"
static const struct {
    const char *what, *ctx_hex, *mprime_hex;
} mprime_samples[] = {
    { "no ctx", "", MPRIME_HEAD "00" MPRIME_PH },
    { "ctx", "0813061205162623",
      MPRIME_HEAD "08" "0813061205162623" MPRIME_PH },
};

static void check_mprime_samples(OSSL_LIB_CTX *ctx)
{
    static const unsigned char m[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    const COMPOSITE_SIG_INFO *info = NULL;
    size_t i;

    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        if (strcmp(composite_sig_table[i].name, MPRIME_SAMPLE_ALG) == 0)
            info = &composite_sig_table[i];
    if (info == NULL) {         /* the draft's sample combo left our table */
        tests++;
        failed++;
        printf("  %-22s draft M' samples ... FAIL (not in composite_sig_table)\n",
               MPRIME_SAMPLE_ALG);
        return;
    }
    for (i = 0; i < sizeof(mprime_samples) / sizeof(mprime_samples[0]); i++) {
        unsigned char *cs = NULL, *mp = NULL, *want = NULL;
        long cslen = 0, wantlen = 0;
        size_t mplen = 0;
        int ok;

        tests++;
        printf("  %-22s draft M' sample (%s) ... ", MPRIME_SAMPLE_ALG,
               mprime_samples[i].what);
        if (mprime_samples[i].ctx_hex[0] != '\0')
            cs = OPENSSL_hexstr2buf(mprime_samples[i].ctx_hex, &cslen);
        want = OPENSSL_hexstr2buf(mprime_samples[i].mprime_hex, &wantlen);
        ok = want != NULL
            && (cs != NULL || cslen == 0)
            && composite_build_mprime(info, ctx, m, sizeof(m), cs,
                                      (size_t)cslen, &mp, &mplen)
            && mplen == (size_t)wantlen && memcmp(mp, want, mplen) == 0;
        printf(ok ? "PASS\n" : "FAIL (M' differs from the draft sample)\n");
        if (ok)
            passed++;
        else
            failed++;
        ERR_clear_error();
        OPENSSL_free(cs);
        OPENSSL_free(mp);
        OPENSSL_free(want);
    }
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (hybrid_test_load(ctx, "default") == NULL) {
        fprintf(stderr, "failed to load default provider\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    hybrid_test_load(ctx, "oqsprovider");   /* optional: experimental tier */
    ERR_clear_error();

    printf("composite (LAMPS) combiner self-consistency\n");
    printf("===========================================\n");
    check_mprime_samples(ctx);
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check(ctx, &composite_sig_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
