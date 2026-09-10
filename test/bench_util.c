/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared benchmark/guard helpers -- see bench_util.h for the model.
 */
#include "bench_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

/*
 * Timing model. The result is the MINIMUM single-op latency over a budget-bounded
 * run: scheduler preemption and cache blips only ever ADD time, so the fastest
 * observed op is the cleanest estimate of the true cost and the ratio of two small
 * numbers stays stable at the short ctest budget. (A batch mean or chunk-mean was
 * tried and flakes the fast standardized-composite signatures to 1.3-1.65x on >=3.5,
 * where the composed op has more per-op variance than its components; the per-op
 * minimum rejects that.) Two efficiencies keep the harness out of the measurement:
 *   - the OUTPUT BUFFER and the size query are set up ONCE and reused, so no per-op
 *     malloc/free of outputs is charged to the crypto (it dominated fast primitives
 *     at the short budget);
 *   - the clock is read ONCE per op -- the end timestamp of one op is the start of
 *     the next -- and that same reading drives the budget check, so there is no
 *     separate per-op budget clock read.
 *
 * What is NOT hoisted is the per-op EVP context creation + operation *_init. That is
 * load-bearing, not churn: a composed op re-initialises its two component operations
 * on every call -- which on OpenSSL >=3.5 re-pays oqsprovider's per-op no_cache
 * method-construct, and for a composite re-runs the combiner setup -- so the
 * standalone components must re-init per op too, or the amortised components would
 * make the ratio explode (2-7x observed when the context was hoisted). Paying the
 * per-op setup on BOTH sides keeps it present in the sum, where it cancels.
 */
#define OP_MIN_ITERS     5       /* honor the budget only after this many ops */
#define OP_MAX_ITERS     200000  /* runaway guard; the ms budget normally governs */
#define OVERHEAD_MIN_MS  0.010   /* below this per-op, timing noise dominates */
#define GUARD_MSG_LEN    32
#define RECHECK_FACTOR   6       /* re-measure a breaching composed op at Nx budget */

static double g_budget_ms = 1000.0;
static const unsigned char guard_msg[GUARD_MSG_LEN] = { 0 };  /* content irrelevant */

void bench_set_budget_ms(double ms)
{
    if (ms > 0.0)
        g_budget_ms = ms;
}

int bench_timing_unreliable(void)
{
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
    return 1;
#elif defined(__has_feature)
# if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) \
        || __has_feature(memory_sanitizer)
    return 1;
# else
    return 0;
# endif
#else
    return 0;
#endif
}

int bench_guard_only(void)
{
    const char *v = getenv("HYBRID_BENCH_GUARD_ONLY");

    return v != NULL && v[0] != '\0' && v[0] != '0';
}

double bench_now_ms(void)
{
    struct timespec t;

    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

EVP_PKEY *bench_gen_key(OSSL_LIB_CTX *ctx, const char *name, const char *propq)
{
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(ctx, name, propq);
    EVP_PKEY *key = NULL;

    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &key) <= 0) {
        ERR_clear_error();
        key = NULL;
    }
    EVP_PKEY_CTX_free(gctx);
    return key;
}

EVP_PKEY *bench_gen_trad_key(OSSL_LIB_CTX *ctx, const char *alg,
                             const char *group, int rsa_bits)
{
    int is_rsa = (strncmp(alg, "RSA", 3) == 0);
    /* RSA-OAEP composites use a plain RSA key; all other RSA variants keep their
     * own keytype (RSA-PSS restricts padding, which we don't need for timing). */
    const char *name = (strcmp(alg, "RSA-OAEP") == 0) ? "RSA" : alg;
    EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    EVP_PKEY *key = NULL;

    if (gctx == NULL || EVP_PKEY_keygen_init(gctx) <= 0)
        goto done;
    if (strcmp(alg, "EC") == 0 && group != NULL) {
        OSSL_PARAM p[2];

        p[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)group, 0);
        p[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(gctx, p) <= 0)
            goto done;
    } else if (is_rsa && rsa_bits > 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, rsa_bits) <= 0)
            goto done;
    }
    if (EVP_PKEY_keygen(gctx, &key) <= 0)
        key = NULL;
done:
    ERR_clear_error();
    EVP_PKEY_CTX_free(gctx);
    return key;
}

int bench_make_sig(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                   const char *propq, unsigned char **sig, size_t *siglen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char *s = NULL;
    size_t l = 0;
    int ret = 0;

    if (m != NULL
            && EVP_DigestSignInit_ex(m, NULL, md, ctx, propq, key, NULL) > 0
            && EVP_DigestSign(m, NULL, &l, guard_msg, GUARD_MSG_LEN) > 0
            && (s = OPENSSL_malloc(l)) != NULL
            && EVP_DigestSign(m, s, &l, guard_msg, GUARD_MSG_LEN) > 0) {
        *sig = s; *siglen = l; s = NULL; ret = 1;
    }
    OPENSSL_free(s);
    EVP_MD_CTX_free(m);
    if (!ret)
        ERR_clear_error();
    return ret;
}

/*
 * Fold one just-completed op into a measurement loop and decide whether to continue.
 * Reads the clock once (this op's end is the next op's start), keeps *best as the
 * running minimum latency, and returns 1 to keep looping or 0 to stop: on op failure
 * (ok == 0, which also sets *best < 0 so the caller can tell), on reaching the ms
 * budget (after OP_MIN_ITERS), or on the OP_MAX_ITERS runaway cap. Every timing loop
 * starts with best = -1, n = 0 and t0 = prev = bench_now_ms(), so the min/budget/
 * timestamp logic lives here once instead of being repeated per op.
 */
static int bench_tick(int ok, double t0, double *prev, double *best, long *n)
{
    double now = bench_now_ms(), dt = now - *prev;

    *prev = now;
    if (!ok) {
        *best = -1.0;
        return 0;
    }
    if (*best < 0 || dt < *best)
        *best = dt;
    return !((++*n >= OP_MIN_ITERS && now - t0 >= g_budget_ms)
             || *n >= OP_MAX_ITERS);
}

/*
 * Per-op sign latency (ms), minimum over the budget; see the timing-model note.
 * The signature buffer is sized once and reused, so no output malloc/free is charged
 * to the crypto; the EVP_MD_CTX is created fresh per op (a real per-signature cost,
 * paid identically by the composed alg and its standalone components -- see the note
 * on why the per-op context/init must not be hoisted). -1.0 on error.
 */
double bench_time_sign(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                       const char *propq)
{
    EVP_MD_CTX *mq = EVP_MD_CTX_new();
    unsigned char *s = NULL;
    size_t cap = 0;
    double t0, prev, best = -1.0, r = -1.0;
    long n = 0;

    /* one-time size query (untimed) sizes the reusable signature buffer */
    if (mq == NULL
            || EVP_DigestSignInit_ex(mq, NULL, md, ctx, propq, key, NULL) <= 0
            || EVP_DigestSign(mq, NULL, &cap, guard_msg, GUARD_MSG_LEN) <= 0
            || (s = OPENSSL_malloc(cap)) == NULL)
        goto done;
    EVP_MD_CTX_free(mq);
    mq = NULL;
    t0 = prev = bench_now_ms();
    for (;;) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();   /* fresh ctx per op (see model note) */
        size_t l = cap;
        int ok = m != NULL
                 && EVP_DigestSignInit_ex(m, NULL, md, ctx, propq, key, NULL) > 0
                 && EVP_DigestSign(m, s, &l, guard_msg, GUARD_MSG_LEN) > 0;

        EVP_MD_CTX_free(m);
        if (!bench_tick(ok, t0, &prev, &best, &n))
            break;
    }
    r = best;
done:
    OPENSSL_free(s);
    EVP_MD_CTX_free(mq);
    if (r < 0)
        ERR_clear_error();
    return r;
}

double bench_time_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                         const char *propq, const unsigned char *sig,
                         size_t siglen)
{
    double t0, prev, best = -1.0, r = -1.0;
    long n = 0;

    t0 = prev = bench_now_ms();
    for (;;) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();   /* fresh ctx per op (see model note) */
        int ok = m != NULL
                 && EVP_DigestVerifyInit_ex(m, NULL, md, ctx, propq, key,
                                            NULL) > 0
                 && EVP_DigestVerify(m, sig, siglen, guard_msg,
                                     GUARD_MSG_LEN) == 1;

        EVP_MD_CTX_free(m);
        if (!bench_tick(ok, t0, &prev, &best, &n))
            break;
    }
    r = best;
    if (r < 0)
        ERR_clear_error();
    return r;
}

/*
 * KEM timers reuse ONE pair of output buffers (sized by an untimed size query) but
 * create a fresh EVP_PKEY_CTX and re-run *_init on every op -- load-bearing, not
 * churn, for the reason in the timing-model note above: the composed op re-inits its
 * two component operations every encapsulate/decapsulate (re-paying oqsprovider's
 * per-op no_cache method-construct on OpenSSL >=3.5), so the standalone components
 * must do the same or the amortised components make the ratio explode (2-7x observed
 * when the context was hoisted). What we drop is the harness churn the reviewer
 * flagged: per-op output-buffer malloc/free and the separate per-op budget clock
 * read. Minimum per-op latency, one clock read per op (see the model note).
 */
double bench_time_kem_encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq)
{
    EVP_PKEY_CTX *q = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    double t0, prev, best = -1.0, r = -1.0;
    long n = 0;

    /* one-time size query (untimed) sizes the reusable output buffers */
    if (q == NULL || EVP_PKEY_encapsulate_init(q, NULL) <= 0
            || EVP_PKEY_encapsulate(q, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL)
        goto done;
    EVP_PKEY_CTX_free(q);
    q = NULL;
    t0 = prev = bench_now_ms();
    for (;;) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
        size_t cl = ctlen, sl = sslen;
        int ok = c != NULL && EVP_PKEY_encapsulate_init(c, NULL) > 0
                 && EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl) > 0;

        EVP_PKEY_CTX_free(c);
        if (!bench_tick(ok, t0, &prev, &best, &n))
            break;
    }
    r = best;
done:
    OPENSSL_free(ct);
    OPENSSL_free(ss);
    EVP_PKEY_CTX_free(q);
    if (r < 0)
        ERR_clear_error();
    return r;
}

double bench_time_kem_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq)
{
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    double t0, prev, best = -1.0, r = -1.0;
    long n = 0;

    /* produce one ciphertext to decapsulate (untimed); buffers are then reused */
    if (ec == NULL || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL
            || EVP_PKEY_encapsulate(ec, ct, &ctlen, ss, &sslen) <= 0)
        goto done;
    EVP_PKEY_CTX_free(ec);
    ec = NULL;
    t0 = prev = bench_now_ms();
    for (;;) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
        size_t sl = sslen;
        int ok = c != NULL && EVP_PKEY_decapsulate_init(c, NULL) > 0
                 && EVP_PKEY_decapsulate(c, ss, &sl, ct, ctlen) > 0;

        EVP_PKEY_CTX_free(c);
        if (!bench_tick(ok, t0, &prev, &best, &n))
            break;
    }
    r = best;
done:
    OPENSSL_free(ct);
    OPENSSL_free(ss);
    EVP_PKEY_CTX_free(ec);
    if (r < 0)
        ERR_clear_error();
    return r;
}

/* One DHKEM encapsulation: ephemeral keygen + derive to trad_pub. */
static int dh_encaps_once(OSSL_LIB_CTX *ctx, EVP_PKEY *trad_pub)
{
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(ctx, trad_pub, NULL);
    EVP_PKEY_CTX *dctx = NULL;
    EVP_PKEY *eph = NULL;
    unsigned char *s = NULL;
    size_t l = 0;
    int ok = 0;

    if (kctx != NULL && EVP_PKEY_keygen_init(kctx) > 0
            && EVP_PKEY_keygen(kctx, &eph) > 0
            && (dctx = EVP_PKEY_CTX_new_from_pkey(ctx, eph, NULL)) != NULL
            && EVP_PKEY_derive_init(dctx) > 0
            && EVP_PKEY_derive_set_peer(dctx, trad_pub) > 0
            && EVP_PKEY_derive(dctx, NULL, &l) > 0
            && (s = OPENSSL_malloc(l)) != NULL
            && EVP_PKEY_derive(dctx, s, &l) > 0)
        ok = 1;
    OPENSSL_free(s);
    EVP_PKEY_free(eph);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);
    return ok;
}

/* One DHKEM decapsulation: derive priv against a fixed peer key. */
static int dh_derive_once(OSSL_LIB_CTX *ctx, EVP_PKEY *priv, EVP_PKEY *peer)
{
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(ctx, priv, NULL);
    unsigned char *s = NULL;
    size_t l = 0;
    int ok = 0;

    if (dctx != NULL && EVP_PKEY_derive_init(dctx) > 0
            && EVP_PKEY_derive_set_peer(dctx, peer) > 0
            && EVP_PKEY_derive(dctx, NULL, &l) > 0
            && (s = OPENSSL_malloc(l)) != NULL
            && EVP_PKEY_derive(dctx, s, &l) > 0)
        ok = 1;
    OPENSSL_free(s);
    EVP_PKEY_CTX_free(dctx);
    return ok;
}

int bench_time_trad_kem(OSSL_LIB_CTX *ctx, const char *trad_alg,
                        const char *group, int rsa_bits, EVP_PKEY *trad,
                        double *enc_ms, double *dec_ms)
{
    double t0, prev, best;
    long n;

    if (strcmp(trad_alg, "RSA-OAEP") == 0) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, trad, NULL);
        unsigned char sec[32] = { 0 }, *ct = NULL;
        size_t ctlen = 0;
        int ok = 0;

        /* encaps = OAEP encrypt of a random secret; decaps = OAEP decrypt. The
         * context and ciphertext buffer are set up once and reused; minimum per-op
         * latency, matching the composed-KEM timers. */
        if (c == NULL || EVP_PKEY_encrypt_init(c) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0
                || EVP_PKEY_encrypt(c, NULL, &ctlen, sec, sizeof(sec)) <= 0
                || (ct = OPENSSL_malloc(ctlen)) == NULL
                || EVP_PKEY_encrypt(c, ct, &ctlen, sec, sizeof(sec)) <= 0)
            goto rdone;                     /* last encrypt doubles as warm-up */
        best = -1.0;
        n = 0;
        t0 = prev = bench_now_ms();
        for (;;) {
            size_t cl = ctlen;
            int ok = EVP_PKEY_encrypt(c, ct, &cl, sec, sizeof(sec)) > 0;

            if (!bench_tick(ok, t0, &prev, &best, &n))
                break;
        }
        if (best < 0)
            goto rdone;
        *enc_ms = best;

        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(ctx, trad, NULL);
        {
            unsigned char out[64];
            size_t ol = sizeof(out);

            if (c == NULL || EVP_PKEY_decrypt_init(c) <= 0
                    || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0
                    || EVP_PKEY_decrypt(c, out, &ol, ct, ctlen) <= 0)
                goto rdone;                 /* decrypt doubles as warm-up */
        }
        best = -1.0;
        n = 0;
        t0 = prev = bench_now_ms();
        for (;;) {
            unsigned char out[64];
            size_t ol = sizeof(out);
            int oper = EVP_PKEY_decrypt(c, out, &ol, ct, ctlen) > 0;

            if (!bench_tick(oper, t0, &prev, &best, &n))
                break;
        }
        if (best < 0)
            goto rdone;
        *dec_ms = best;
        ok = 1;
rdone:
        OPENSSL_free(ct);
        EVP_PKEY_CTX_free(c);
        if (!ok)
            ERR_clear_error();
        return ok;
    }

    /*
     * DHKEM: encaps = ephemeral keygen + derive; decaps = one derive. Each op is a
     * from-scratch DHKEM operation (the ephemeral keygen and its context are part
     * of the encaps cost the composed KEM's classical half also pays every call),
     * so dh_encaps_once/dh_derive_once stay per-op; minimum per-op latency.
     */
    {
        EVP_PKEY *peer = bench_gen_trad_key(ctx, trad_alg, group, rsa_bits);
        int ok = 0;

        if (peer == NULL || !dh_encaps_once(ctx, trad))   /* warm-up */
            goto ddone;
        best = -1.0;
        n = 0;
        t0 = prev = bench_now_ms();
        for (;;)
            if (!bench_tick(dh_encaps_once(ctx, trad), t0, &prev, &best, &n))
                break;
        if (best < 0)
            goto ddone;
        *enc_ms = best;

        if (!dh_derive_once(ctx, trad, peer))             /* warm-up */
            goto ddone;
        best = -1.0;
        n = 0;
        t0 = prev = bench_now_ms();
        for (;;)
            if (!bench_tick(dh_derive_once(ctx, trad, peer), t0, &prev, &best, &n))
                break;
        if (best < 0)
            goto ddone;
        *dec_ms = best;
        ok = 1;
ddone:
        EVP_PKEY_free(peer);
        if (!ok)
            ERR_clear_error();
        return ok;
    }
}

void bench_guard_op(const char *alg, const char *op, double comp, double sum,
                    double ceil, int *failures)
{
    if (sum < OVERHEAD_MIN_MS)
        return;                            /* too small to time reliably */
    printf("    %-30s %-6s  %8.3f vs sum %8.3f  (%.2fx)\n",
           alg, op, comp, sum, comp / sum);
    if (comp > sum * ceil) {
        printf("    !! %s %s composition overhead %.2fx sum-of-components exceeds "
               "%.1fx ceiling\n", alg, op, comp / sum, ceil);
        (*failures)++;
    }
}

void bench_guard_sig(OSSL_LIB_CTX *ctx, const char *composed_name,
                     const char *composed_propq, const char *pq_alg,
                     const char *trad_alg, const char *trad_group,
                     int trad_rsa_bits, const char *trad_md,
                     double ceil, int *failures)
{
    EVP_PKEY *comp = NULL, *pq = NULL, *trad = NULL;
    unsigned char *csig = NULL, *psig = NULL, *tsig = NULL;
    size_t cl = 0, pl = 0, tl = 0;
    double cs, cv, ps, pv, ts, tv;

    /* Composed alg must be available; if not, its report row already said so. */
    if ((comp = bench_gen_key(ctx, composed_name, composed_propq)) == NULL)
        return;
    if ((pq = bench_gen_key(ctx, pq_alg, NULL)) == NULL
            || (trad = bench_gen_trad_key(ctx, trad_alg, trad_group,
                                          trad_rsa_bits)) == NULL)
        goto done;

    /*
     * The composed signature always signs the message directly (NULL md), like the
     * PQ half; the classical component uses its own trad_md. The composed op needs
     * its explicit provider propq -- it is a composite/hybrid keytype, and NULL
     * would force a costly per-op cross-provider resolution (see bench_util.h). The
     * standalone components correctly use NULL: each is a plain single-algorithm key
     * that only one provider owns, so NULL resolves the cached way to that provider
     * (the same impl the composed op composes from) -- not the composite-keytype
     * pathology. The measured ~1.0x sum is the check that they aren't inflated.
     */
    if (!bench_make_sig(ctx, comp, NULL, composed_propq, &csig, &cl)
            || !bench_make_sig(ctx, pq, NULL, NULL, &psig, &pl)
            || !bench_make_sig(ctx, trad, trad_md, NULL, &tsig, &tl))
        goto done;

    cs = bench_time_sign(ctx, comp, NULL, composed_propq);
    ps = bench_time_sign(ctx, pq, NULL, NULL);
    ts = bench_time_sign(ctx, trad, trad_md, NULL);
    cv = bench_time_verify(ctx, comp, NULL, composed_propq, csig, cl);
    pv = bench_time_verify(ctx, pq, NULL, NULL, psig, pl);
    tv = bench_time_verify(ctx, trad, trad_md, NULL, tsig, tl);
    if (cs < 0 || ps < 0 || ts < 0 || cv < 0 || pv < 0 || tv < 0)
        goto done;

    /*
     * Reject transient CI outliers before asserting. A per-op timing is a MINIMUM,
     * which contention can only push HIGH, so a false breach can only come from the
     * composed op under-sampling at the short smoke budget -- the component sum can
     * never be spuriously low. On a breach, re-measure just the composed op at a
     * larger budget: a real regression stays high, a scheduler blip drops back.
     */
    if (cs > (ps + ts) * ceil) {
        double b = g_budget_ms;

        g_budget_ms = b * RECHECK_FACTOR;
        cs = bench_time_sign(ctx, comp, NULL, composed_propq);
        g_budget_ms = b;
    }
    if (cv > (pv + tv) * ceil) {
        double b = g_budget_ms;

        g_budget_ms = b * RECHECK_FACTOR;
        cv = bench_time_verify(ctx, comp, NULL, composed_propq, csig, cl);
        g_budget_ms = b;
    }
    bench_guard_op(composed_name, "sign", cs, ps + ts, ceil, failures);
    bench_guard_op(composed_name, "verify", cv, pv + tv, ceil, failures);
done:
    OPENSSL_free(csig);
    OPENSSL_free(psig);
    OPENSSL_free(tsig);
    EVP_PKEY_free(comp);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}

void bench_guard_kem(OSSL_LIB_CTX *ctx, const char *composed_name,
                     const char *composed_propq, const char *pq_alg,
                     const char *trad_alg, const char *trad_group,
                     int trad_rsa_bits, double ceil, int *failures)
{
    EVP_PKEY *comp = NULL, *pq = NULL, *trad = NULL;
    double ce, cd, pe, pd, te = 0, td = 0;

    if ((comp = bench_gen_key(ctx, composed_name, composed_propq)) == NULL)
        return;
    if ((pq = bench_gen_key(ctx, pq_alg, NULL)) == NULL
            || (trad = bench_gen_trad_key(ctx, trad_alg, trad_group,
                                          trad_rsa_bits)) == NULL)
        goto done;

    ce = bench_time_kem_encaps(ctx, comp, composed_propq);
    cd = bench_time_kem_decaps(ctx, comp, composed_propq);
    pe = bench_time_kem_encaps(ctx, pq, NULL);
    pd = bench_time_kem_decaps(ctx, pq, NULL);
    if (ce < 0 || cd < 0 || pe < 0 || pd < 0
            || !bench_time_trad_kem(ctx, trad_alg, trad_group, trad_rsa_bits,
                                    trad, &te, &td))
        goto done;

    /* Reject transient outliers: re-measure a breaching composed op at a larger
     * budget before asserting (see the note in bench_guard_sig). */
    if (ce > (pe + te) * ceil) {
        double b = g_budget_ms;

        g_budget_ms = b * RECHECK_FACTOR;
        ce = bench_time_kem_encaps(ctx, comp, composed_propq);
        g_budget_ms = b;
    }
    if (cd > (pd + td) * ceil) {
        double b = g_budget_ms;

        g_budget_ms = b * RECHECK_FACTOR;
        cd = bench_time_kem_decaps(ctx, comp, composed_propq);
        g_budget_ms = b;
    }
    bench_guard_op(composed_name, "encaps", ce, pe + te, ceil, failures);
    bench_guard_op(composed_name, "decaps", cd, pd + td, ceil, failures);
done:
    EVP_PKEY_free(comp);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}
