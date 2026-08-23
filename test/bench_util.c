/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared benchmark/guard helpers -- see bench_util.h for the model.
 */
#include "bench_util.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define OP_MIN_ITERS     5
#define OP_MAX_ITERS     500
#define OVERHEAD_MIN_MS  0.010   /* below this per-op, timing noise dominates */
#define GUARD_MSG_LEN    32

static double g_budget_ms = 1000.0;
static const unsigned char guard_msg[GUARD_MSG_LEN] = { 0 };  /* content irrelevant */

void bench_set_budget_ms(double ms)
{
    if (ms > 0.0)
        g_budget_ms = ms;
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
 * Minimum single-op latency (ms) over a budget-bounded run. We take the MIN, not
 * the mean: scheduler preemption and cache blips only ever ADD time, so the
 * fastest observed op is the cleanest estimate of the true compute cost.
 * Deterministic combiner overhead is present in every op (including the fastest),
 * so a real regression still shows; transient spikes -- which otherwise make the
 * ratio of two small timings flaky at the short ctest budget -- are filtered out.
 */
double bench_time_sign(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                       const char *propq)
{
    double t0 = bench_now_ms(), best = -1.0;
    int n;

    for (n = 0; n < OP_MAX_ITERS; n++) {
        unsigned char *s = NULL;
        size_t l = 0;
        double a = bench_now_ms(), dt;

        if (!bench_make_sig(ctx, key, md, propq, &s, &l))
            return -1.0;
        dt = bench_now_ms() - a;
        OPENSSL_free(s);
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
            break;
    }
    return best;
}

double bench_time_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                         const char *propq, const unsigned char *sig,
                         size_t siglen)
{
    double t0 = bench_now_ms(), best = -1.0;
    int n;

    for (n = 0; n < OP_MAX_ITERS; n++) {
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        double a = bench_now_ms(), dt;
        int ok = m != NULL
                 && EVP_DigestVerifyInit_ex(m, NULL, md, ctx, propq, key, NULL) > 0
                 && EVP_DigestVerify(m, sig, siglen, guard_msg, GUARD_MSG_LEN) == 1;

        dt = bench_now_ms() - a;
        EVP_MD_CTX_free(m);
        if (!ok) {
            ERR_clear_error();
            return -1.0;
        }
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
            break;
    }
    return best;
}

/*
 * KEM timers create+init the context INSIDE the loop, per op: the composed
 * algorithm sets up its two component operations on every encapsulate, and a
 * persistent-context peer would amortise the sub-provider fetch (including
 * oqsprovider's per-op no_cache tax) that the composed op pays every time --
 * making fast oqsprovider-component rows look artificially slow. Per-op setup
 * keeps the comparison symmetric (and mirrors the one-encaps-per-handshake TLS
 * pattern). Minimum per-op latency, as for the signature timers.
 */
double bench_time_kem_encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq)
{
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    double t0, best = -1.0, r = -1.0;
    int n;

    /* size query (untimed) to allocate reusable output buffers */
    if (ec == NULL || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL)
        goto done;
    EVP_PKEY_CTX_free(ec);
    ec = NULL;
    t0 = bench_now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        size_t cl = ctlen, sl = sslen;
        double a = bench_now_ms(), dt;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
        int ok = c != NULL && EVP_PKEY_encapsulate_init(c, NULL) > 0
                 && EVP_PKEY_encapsulate(c, ct, &cl, ss, &sl) > 0;

        dt = bench_now_ms() - a;
        EVP_PKEY_CTX_free(c);
        if (!ok)
            goto done;
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
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

double bench_time_kem_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq)
{
    EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    double t0, best = -1.0, r = -1.0;
    int n;

    if (ec == NULL || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, NULL, &ctlen, NULL, &sslen) <= 0
            || (ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss = OPENSSL_malloc(sslen)) == NULL
            || EVP_PKEY_encapsulate(ec, ct, &ctlen, ss, &sslen) <= 0)
        goto done;
    t0 = bench_now_ms();
    for (n = 0; n < OP_MAX_ITERS; n++) {
        size_t sl = sslen;
        double a = bench_now_ms(), dt;
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, key, propq);
        int ok = c != NULL && EVP_PKEY_decapsulate_init(c, NULL) > 0
                 && EVP_PKEY_decapsulate(c, ss, &sl, ct, ctlen) > 0;

        dt = bench_now_ms() - a;
        EVP_PKEY_CTX_free(c);
        if (!ok)
            goto done;
        if (best < 0 || dt < best)
            best = dt;
        if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
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
    double t0, best;
    int n;

    if (strcmp(trad_alg, "RSA-OAEP") == 0) {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, trad, NULL);
        unsigned char sec[32] = { 0 }, *ct = NULL;
        size_t ctlen = 0;
        int ok = 0;

        /* encaps = OAEP encrypt of a random secret; decaps = OAEP decrypt. */
        if (c == NULL || EVP_PKEY_encrypt_init(c) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0
                || EVP_PKEY_encrypt(c, NULL, &ctlen, sec, sizeof(sec)) <= 0
                || (ct = OPENSSL_malloc(ctlen)) == NULL)
            goto rdone;
        t0 = bench_now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            size_t cl = ctlen;
            double a = bench_now_ms(), dt;

            if (EVP_PKEY_encrypt(c, ct, &cl, sec, sizeof(sec)) <= 0)
                goto rdone;
            dt = bench_now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
                break;
        }
        *enc_ms = best;

        EVP_PKEY_CTX_free(c);
        c = EVP_PKEY_CTX_new_from_pkey(ctx, trad, NULL);
        if (c == NULL || EVP_PKEY_decrypt_init(c) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0)
            goto rdone;
        t0 = bench_now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            unsigned char out[64];
            size_t ol = sizeof(out);
            double a = bench_now_ms(), dt;

            if (EVP_PKEY_decrypt(c, out, &ol, ct, ctlen) <= 0)
                goto rdone;
            dt = bench_now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
                break;
        }
        *dec_ms = best;
        ok = 1;
rdone:
        OPENSSL_free(ct);
        EVP_PKEY_CTX_free(c);
        if (!ok)
            ERR_clear_error();
        return ok;
    }

    /* DHKEM: encaps = ephemeral keygen + derive; decaps = one derive. */
    {
        EVP_PKEY *peer = bench_gen_trad_key(ctx, trad_alg, group, rsa_bits);
        int ok = 0;

        if (peer == NULL)
            goto ddone;
        t0 = bench_now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            double a = bench_now_ms(), dt;

            if (!dh_encaps_once(ctx, trad))
                goto ddone;
            dt = bench_now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
                break;
        }
        *enc_ms = best;
        t0 = bench_now_ms();
        best = -1.0;
        for (n = 0; n < OP_MAX_ITERS; n++) {
            double a = bench_now_ms(), dt;

            if (!dh_derive_once(ctx, trad, peer))
                goto ddone;
            dt = bench_now_ms() - a;
            if (best < 0 || dt < best)
                best = dt;
            if (n + 1 >= OP_MIN_ITERS && bench_now_ms() - t0 >= g_budget_ms)
                break;
        }
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
     * PQ half; the classical component uses its own trad_md. The composed op uses
     * its provider propq (representative of real use, and avoids a per-op cross-
     * provider resolution that would inflate fast primitives); the standalone
     * components resolve naturally (NULL -> their sole provider).
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

    bench_guard_op(composed_name, "encaps", ce, pe + te, ceil, failures);
    bench_guard_op(composed_name, "decaps", cd, pd + td, ceil, failures);
done:
    EVP_PKEY_free(comp);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}
