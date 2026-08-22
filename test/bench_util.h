/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared benchmark/guard helpers for the composition-overhead guards.
 *
 * All three benches (hybrid_bench, composite_sig_bench, composite_kem_bench) share
 * ONE regression model: a composed algorithm (hybrid or composite) IS its two
 * constituent components plus a small combiner glue, so the guard asserts that the
 * composed op stays within a tight multiple of the SUM OF THE COMPONENTS measured
 * standalone. This needs no native peer, no same-implementation ("FAIR") matching
 * and no version-gating: because the peer literally is the two components, any
 * per-component cost -- including oqsprovider's per-op no_cache tax -- cancels.
 *
 * Two invariants make a single tight bound sound (see the individual functions):
 *   - keygen is never asserted (randomised, heavy-tailed);
 *   - timings are the MINIMUM per-op latency (noise only adds time), with per-op
 *     component context setup so the tax cancels symmetrically.
 */
#ifndef HYBRID_TEST_BENCH_UTIL_H
#define HYBRID_TEST_BENCH_UTIL_H

#include <stddef.h>
#include <openssl/evp.h>

/* Per-op wall-clock budget shared by every timing loop (default 1000 ms). */
void   bench_set_budget_ms(double ms);
double bench_now_ms(void);

/* Generate a key of a named algorithm from a given provider (or NULL propq). */
EVP_PKEY *bench_gen_key(OSSL_LIB_CTX *ctx, const char *name, const char *propq);

/*
 * Generate a standalone classical component key matching a composed algorithm's
 * traditional half: "EC" (+group), "X25519"/"X448", "ED25519"/"ED448",
 * "RSA"/"RSA-PSS" (+rsa_bits), or "RSA-OAEP" (mapped to an RSA key). NULL on error.
 */
EVP_PKEY *bench_gen_trad_key(OSSL_LIB_CTX *ctx, const char *alg,
                             const char *group, int rsa_bits);

/* One raw signature over the fixed guard message (caller frees). md may be NULL. */
int    bench_make_sig(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                      unsigned char **sig, size_t *siglen);

/* Minimum per-op latency (ms) for the named op; -1.0 on error. */
double bench_time_sign(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md);
double bench_time_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                         const unsigned char *sig, size_t siglen);
double bench_time_kem_encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq);
double bench_time_kem_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *propq);

/*
 * Classical KEM component encaps+decaps times (ms) for a composed KEM's trad half:
 * DHKEM (ephemeral keygen + derive) for EC/X25519/X448, or RSA-OAEP
 * (encrypt/decrypt). Returns 1 and sets *enc_ms/*dec_ms; 0 on error.
 */
int    bench_time_trad_kem(OSSL_LIB_CTX *ctx, const char *trad_alg,
                           const char *group, int rsa_bits, EVP_PKEY *trad,
                           double *enc_ms, double *dec_ms);

/* Assert one op: composed time within ceil x the summed-components time; prints a
 * row, and on breach prints "!!" and bumps *failures. Sub-noise-floor sums skip.
 * A NULL failures pointer reports the row without asserting it (for a caller that
 * deliberately excludes a known anomaly). bench_guard_{sig,kem} forward it. */
void   bench_guard_op(const char *alg, const char *op, double comp, double sum,
                      double ceil, int *failures);

/*
 * Full sum-of-components guard for one composed signature: gen the composed key
 * (composed_name via composed_propq) and its two components, then assert
 * sign/verify. trad_md is the classical component's own digest (NULL = pure Ed).
 * A missing composed alg is silently skipped (already reported elsewhere).
 */
void   bench_guard_sig(OSSL_LIB_CTX *ctx, const char *composed_name,
                       const char *composed_propq, const char *pq_alg,
                       const char *trad_alg, const char *trad_group,
                       int trad_rsa_bits, const char *trad_md,
                       double ceil, int *failures);

/* Full sum-of-components guard for one composed KEM (encaps/decaps). */
void   bench_guard_kem(OSSL_LIB_CTX *ctx, const char *composed_name,
                       const char *composed_propq, const char *pq_alg,
                       const char *trad_alg, const char *trad_group,
                       int trad_rsa_bits, double ceil, int *failures);

#endif /* HYBRID_TEST_BENCH_UTIL_H */
