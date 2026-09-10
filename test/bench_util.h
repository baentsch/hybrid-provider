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
 * Measured this way the glue is small: ~1.0x for signatures and up to ~1.2x for
 * the fastest KEMs (the composite SHA3-256 combiner pass / provider dispatch on a
 * ~0.07ms base), and a hybrid is at parity with oqsprovider's own hybrid. Three
 * invariants make a single tight bound sound (see the individual functions):
 *   - keygen is never asserted (randomised, heavy-tailed);
 *   - each timing is the MINIMUM per-op latency over a budgeted run (noise only
 *     adds time); the output buffers are sized once and reused and the clock is read
 *     once per op, so per-op output malloc/free and timer calls are not charged to
 *     the crypto (they dominated at the short ctest budget). The per-op EVP context
 *     creation + operation *_init is deliberately NOT hoisted: the composed op
 *     re-inits its two components every call (re-paying any oqsprovider no_cache
 *     re-fetch on >=3.5), so the standalone components re-init per op too and that
 *     cost is present on both sides of the ratio, where it cancels; hoisting it made
 *     fast oqsprovider KEMs read 2-7x;
 *   - the COMPOSED op is measured with its provider's property query (provider=...),
 *     as real callers do. It is a hybrid/composite *keytype*, and resolving that
 *     with a NULL propq forces a per-op cross-provider method construction that can
 *     dwarf the crypto for fast primitives (RSA especially) and grossly misreport
 *     the overhead -- an earlier revision saw ~13-18x. The STANDALONE components,
 *     by contrast, keep NULL on purpose: each is a plain single-algorithm key
 *     (ML-DSA, ECDSA, RSA, ...) whose keytype only one provider owns, so NULL
 *     resolves the ordinary cached way to that same provider the composed op
 *     composes from -- no cross-provider fan-out. That the components are NOT
 *     inflated is visible in the result: if they were, the sum would balloon and
 *     ratios would sit far below 1.0; instead they sit at ~1.0.
 */
#ifndef HYBRID_TEST_BENCH_UTIL_H
#define HYBRID_TEST_BENCH_UTIL_H

#include <stddef.h>
#include <openssl/evp.h>

/*
 * 1 when built under a sanitizer (ASan/TSan/MSan). Timing is meaningless there --
 * the instrumentation adds a large, uneven slowdown that inflates the composition
 * ratios and makes the guard flaky -- so the benches run the informational report
 * but SKIP the machine-checked overhead assertion under a sanitizer.
 */
int bench_timing_unreliable(void);

/*
 * 1 when HYBRID_BENCH_GUARD_ONLY is set to a non-empty, non-"0" value. In that
 * mode a bench skips its informational Part 1 report (the non-asserted native /
 * component side-by-side, which re-runs the whole inventory incl. slow keygen
 * loops) and runs only the asserted composition-overhead guard. The ctest smoke
 * registrations set it so the CI wall-clock reflects just the regression check;
 * a manual run (no env) still prints the full report.
 */
int bench_guard_only(void);

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

/*
 * One raw signature over the fixed guard message (caller frees). md may be NULL.
 * propq matters: signing a provider-native key with NULL forces a per-op
 * cross-provider signature resolution that the explicit "provider=..." hint (as
 * real callers and libssl use) avoids -- for fast primitives that resolution can
 * dwarf the crypto and misreport composition overhead. Pass the key's provider.
 */
int    bench_make_sig(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                      const char *propq, unsigned char **sig, size_t *siglen);

/* Minimum per-op latency (ms) over a budgeted run for the named op; -1.0 on error. */
double bench_time_sign(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                       const char *propq);
double bench_time_verify(OSSL_LIB_CTX *ctx, EVP_PKEY *key, const char *md,
                         const char *propq, const unsigned char *sig,
                         size_t siglen);
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
 * row, and on breach prints "!!" and bumps *failures. Sub-noise-floor sums skip. */
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
