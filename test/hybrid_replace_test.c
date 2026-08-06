/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drop-in replacement test: hybrid-provider fully replaces oqsprovider's hybrid
 * algorithms, composing over a PQ-only oqsprovider.
 *
 * The test sets OQS_CEDE_HYBRIDS before loading providers, so oqsprovider
 * withdraws every hybrid KEM/signature (the OQS_CEDE_HYBRIDS lever; carried as
 * test/patches/oqsprovider-cede-hybrids.patch until it lands upstream) while
 * keeping the standalone PQ + classical component algorithms. With default +
 * (PQ-only) oqsprovider + hybrid all in one libctx it then asserts:
 *
 *   1. oqsprovider serves ZERO hybrids (cede precondition) but still serves the
 *      standalone PQ bases the hybrid provider composes over.
 *   2. hybrid-provider serves and round-trips every hybrid, PQ sourced from
 *      oqsprovider (proven concretely by the Frodo/BIKE/HQC hybrids, whose PQ
 *      base exists only in oqsprovider).
 *
 * Version contract (the claim this test ascertains per running OpenSSL):
 *   - hybrid KEMs   — OpenSSL 3.0+ (EVP KEM API)          → always exercised
 *   - hybrid sigs   — OpenSSL 3.2+ (oqsprovider sig floor) → skipped below 3.2
 *   - composite     — OpenSSL 3.5+ (ML-DSA seed API)       → skipped below 3.5 /
 *                     when hybrid-provider was built without the composite family
 *
 * Positive assertions only: where the running version meets a threshold the
 * algorithms MUST work; below it they are skipped (not asserted absent), since
 * the thresholds are declared floors, not hard cliffs.
 *
 * Self-skips (exit 0) when oqsprovider is absent, or present but NOT honoring
 * OQS_CEDE_HYBRIDS (unpatched) — in which case true drop-in cannot be tested.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

static int tests = 0, passed = 0, failed = 0, skipped = 0;

/* Hybrid KEMs: MLX (default-compatible) + every OQS-legacy family. */
static const char *kem_hybrids[] = {
    /* MLX */
    "X25519MLKEM768", "SecP256r1MLKEM768", "X448MLKEM1024", "SecP384r1MLKEM1024",
    /* OQS-legacy ML-KEM */
    "x25519_mlkem512", "p256_mlkem512", "bp256_mlkem512", "p384_mlkem768",
    "x448_mlkem768", "bp384_mlkem768", "p521_mlkem1024", "bp512_mlkem1024",
    /* FrodoKEM / eFrodoKEM / BIKE / HQC — PQ base is oqsprovider-only */
    "p256_frodo640aes", "x25519_frodo640aes", "p384_frodo976shake",
    "p521_frodo1344aes", "p256_efrodo640aes", "x25519_efrodo640shake",
    "p256_bikel1", "x25519_bikel1", "p384_bikel3", "p521_bikel5",
    "p256_hqc1", "x25519_hqc1", "p384_hqc3", "p521_hqc5",
};

/* Hybrid signatures across every family. */
static const char *sig_hybrids[] = {
    "p256_mldsa44", "rsa3072_mldsa44", "p384_mldsa65", "p521_mldsa87",
    "p256_falcon512", "rsa3072_falcon512", "p521_falcon1024",
    "p256_falconpadded512", "p256_mayo1", "p256_mayo2", "p384_mayo3",
    "p521_mayo5", "p256_OV_Is_pkc", "p256_OV_Ip_pkc",
    "p256_snova2454", "p384_snova2455", "p521_snova2965",
    "p256_mqom2cat1gf16fastr5", "p384_mqom2cat3gf16fastr5",
    "p521_mqom2cat5gf16fastr5",
};

/* Composite (LAMPS) signatures — only when hybrid-provider was built with them. */
static const char *composite_sigs[] = {
    "mldsa44_ecdsa_p256", "mldsa44_ed25519", "mldsa44_rsa2048_pss",
    "mldsa65_ecdsa_p384", "mldsa65_ed25519", "mldsa87_ecdsa_p521",
    "mldsa87_ed448",
};

/* KEM self-consistency via provider=hybrid (keygen, encaps, decaps, ss match). */
static int kem_roundtrip(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = NULL, *e = NULL, *d = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ctlen = 0, ss1len = 0, ss2len = 0;
    int ok = 0;

    g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &key) <= 0)
        goto done;

    e = EVP_PKEY_CTX_new_from_pkey(ctx, key, "provider=hybrid");
    if (e == NULL || EVP_PKEY_encapsulate_init(e, NULL) <= 0
        || EVP_PKEY_encapsulate(e, NULL, &ctlen, NULL, &ss1len) <= 0)
        goto done;
    ct = OPENSSL_malloc(ctlen);
    ss1 = OPENSSL_malloc(ss1len);
    if (ct == NULL || ss1 == NULL
        || EVP_PKEY_encapsulate(e, ct, &ctlen, ss1, &ss1len) <= 0)
        goto done;

    d = EVP_PKEY_CTX_new_from_pkey(ctx, key, "provider=hybrid");
    if (d == NULL || EVP_PKEY_decapsulate_init(d, NULL) <= 0
        || EVP_PKEY_decapsulate(d, NULL, &ss2len, ct, ctlen) <= 0)
        goto done;
    ss2 = OPENSSL_malloc(ss2len);
    if (ss2 == NULL || EVP_PKEY_decapsulate(d, ss2, &ss2len, ct, ctlen) <= 0)
        goto done;

    ok = (ss1len == ss2len && ss1len > 0 && memcmp(ss1, ss2, ss1len) == 0);

done:
    OPENSSL_free(ct);
    OPENSSL_free(ss1);
    OPENSSL_free(ss2);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(g);
    EVP_PKEY_CTX_free(e);
    EVP_PKEY_CTX_free(d);
    return ok;
}

/* Sign/verify self-consistency via provider=hybrid, incl. tamper rejection. */
static int sig_roundtrip(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *md = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    const unsigned char msg[] = "hybrid drop-in replacement message";
    unsigned char bad[sizeof(msg)];
    int ok = 0;

    if (g == NULL || EVP_PKEY_keygen_init(g) <= 0 || EVP_PKEY_keygen(g, &key) <= 0)
        goto done;

    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestSignInit_ex(md, NULL, NULL, ctx, "provider=hybrid", key,
                                 NULL) <= 0
        || EVP_DigestSign(md, NULL, &siglen, msg, sizeof(msg)) <= 0)
        goto done;
    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(md, sig, &siglen, msg, sizeof(msg)) <= 0)
        goto done;

    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, "provider=hybrid", key,
                                   NULL) <= 0
        || EVP_DigestVerify(md, sig, siglen, msg, sizeof(msg)) != 1)
        goto done;

    memcpy(bad, msg, sizeof(msg));
    bad[0] ^= 0x01;
    EVP_MD_CTX_free(md);
    md = EVP_MD_CTX_new();
    if (md == NULL
        || EVP_DigestVerifyInit_ex(md, NULL, NULL, ctx, "provider=hybrid", key,
                                   NULL) <= 0
        || EVP_DigestVerify(md, sig, siglen, bad, sizeof(bad)) == 1)
        goto done;

    ok = 1;
done:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(g);
    return ok;
}

static void run(const char *kind, int (*fn)(OSSL_LIB_CTX *, const char *),
                OSSL_LIB_CTX *ctx, const char *alg)
{
    tests++;
    printf("  %-26s %s ... ", alg, kind);
    fflush(stdout);
    if (fn(ctx, alg)) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL\n");
        ERR_print_errors_fp(stdout);
        failed++;
    }
}

/* Does `prov` serve algorithm `alg` (KEM or signature)? */
static int provider_serves(OSSL_LIB_CTX *ctx, const char *alg, const char *prov,
                           int is_kem)
{
    if (is_kem) {
        EVP_KEM *k = EVP_KEM_fetch(ctx, alg, prov);
        int r = (k != NULL);
        EVP_KEM_free(k);
        return r;
    } else {
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(ctx, alg, prov);
        int r = (s != NULL);
        EVP_SIGNATURE_free(s);
        return r;
    }
}

int main(void)
{
    OSSL_LIB_CTX *ctx;
    const char *mods = getenv("OPENSSL_MODULES");
    unsigned long ver;
    size_t i;

    /* Must be set BEFORE oqsprovider initialises. */
    setenv("OQS_CEDE_HYBRIDS", "1", 1);

    ctx = OSSL_LIB_CTX_new();
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);

    if (OSSL_PROVIDER_load(ctx, "default") == NULL
        || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING drop-in replacement test\n");
        printf("(run test/setup_oqs_interop.sh to build the interop peer)\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }

    ver = OpenSSL_version_num();
    printf("Drop-in replacement: hybrid-provider over a PQ-only oqsprovider\n");
    printf("OpenSSL %s (0x%08lx)\n", OpenSSL_version(OPENSSL_VERSION), ver);
    printf("===============================================================\n");

    /* Precondition 1: oqsprovider must serve NO hybrids (cede active). */
    if (provider_serves(ctx, "p256_mlkem512", "provider=oqsprovider", 1)
        || provider_serves(ctx, "p256_mldsa44", "provider=oqsprovider", 0)) {
        printf("oqsprovider still serves hybrids -- OQS_CEDE_HYBRIDS not honored\n");
        printf("(oqsprovider not built with the cede patch) -- SKIPPING\n");
        OSSL_LIB_CTX_free(ctx);
        return 0;
    }
    printf("  precondition: oqsprovider cedes all hybrids ................ OK\n");

    /* Precondition 2: it still serves the standalone PQ bases we compose over
     * (FrodoKEM/Falcon exist only in oqsprovider, at every OpenSSL version). */
    if (!provider_serves(ctx, "frodo640aes", "provider=oqsprovider", 1)) {
        printf("oqsprovider no longer serves standalone PQ (frodo640aes) -- FAIL\n");
        OSSL_LIB_CTX_free(ctx);
        return 1;
    }
    printf("  precondition: oqsprovider still serves standalone PQ ...... OK\n\n");

    /* Hybrid KEMs — OpenSSL 3.0+ (always). */
    printf("hybrid KEMs (>= 3.0) served by hybrid-provider, PQ from oqsprovider\n");
    for (i = 0; i < sizeof(kem_hybrids) / sizeof(kem_hybrids[0]); i++)
        run("kem", kem_roundtrip, ctx, kem_hybrids[i]);

    /* Hybrid signatures — OpenSSL 3.2+. */
    printf("\nhybrid signatures (>= 3.2)\n");
    if (ver >= 0x30200000L) {
        for (i = 0; i < sizeof(sig_hybrids) / sizeof(sig_hybrids[0]); i++)
            run("sign/verify", sig_roundtrip, ctx, sig_hybrids[i]);
    } else {
        size_t n = sizeof(sig_hybrids) / sizeof(sig_hybrids[0]);
        printf("  SKIP %zu sigs (need OpenSSL 3.2+)\n", n);
        skipped += (int)n;
    }

    /* Composite signatures — OpenSSL 3.5+, and only if built with them. */
    printf("\ncomposite signatures (>= 3.5)\n");
    if (ver < 0x30500000L) {
        size_t n = sizeof(composite_sigs) / sizeof(composite_sigs[0]);
        printf("  SKIP %zu composite (need OpenSSL 3.5+)\n", n);
        skipped += (int)n;
    } else if (!provider_serves(ctx, composite_sigs[0], "provider=hybrid", 0)) {
        size_t n = sizeof(composite_sigs) / sizeof(composite_sigs[0]);
        printf("  SKIP %zu composite (hybrid-provider built without composite)\n", n);
        skipped += (int)n;
    } else {
        for (i = 0; i < sizeof(composite_sigs) / sizeof(composite_sigs[0]); i++)
            run("sign/verify", sig_roundtrip, ctx, composite_sigs[i]);
    }

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
