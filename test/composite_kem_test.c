/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM combiner test — drives composite_kem.c directly with
 * EVP-generated component keys, independent of the provider plumbing (the KEM
 * analogue of composite_sig_test.c). Two checks:
 *
 *   1. Combiner KAT: the worked X25519 example from lamps-wg/draft-composite-kem
 *      (src/kemCombiner_MLKEM768_X25519_SHA3_256.md) — fixed inputs -> fixed ss.
 *      This proves byte-exactness of the SHA3-256 combiner against the draft with
 *      no provider and no ML-KEM (SHA3-256 alone suffices), so it runs anywhere.
 *
 *   2. Encaps/decaps self-consistency: for every table combo whose components are
 *      available, generate an ML-KEM + a classical keypair via EVP, encapsulate
 *      and decapsulate, and assert the 32-byte shared secrets match. Needs ML-KEM
 *      from the default provider (3.5+); each combo self-skips otherwise.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "composite_kem_prov.h"

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

/* Check 1 — the draft-18 worked X25519 combiner vector. */
static void combiner_kat(OSSL_LIB_CTX *ctx)
{
    /* draft-ietf-lamps-pq-composite-kem-18 worked example, from
     * https://github.com/lamps-wg/draft-composite-kem/blob/
     * draft-ietf-lamps-pq-composite-kem-18/src/kemCombiner_MLKEM768_X25519_SHA3_256.md */
    const char *mlss_h = "461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1";
    const char *trss_h = "4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843";
    const char *trct_h = "0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f";
    const char *trpk_h = "1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b";
    const unsigned char label[] = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };
    const char *want_h = "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98";
    unsigned char *mlss, *trss, *trct, *trpk, *want;
    size_t l1, l2, l3, l4, wl;
    unsigned char got[COMPOSITE_KEM_SS_BYTES];

    tests++;
    printf("  %-22s draft X25519 combiner vector ... ", "combiner-kat");
    fflush(stdout);

    mlss = hexdec(mlss_h, &l1); trss = hexdec(trss_h, &l2);
    trct = hexdec(trct_h, &l3); trpk = hexdec(trpk_h, &l4);
    want = hexdec(want_h, &wl);
    if (mlss == NULL || trss == NULL || trct == NULL || trpk == NULL
            || want == NULL) {
        printf("FAIL (hex)\n"); failed++; goto done;
    }
    if (composite_kem_combine(ctx, mlss, l1, trss, l2, trct, l3, trpk, l4,
                              label, sizeof(label), got)
            && wl == sizeof(got) && memcmp(got, want, wl) == 0) {
        printf("PASS\n"); passed++;
    } else {
        printf("FAIL (combiner output != draft ss)\n"); failed++;
    }
done:
    OPENSSL_free(mlss); OPENSSL_free(trss); OPENSSL_free(trct);
    OPENSSL_free(trpk); OPENSSL_free(want);
}

static int have_alg(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, "provider=default");
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

/* Property query selecting the provider for the classical component. Defaults to
 * the default provider, but is overridable (e.g. COMPOSITE_TRAD_PROPQ=
 * "provider=fips") so the classical half can be sourced elsewhere — mirroring the
 * real provider's config-driven classic-propquery, which is not hard-wired to
 * the default provider either. */
static const char *trad_propq(void)
{
    const char *p = getenv("COMPOSITE_TRAD_PROPQ");

    return p != NULL ? p : "provider=default";
}

static EVP_PKEY *gen_trad(OSSL_LIB_CTX *ctx, const COMPOSITE_KEM_INFO *info)
{
    const char *propq = trad_propq();

    if (strcmp(info->trad_alg, "EC") == 0)
        return EVP_PKEY_Q_keygen(ctx, propq, "EC", info->trad_group);
    if (strcmp(info->trad_alg, "X25519") == 0
            || strcmp(info->trad_alg, "X448") == 0)
        return EVP_PKEY_Q_keygen(ctx, propq, info->trad_alg);
    return EVP_PKEY_Q_keygen(ctx, propq, "RSA", (size_t)info->trad_rsa_bits);
}

/* Check 2 — encaps/decaps self-consistency for one combo. */
static void roundtrip(OSSL_LIB_CTX *ctx, const COMPOSITE_KEM_INFO *info)
{
    EVP_PKEY *pq = NULL, *trad = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ctlen = 0, ss1len = 0, ss2len = 0;

    tests++;
    printf("  %-22s encaps/decaps round-trip ... ", info->name);
    fflush(stdout);

    if (!have_alg(ctx, info->pq_alg)) {
        printf("SKIP (%s unavailable)\n", info->pq_alg);
        skipped++; tests--;
        return;
    }
    pq = EVP_PKEY_Q_keygen(ctx, "provider=default", info->pq_alg);
    trad = gen_trad(ctx, info);
    if (pq == NULL || trad == NULL) {
        printf("SKIP (component keygen failed)\n");
        skipped++; tests--;
        goto done;
    }
    if (!composite_kem_encaps(info, pq, trad, ctx, "provider=default",
                              "provider=default", &ct, &ctlen, &ss1, &ss1len)) {
        printf("FAIL (encaps)\n"); failed++; goto done;
    }
    if (!composite_kem_decaps(info, pq, trad, ctx, "provider=default",
                              "provider=default", ct, ctlen, &ss2, &ss2len)) {
        printf("FAIL (decaps)\n"); failed++; goto done;
    }
    if (ss1len == COMPOSITE_KEM_SS_BYTES && ss1len == ss2len
            && memcmp(ss1, ss2, ss1len) == 0) {
        printf("PASS\n"); passed++;
    } else {
        printf("FAIL (shared secrets differ)\n"); failed++;
    }
done:
    OPENSSL_free(ct);
    OPENSSL_clear_free(ss1, ss1len);
    OPENSSL_clear_free(ss2, ss2len);
    EVP_PKEY_free(pq);
    EVP_PKEY_free(trad);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL) {
        fprintf(stderr, "failed to load default provider\n");
        return 1;
    }
    ERR_clear_error();

    printf("composite (LAMPS) ML-KEM combiner tests\n");
    printf("=======================================\n");
    combiner_kat(ctx);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        roundtrip(ctx, &composite_kem_table[i]);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);
    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
