/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) KAT interop test (issue #6) — the real draft-19 cross-
 * implementation check. Loads the reference test vectors from
 * draft-ietf-lamps-pq-composite-sigs (lamps-wg/draft-composite-sigs,
 * src/testvectors.json, distilled into test/composite_kat.txt), imports each
 * reference public key into the composite provider, and VERIFIES the reference
 * signature over the reference message.
 *
 * A pass means our combiner is byte-compatible with the reference across the
 * whole construction — prefix, per-algorithm label, prehash, RSA-PSS params,
 * ML-DSA context, component split and encoding — since verify recomputes M' and
 * checks both component signatures against bytes we did not produce. This is what
 * self-consistent sign/verify cannot establish.
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

/* Is ML-DSA available from the default provider? (No on 3.4.) */
static int default_has_mldsa(OSSL_LIB_CTX *ctx)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, "ML-DSA-44",
                                                 "provider=default");
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

static void check(OSSL_LIB_CTX *ctx, int have_mldsa, const char *name,
                  const char *msgh, const char *pkh, const char *sigh)
{
    unsigned char *msg = NULL, *pk = NULL, *sig = NULL;
    size_t msglen = 0, pklen = 0, siglen = 0;
    EVP_PKEY_CTX *fc = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *m = NULL;
    OSSL_PARAM p[2];

    tests++;
    printf("  %-22s verify reference sig ... ", name);
    fflush(stdout);

    if (!have_mldsa) {
        printf("SKIP (no default ML-DSA)\n");
        skipped++; tests--;
        return;
    }
    if ((msg = hexdec(msgh, &msglen)) == NULL
            || (pk = hexdec(pkh, &pklen)) == NULL
            || (sig = hexdec(sigh, &siglen)) == NULL) {
        printf("FAIL (bad hex in KAT)\n");
        failed++;
        goto done;
    }

    /* Import the reference public key (raw concat pqPub||tradPub). */
    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pk, pklen);
    p[1] = OSSL_PARAM_construct_end();
    fc = EVP_PKEY_CTX_new_from_name(ctx, name, "provider=composite");
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &key, EVP_PKEY_PUBLIC_KEY, p) <= 0
            || key == NULL) {
        printf("FAIL (public-key import)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }

    m = EVP_MD_CTX_new();
    if (m == NULL
            || EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=composite",
                                       key, NULL) <= 0) {
        printf("FAIL (verify init)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (EVP_DigestVerify(m, sig, siglen, msg, msglen) == 1) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL (reference signature did not verify)\n");
        ERR_print_errors_fp(stdout);
        failed++;
    }
done:
    OPENSSL_free(msg);
    OPENSSL_free(pk);
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(fc);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    const char *katfile = argc > 1 ? argv[1] : "composite_kat.txt";
    FILE *f;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int have_mldsa;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "composite") == NULL) {
        fprintf(stderr, "failed to load default/composite providers\n");
        return 1;
    }
    ERR_clear_error();
    have_mldsa = default_has_mldsa(ctx);

    if ((f = fopen(katfile, "r")) == NULL) {
        fprintf(stderr, "cannot open KAT file: %s\n", katfile);
        return 1;
    }

    printf("composite (LAMPS) KAT interop vs draft-19 reference vectors\n");
    printf("==========================================================\n");
    while ((n = getline(&line, &cap, f)) > 0) {
        char *save, *name, *msgh, *pkh, *sigh;

        if (line[0] == '#' || line[0] == '\n')
            continue;
        name = strtok_r(line, " \t\r\n", &save);
        msgh = strtok_r(NULL, " \t\r\n", &save);
        pkh = strtok_r(NULL, " \t\r\n", &save);
        sigh = strtok_r(NULL, " \t\r\n", &save);
        if (name && msgh && pkh && sigh)
            check(ctx, have_mldsa, name, msgh, pkh, sigh);
    }
    free(line);
    fclose(f);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
