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
#include "composite_prov.h"   /* composite_sig_table: map KAT name -> PQ component */

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

static void check(OSSL_LIB_CTX *ctx, const char *name,
                  const char *msgh, const char *pkh, const char *sigh)
{
    const COMPOSITE_SIG_INFO *info = find_info(name);
    unsigned char *msg = NULL, *pk = NULL, *sig = NULL;
    size_t msglen = 0, pklen = 0, siglen = 0;
    EVP_PKEY_CTX *fc = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *m = NULL;
    OSSL_PARAM p[2];

    tests++;
    printf("  %-22s verify reference sig ... ", name);
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
    fc = EVP_PKEY_CTX_new_from_name(ctx, name, "provider=hybrid");
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
            || EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, "provider=hybrid",
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

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    ERR_clear_error();

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
            check(ctx, name, msgh, pkh, sigh);
    }
    free(line);
    fclose(f);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
