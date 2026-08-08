/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM KAT interop test — the real draft-18 cross-
 * implementation check. Loads the reference vectors from
 * draft-ietf-lamps-pq-composite-kem (lamps-wg/draft-composite-kem,
 * src/testvectors.json, distilled into test/composite_kem_kat.txt), imports each
 * reference PKCS#8 private key into the composite provider, DECAPSULATES the
 * reference ciphertext, and checks it recovers the reference shared secret.
 *
 * A pass means the decoder, the ML-KEM seed expansion, the traditional-component
 * decapsulation and the SHA3-256 combiner are all byte-compatible with the
 * reference across bytes this provider did not produce — which self-consistent
 * encaps/decaps cannot establish. It is also the oracle that settles the RSA
 * tradPK combiner encoding for the RSA-OAEP combos.
 *
 * Needs ML-KEM from the default provider (3.5+); each combo self-skips otherwise.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
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

static const COMPOSITE_KEM_INFO *find_info(const char *name)
{
    size_t i;

    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        if (strcmp(composite_kem_table[i].name, name) == 0)
            return &composite_kem_table[i];
    return NULL;
}

static int pq_available(OSSL_LIB_CTX *ctx, const char *pq_alg)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, pq_alg, "provider=default");
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

static void check(OSSL_LIB_CTX *ctx, const char *name,
                  const char *p8h, const char *ch, const char *kh)
{
    const COMPOSITE_KEM_INFO *info = find_info(name);
    unsigned char *p8 = NULL, *ct = NULL, *k = NULL, *ss = NULL;
    size_t p8len = 0, ctlen = 0, klen = 0, sslen = 0;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    OSSL_DECODER_CTX *odc = NULL;

    tests++;
    printf("  %-22s decaps reference ct -> k ... ", name);
    fflush(stdout);

    if (info == NULL) {
        printf("FAIL (KAT name not in composite-KEM table)\n");
        failed++;
        return;
    }
    if (!pq_available(ctx, info->pq_alg)) {
        printf("SKIP (%s unavailable)\n", info->pq_alg);
        skipped++; tests--;
        return;
    }
    if ((p8 = hexdec(p8h, &p8len)) == NULL || (ct = hexdec(ch, &ctlen)) == NULL
            || (k = hexdec(kh, &klen)) == NULL) {
        printf("FAIL (bad hex in KAT)\n");
        failed++;
        goto done;
    }

    /* Import the reference PKCS#8 private key through the provider decoder. */
    {
        const unsigned char *p = p8;
        size_t l = p8len;

        odc = OSSL_DECODER_CTX_new_for_pkey(&key, "DER", "PrivateKeyInfo", NULL,
                                            EVP_PKEY_KEYPAIR, ctx,
                                            "provider=hybrid");
        if (odc == NULL || !OSSL_DECODER_from_data(odc, &p, &l) || key == NULL) {
            printf("FAIL (private-key decode)\n");
            ERR_print_errors_fp(stdout);
            failed++;
            goto done;
        }
    }

    dctx = EVP_PKEY_CTX_new_from_pkey(ctx, key, "provider=hybrid");
    if (dctx == NULL || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0
            || EVP_PKEY_decapsulate(dctx, NULL, &sslen, ct, ctlen) <= 0
            || (ss = OPENSSL_malloc(sslen)) == NULL
            || EVP_PKEY_decapsulate(dctx, ss, &sslen, ct, ctlen) <= 0) {
        printf("FAIL (decapsulate)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto done;
    }
    if (sslen == klen && memcmp(ss, k, klen) == 0) {
        printf("PASS\n");
        passed++;
    } else {
        printf("FAIL (recovered secret != reference k)\n");
        failed++;
    }
done:
    OPENSSL_free(p8);
    OPENSSL_free(ct);
    OPENSSL_free(k);
    OPENSSL_clear_free(ss, sslen);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(dctx);
    OSSL_DECODER_CTX_free(odc);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    const char *katfile = argc > 1 ? argv[1] : "composite_kem_kat.txt";
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

    printf("composite (LAMPS) ML-KEM KAT interop vs draft-18 reference vectors\n");
    printf("=================================================================\n");
    while ((n = getline(&line, &cap, f)) > 0) {
        char *save, *name, *p8h, *ch, *kh;

        if (line[0] == '#' || line[0] == '\n')
            continue;
        name = strtok_r(line, " \t\r\n", &save);
        p8h = strtok_r(NULL, " \t\r\n", &save);
        ch = strtok_r(NULL, " \t\r\n", &save);
        kh = strtok_r(NULL, " \t\r\n", &save);
        if (name && p8h && ch && kh)
            check(ctx, name, p8h, ch, kh);
    }
    free(line);
    fclose(f);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
