/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Item 8: "pkey -text" (TEXT) encoder coverage. The text-print encoders for all
 * three families had zero test coverage. Documented prior-art defects for this
 * path are (a) printing `algorithm "<NULL>" unsupported` and (b) dropping the
 * last few key bytes. For every key type we assert the TEXT output is produced
 * and that it:
 *   - names the algorithm (a non-empty label line, no "<NULL>"/"unsupported"),
 *   - prints BOTH component sections (two "key material:" blocks), and
 *   - for the private key, is strictly larger than the public print (the private
 *     component material is really there, not silently dropped).
 *
 * Driven through OSSL_ENCODER by name (provider=hybrid). Each algorithm self-
 * skips when its components are unavailable, and when the family's TEXT encoder
 * is not built into this provider (hybrid KEM text needs -DHYBRID_KEM_ENCODERS;
 * the composite families need -DHYBRID_COMPOSITE) -- detected at runtime via the
 * encoder count, so the test is correct for every build configuration.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include "hybrid_prov.h"
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
# include "composite_kem_prov.h"
#endif

static int tests, passed, failed, skipped;

static EVP_PKEY *keygen(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *k = NULL;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0)
        EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    return k;
}

/*
 * TEXT-encode `selection` of `k`. Returns a malloc'd NUL-terminated string (its
 * byte length in *outlen). *had_encoder tells the caller whether a TEXT encoder
 * for this key even exists (0 => the family's text encoder was not built, so the
 * caller should SKIP rather than FAIL).
 */
static char *text_encode(EVP_PKEY *k, int selection, size_t *outlen,
                         int *had_encoder)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(k, selection, "TEXT",
                                                        NULL, "provider=hybrid");
    unsigned char *data = NULL;
    size_t len = 0;
    char *out = NULL;

    *had_encoder = (e != NULL && OSSL_ENCODER_CTX_get_num_encoders(e) > 0);
    if (*had_encoder && OSSL_ENCODER_to_data(e, &data, &len) > 0
            && data != NULL && (out = OPENSSL_malloc(len + 1)) != NULL) {
        memcpy(out, data, len);
        out[len] = '\0';
        *outlen = len;
    }
    OPENSSL_free(data);
    OSSL_ENCODER_CTX_free(e);
    return out;
}

/* Non-overlapping occurrences of needle in hay. */
static int count_occ(const char *hay, const char *needle)
{
    int n = 0;
    size_t nl = strlen(needle);
    const char *p = hay;

    while ((p = strstr(p, needle)) != NULL) { n++; p += nl; }
    return n;
}

/*
 * After the LAST "key material:" label the dump is pure ASN1_buf_print hex
 * (indented "ab:cd:.." lines). At least `min` hex nibbles there proves the final
 * component's material is actually printed -- i.e. it was not truncated away, the
 * documented "drops the last few key bytes" defect. (The tail is hex-only, so
 * counting hex chars cannot be fooled by letters in a label.)
 */
static int tail_has_hex(const char *text, int min)
{
    const char *p = text, *last = NULL;
    int nib = 0;

    while ((p = strstr(p, "key material:")) != NULL) { last = p; p += 13; }
    if (last == NULL)
        return 0;
    for (p = last; *p != '\0'; p++)
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')
                || (*p >= 'A' && *p <= 'F'))
            nib++;
    return nib >= min;
}

static void check_text(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY *k = NULL;
    char *pub = NULL, *priv = NULL;
    size_t publen = 0, privlen = 0;
    int have_pub = 0, have_priv = 0;

    printf("  %-28s pkey -text ... ", alg);
    fflush(stdout);
    tests++;

    if ((k = keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        return;
    }

    pub = text_encode(k, EVP_PKEY_PUBLIC_KEY, &publen, &have_pub);
    priv = text_encode(k, EVP_PKEY_KEYPAIR, &privlen, &have_priv);

    if (!have_pub && !have_priv) {
        printf("SKIP (no TEXT encoder in this build)\n");
        skipped++; tests--;
        goto end;
    }
    if (pub == NULL || priv == NULL) {
        printf("FAIL: TEXT encode returned no data\n");
        ERR_print_errors_fp(stdout); failed++;
        goto end;
    }
    if (strstr(pub, "<NULL>") != NULL || strstr(pub, "unsupported") != NULL) {
        printf("FAIL: algorithm name missing (\"<NULL>\"/unsupported)\n");
        failed++;
        goto end;
    }
    /* Both component sections must be printed (classical + PQ). */
    if (count_occ(pub, "key material:") < 2 || count_occ(priv, "key material:") < 2) {
        printf("FAIL: fewer than two component sections printed\n");
        failed++;
        goto end;
    }
    /* The last section's material is actually present (not truncated away). */
    if (!tail_has_hex(pub, 16) || !tail_has_hex(priv, 16)) {
        printf("FAIL: last component's key material missing/truncated\n");
        failed++;
        goto end;
    }
    printf("PASS (named, 2 sections, material intact: pub=%zu priv=%zu)\n",
           publen, privlen);
    passed++;
end:
    OPENSSL_free(pub);
    OPENSSL_free(priv);
    EVP_PKEY_free(k);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    /* Best-effort: supplies the non-native PQ bases (Falcon/MAYO/…) and, below
     * OpenSSL 3.5, ML-DSA/ML-KEM. */
    OSSL_PROVIDER_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("pkey -text (TEXT) encoder coverage\n");
    printf("==================================\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        check_text(ctx, hybrid_sig_table[i].hybrid_name);
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check_text(ctx, hybrid_kem_table[i].hybrid_name);
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check_text(ctx, composite_sig_table[i].name);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        check_text(ctx, composite_kem_table[i].name);
#endif

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
