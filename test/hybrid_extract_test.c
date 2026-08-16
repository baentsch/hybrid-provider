/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Component extraction / composition (work-items item 13).
 *
 * A hybrid/composite key composes a classical component and a PQ component, each
 * a real EVP_PKEY. This test proves three things the provider now supports over
 * the public EVP API only:
 *
 *   (1) EXTRACTION as a usable key object. The provider exposes each component's
 *       public half as a SubjectPublicKeyInfo DER via the gettable params
 *       HYBRID_PKEY_PARAM_CLASSIC_PUB / HYBRID_PKEY_PARAM_PQ_PUB. We d2i_PUBKEY
 *       each into a standalone EVP_PKEY and confirm its algorithm and that it is
 *       a usable key (non-zero size) -- not an opaque OCTET STRING wrapper.
 *
 *   (2) INNER == STANDALONE parity. The bytes a component contributes to the
 *       composite/hybrid container must equal that component's own standalone
 *       encoding (the classic OCTET-STRING-nesting divergence bug). For the
 *       hybrid family we check the concatenated OSSL_PKEY_PARAM_PUB_KEY is
 *       exactly the two components' raw public keys; for the composite family we
 *       decode the composite SPKI and check its BIT STRING is exactly
 *       pqPub || tradPub (draft-19 order).
 *
 *   (3) COMPOSITION. Rebuild the container's public blob from the two extracted
 *       components' raw public keys and re-import it (EVP_PKEY_fromdata); the
 *       composed key must compare equal (EVP_PKEY_eq) to the original.
 *
 * All algorithms here draw both halves from the default provider (>= 3.5), so the
 * test needs no oqsprovider. Cede-to-default is switched off so the hybrid
 * provider serves the MLX KEMs itself (mirrors the other default+hybrid tests).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "hybrid_prov.h"

static int tests, passed, failed, skipped;

enum family { HYBRID, COMPOSITE };

static EVP_PKEY *gen(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *k = NULL;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0)
        EVP_PKEY_keygen(g, &k);
    EVP_PKEY_CTX_free(g);
    return k;
}

/* Read an octet-string param into a fresh buffer. Returns 1 on success. */
static int get_octet(EVP_PKEY *k, const char *name,
                     unsigned char **buf, size_t *len)
{
    size_t n = 0;

    *buf = NULL;
    if (EVP_PKEY_get_octet_string_param(k, name, NULL, 0, &n) <= 0 || n == 0)
        return 0;
    if ((*buf = OPENSSL_malloc(n)) == NULL)
        return 0;
    if (EVP_PKEY_get_octet_string_param(k, name, *buf, n, len) <= 0) {
        OPENSSL_free(*buf);
        *buf = NULL;
        return 0;
    }
    return 1;
}

/* Extract a component: SPKI DER param -> standalone EVP_PKEY. */
static EVP_PKEY *extract(OSSL_LIB_CTX *ctx, EVP_PKEY *k, const char *pname)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    size_t n = 0;
    EVP_PKEY *comp = NULL;

    if (!get_octet(k, pname, &der, &n))
        return NULL;
    p = der;
    comp = d2i_PUBKEY_ex(NULL, &p, (long)n, ctx, NULL);
    OPENSSL_free(der);
    return comp;
}

/* Re-import a hybrid/composite public key from a concatenated blob. */
static EVP_PKEY *import_pub(OSSL_LIB_CTX *ctx, const char *alg,
                           const unsigned char *blob, size_t len)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *k = NULL;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                             (void *)blob, len);
    p[1] = OSSL_PARAM_construct_end();
    if (c != NULL && EVP_PKEY_fromdata_init(c) > 0)
        EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, p);
    EVP_PKEY_CTX_free(c);
    return k;
}

/* The composite SPKI BIT STRING payload (the concatenated component pub blob). */
static int composite_spki_bits(EVP_PKEY *k, unsigned char **out, size_t *outlen)
{
    unsigned char *spki = NULL;
    const unsigned char *pp;
    X509_PUBKEY *xp = NULL;
    const unsigned char *pk = NULL;
    int spkilen, pklen = 0, ret = 0;

    if ((spkilen = i2d_PUBKEY(k, &spki)) <= 0)
        return 0;
    pp = spki;
    if ((xp = d2i_X509_PUBKEY(NULL, &pp, spkilen)) == NULL
            || !X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, xp))
        goto end;
    if ((*out = OPENSSL_memdup(pk, pklen)) == NULL)
        goto end;
    *outlen = (size_t)pklen;
    ret = 1;
end:
    X509_PUBKEY_free(xp);
    OPENSSL_free(spki);
    return ret;
}

static void check(OSSL_LIB_CTX *ctx, const char *alg, enum family fam,
                  const char *want_classic, const char *want_pq)
{
    EVP_PKEY *key = NULL, *c = NULL, *q = NULL, *composed_key = NULL;
    unsigned char *craw = NULL, *qraw = NULL, *blob = NULL, *composed = NULL;
    size_t clen = 0, qlen = 0, blen = 0, comlen = 0;
    const char *cn, *qn;

    tests++;
    printf("  %-22s (%-9s) extract/parity/compose ... ",
           alg, fam == HYBRID ? "hybrid" : "composite");
    fflush(stdout);

    if ((key = gen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    /* (1) extraction -> usable standalone EVP_PKEYs of the expected algorithms */
    c = extract(ctx, key, HYBRID_PKEY_PARAM_CLASSIC_PUB);
    q = extract(ctx, key, HYBRID_PKEY_PARAM_PQ_PUB);
    if (c == NULL || q == NULL) {
        printf("FAIL (component extraction)\n");
        ERR_print_errors_fp(stdout); failed++; goto done;
    }
    cn = EVP_PKEY_get0_type_name(c);
    qn = EVP_PKEY_get0_type_name(q);
    if (EVP_PKEY_get_bits(c) <= 0 || EVP_PKEY_get_bits(q) <= 0
            || cn == NULL || strcmp(cn, want_classic) != 0
            || qn == NULL || strcmp(qn, want_pq) != 0) {
        printf("FAIL (extracted classic=%s/%s pq=%s/%s)\n",
               cn ? cn : "?", want_classic, qn ? qn : "?", want_pq);
        failed++; goto done;
    }

    /* raw public keys of the extracted components */
    if (!get_octet(c, OSSL_PKEY_PARAM_PUB_KEY, &craw, &clen)
            || !get_octet(q, OSSL_PKEY_PARAM_PUB_KEY, &qraw, &qlen)) {
        printf("FAIL (component raw pub)\n");
        ERR_print_errors_fp(stdout); failed++; goto done;
    }

    /* (2) inner == standalone parity, and build the composition blob */
    if (fam == HYBRID) {
        /* concatenated PUB_KEY must be exactly the two components' raw pubs;
         * the order is algorithm-specific, so accept either and rebuild it. */
        if (!get_octet(key, OSSL_PKEY_PARAM_PUB_KEY, &blob, &blen)
                || blen != clen + qlen) {
            printf("FAIL (hybrid pub blob length)\n");
            ERR_print_errors_fp(stdout); failed++; goto done;
        }
        composed = OPENSSL_malloc(blen);
        if (memcmp(blob, craw, clen) == 0
                && memcmp(blob + clen, qraw, qlen) == 0) {
            memcpy(composed, craw, clen);
            memcpy(composed + clen, qraw, qlen);
        } else if (memcmp(blob, qraw, qlen) == 0
                && memcmp(blob + qlen, craw, clen) == 0) {
            memcpy(composed, qraw, qlen);
            memcpy(composed + qlen, craw, clen);
        } else {
            printf("FAIL (hybrid inner!=standalone parity)\n");
            failed++; goto done;
        }
        comlen = blen;
    } else {
        /* composite SPKI BIT STRING must be exactly pqPub || tradPub (draft-19) */
        if (!composite_spki_bits(key, &blob, &blen)) {
            printf("FAIL (composite SPKI decode)\n");
            ERR_print_errors_fp(stdout); failed++; goto done;
        }
        comlen = qlen + clen;
        composed = OPENSSL_malloc(comlen);
        memcpy(composed, qraw, qlen);
        memcpy(composed + qlen, craw, clen);
        if (blen != comlen || memcmp(blob, composed, comlen) != 0) {
            printf("FAIL (composite inner!=standalone parity)\n");
            failed++; goto done;
        }
    }

    /* (3) composition: re-import the rebuilt blob -> must equal the original */
    composed_key = import_pub(ctx, alg, composed, comlen);
    if (composed_key == NULL || EVP_PKEY_eq(composed_key, key) != 1) {
        printf("FAIL (compose/re-import mismatch)\n");
        ERR_print_errors_fp(stdout); failed++; goto done;
    }

    printf("PASS (classic=%s pq=%s)\n", cn, qn);
    passed++;
done:
    OPENSSL_free(craw);
    OPENSSL_free(qraw);
    OPENSSL_free(blob);
    OPENSSL_free(composed);
    EVP_PKEY_free(c);
    EVP_PKEY_free(q);
    EVP_PKEY_free(composed_key);
    EVP_PKEY_free(key);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");

    /* Serve the MLX KEMs from the hybrid provider (not ceded to default). */
    setenv("HYBRID_CEDE_TO_DEFAULT", "0", 1);

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    ERR_clear_error();

    printf("hybrid/composite component extraction & composition\n");
    printf("===================================================\n");

    /* One representative per family/component-shape; the extraction code path is
     * identical across the tables, so this covers EC, X25519, Ed25519, ML-DSA and
     * ML-KEM component encodings without enumerating every row. */
    check(ctx, "p256_mldsa44",      HYBRID,    "EC",      "ML-DSA-44");   /* sig */
    check(ctx, "SecP256r1MLKEM768", HYBRID,    "EC",      "ML-KEM-768");  /* KEM */
    check(ctx, "X25519MLKEM768",    HYBRID,    "X25519",  "ML-KEM-768");  /* KEM */
    check(ctx, "mldsa44_ed25519",   COMPOSITE, "ED25519", "ML-DSA-44");   /* comp */

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
