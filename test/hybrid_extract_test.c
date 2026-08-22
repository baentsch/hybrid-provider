/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Component extraction / composition (work-items item 13).
 *
 * A hybrid/composite key composes a classical component and a PQ component, each
 * a real EVP_PKEY. This test proves, over the public EVP API only and driven off
 * the master algorithm tables (no hardcoded combos), that the provider now
 * supports:
 *
 *   (1) EXTRACTION as usable, standalone key objects — both halves. Each
 *       component's public key is exposed as a SubjectPublicKeyInfo DER
 *       (HYBRID_PKEY_PARAM_*_PUB, d2i_PUBKEY) and, for a private key, its private
 *       half as a PKCS#8 PrivateKeyInfo DER (HYBRID_PKEY_PARAM_*_PRIV,
 *       d2i_PKCS8_PRIV_KEY_INFO -> EVP_PKCS82PKEY). We reconstruct standalone
 *       EVP_PKEYs and check pub/priv are consistent (EVP_PKEY_eq of the extracted
 *       private against the extracted public), which also proves they are usable.
 *
 *   (2) INNER == STANDALONE parity. The bytes a component contributes to the
 *       container equal that component's standalone encoding. For the hybrid
 *       family the concatenated OSSL_PKEY_PARAM_PUB_KEY is exactly the two
 *       components' raw public keys; for the composite family the SPKI BIT STRING
 *       is exactly pqPub || tradPub (draft-19).
 *
 *   (3) COMPOSITION. Rebuild the container's public blob from the two extracted
 *       components' raw public keys and re-import it (EVP_PKEY_fromdata); the
 *       composed key must compare equal (EVP_PKEY_eq) to the original.
 *
 * Every row of hybrid_kem_table, hybrid_sig_table and (when built)
 * composite_sig_table is exercised; a row whose components are unavailable on the
 * running provider mix self-skips. Cede-to-default is switched off so the hybrid
 * provider serves the MLX groups the default provider also offers.
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
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
#endif

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

/*
 * Can the PQ component be generated in the running provider mix? Probes the exact
 * fetch name the provider uses internally for the component (hybrid_component_keygen
 * calls EVP_PKEY_CTX_new_from_name with this same name), so a failure here means
 * the component's provider is genuinely absent — the row self-skips — as opposed
 * to a hybrid keygen failure with the component present, which is a real bug.
 */
static int pq_available(OSSL_LIB_CTX *ctx, const char *pq_alg)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, pq_alg, NULL);
    EVP_PKEY *k = NULL;
    int ok = 0;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &k) > 0)
        ok = 1;
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

/*
 * Can a standalone key of this PQ algorithm be serialized to SubjectPublicKeyInfo
 * *and* PKCS#8 by its own provider? If yes, the hybrid's component extraction must
 * succeed too, so an extraction failure is a real bug (FAIL) — not a skip. If no
 * (the oqs research KEMs Frodo/BIKE/HQC, which get no standalone encoding even
 * with OQS_KEM_ENCODERS=ON — they carry no OID for the encode path), extraction
 * genuinely cannot work and the row legitimately self-skips. This mirrors exactly
 * what the provider's extraction params do (i2d_PUBKEY / EVP_PKEY2PKCS8 on the
 * component), so it keeps skips trustworthy without hardcoding an allowlist.
 */
static int pq_serializable(OSSL_LIB_CTX *ctx, const char *pq_alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, pq_alg, NULL);
    EVP_PKEY *k = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    unsigned char *der = NULL;
    int ok = 0;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0 && EVP_PKEY_keygen(g, &k) > 0
            && i2d_PUBKEY(k, &der) > 0
            && (p8 = EVP_PKEY2PKCS8(k)) != NULL)
        ok = 1;
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_free(der);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(g);
    ERR_clear_error();
    return ok;
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

/* Extract a component public key: SPKI DER param -> standalone EVP_PKEY. */
static EVP_PKEY *extract_pub(OSSL_LIB_CTX *ctx, EVP_PKEY *k, const char *pname)
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

/* Extract a component private key: PKCS#8 DER param -> standalone EVP_PKEY. */
static EVP_PKEY *extract_priv(OSSL_LIB_CTX *ctx, EVP_PKEY *k, const char *pname)
{
    unsigned char *der = NULL;
    const unsigned char *p;
    size_t n = 0;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    EVP_PKEY *comp = NULL;

    if (!get_octet(k, pname, &der, &n))
        return NULL;
    p = der;
    if ((p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)n)) != NULL)
        comp = EVP_PKCS82PKEY_ex(p8, ctx, NULL);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_clear_free(der, n);
    return comp;
}

/*
 * A component's raw public key: the OSSL_PKEY_PARAM_PUB_KEY octet where the
 * component exposes one (EC point, ECX/Ed raw, ML-KEM/ML-DSA encoded pub), else
 * i2d_PublicKey (RSA). This mirrors how the provider lays each component into the
 * concatenated container blob, so the two are byte-comparable.
 */
static int raw_pub(EVP_PKEY *k, unsigned char **buf, size_t *len)
{
    int dlen;

    if (get_octet(k, OSSL_PKEY_PARAM_PUB_KEY, buf, len))
        return 1;
    ERR_clear_error();
    *buf = NULL;
    if ((dlen = i2d_PublicKey(k, buf)) <= 0)
        return 0;
    *len = (size_t)dlen;
    return 1;
}

#ifdef HYBRID_COMPOSITE
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
#endif /* HYBRID_COMPOSITE */

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

static void check(OSSL_LIB_CTX *ctx, const char *alg, enum family fam,
                  const char *pq_alg)
{
    EVP_PKEY *key = NULL, *cpub = NULL, *qpub = NULL;
    EVP_PKEY *cpriv = NULL, *qpriv = NULL, *composed_key = NULL;
    unsigned char *craw = NULL, *qraw = NULL, *blob = NULL, *composed = NULL;
    size_t clen = 0, qlen = 0, blen = 0, comlen = 0;

    tests++;
    printf("  %-24s (%-9s) ... ", alg, fam == HYBRID ? "hybrid" : "composite");
    fflush(stdout);

    if ((key = gen(ctx, alg)) == NULL) {
        /* A keygen failure is only benign when a component provider is absent
         * (the PQ half — the classical half is always default-provider). If the
         * PQ component *can* be generated here, hybrid keygen must not fail. */
        if (!pq_available(ctx, pq_alg)) {
            printf("SKIP (PQ component provider absent)\n");
            skipped++; tests--; ERR_clear_error();
        } else {
            printf("FAIL (keygen)\n");
            ERR_print_errors_fp(stdout); failed++;
        }
        goto done;
    }

    /* (1) public + private extraction -> usable standalone EVP_PKEYs, and the
     * private half's public part matches the extracted public half.
     *
     * The classical component is always serializable, so its extraction must
     * succeed. The PQ component depends on its provider producing a standalone
     * encoding: ML-KEM/ML-DSA (default) and the oqs *signature* families do, but
     * the oqs research *KEMs* (FrodoKEM/BIKE/HQC) do not — even with oqsprovider
     * built with OQS_KEM_ENCODERS they carry no OID for the encode path, so no
     * standalone SPKI/PKCS8 is produced (cf. issue #19). Such a row self-skips,
     * but only after pq_serializable() confirms the component genuinely cannot be
     * serialized standalone — otherwise a failed extraction is a real FAIL. */
    cpub = extract_pub(ctx, key, HYBRID_PKEY_PARAM_CLASSIC_PUB);
    cpriv = extract_priv(ctx, key, HYBRID_PKEY_PARAM_CLASSIC_PRIV);
    if (cpub == NULL || cpriv == NULL) {
        printf("FAIL (classical extraction: pub=%d priv=%d)\n",
               cpub != NULL, cpriv != NULL);
        ERR_print_errors_fp(stdout); failed++; goto done;
    }
    if (EVP_PKEY_eq(cpriv, cpub) != 1) {
        printf("FAIL (classical priv/pub inconsistent)\n");
        failed++; goto done;
    }
    qpub = extract_pub(ctx, key, HYBRID_PKEY_PARAM_PQ_PUB);
    qpriv = extract_priv(ctx, key, HYBRID_PKEY_PARAM_PQ_PRIV);
    if (qpub == NULL || qpriv == NULL) {
        /* Only a genuine "component cannot be serialized standalone" is a skip;
         * if the component IS serializable, the hybrid must extract it too. */
        if (pq_serializable(ctx, pq_alg)) {
            printf("FAIL (PQ extraction pub=%d priv=%d, but component IS "
                   "serializable standalone)\n", qpub != NULL, qpriv != NULL);
            ERR_print_errors_fp(stdout); failed++;
        } else {
            printf("SKIP (PQ component not serializable by its provider)\n");
            skipped++; tests--; ERR_clear_error();
        }
        goto done;
    }
    if (EVP_PKEY_eq(qpriv, qpub) != 1) {
        printf("FAIL (PQ priv/pub inconsistent)\n");
        failed++; goto done;
    }

    /* raw public keys of the extracted components */
    if (!raw_pub(cpub, &craw, &clen) || !raw_pub(qpub, &qraw, &qlen)) {
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
    }
#ifdef HYBRID_COMPOSITE
    else {
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
#endif /* HYBRID_COMPOSITE */

    /* (3) composition: re-import the rebuilt blob -> must equal the original */
    composed_key = import_pub(ctx, alg, composed, comlen);
    if (composed_key == NULL || EVP_PKEY_eq(composed_key, key) != 1) {
        printf("FAIL (compose/re-import mismatch)\n");
        ERR_print_errors_fp(stdout); failed++; goto done;
    }

    printf("PASS (classic=%s pq=%s)\n",
           EVP_PKEY_get0_type_name(cpub), EVP_PKEY_get0_type_name(qpub));
    passed++;
done:
    OPENSSL_free(craw);
    OPENSSL_free(qraw);
    OPENSSL_free(blob);
    OPENSSL_free(composed);
    EVP_PKEY_free(cpub);
    EVP_PKEY_free(qpub);
    EVP_PKEY_free(cpriv);
    EVP_PKEY_free(qpriv);
    EVP_PKEY_free(composed_key);
    EVP_PKEY_free(key);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    /* Serve the MLX KEMs from the hybrid provider (not ceded to default). */
    setenv("HYBRID_CEDE_TO_DEFAULT", "0", 1);

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        return 1;
    }
    /* oqsprovider is optional: rows needing it self-skip when it is absent. */
    OSSL_PROVIDER_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("hybrid/composite component extraction & composition\n");
    printf("===================================================\n");

    /* Every row of the master tables — no hardcoded combos. The PQ component
     * name (alg2/pq_alg) lets a row tell a genuine keygen bug from a component
     * whose provider simply is not loaded here. */
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check(ctx, hybrid_kem_table[i].hybrid_name, HYBRID,
              hybrid_kem_table[i].alg2_name);
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        check(ctx, hybrid_sig_table[i].hybrid_name, HYBRID,
              hybrid_sig_table[i].alg2_name);
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check(ctx, composite_sig_table[i].name, COMPOSITE,
              composite_sig_table[i].pq_alg);
#endif

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
