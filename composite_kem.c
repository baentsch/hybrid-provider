/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) ML-KEM combiner — the cryptographic core of the composite-KEM
 * family, kept independent of the provider plumbing so it can be unit-tested
 * directly with EVP-generated component keys (test/composite_kem_test.c).
 *
 * draft-ietf-lamps-pq-composite-kem-18 (combiner unchanged since -14):
 *     ss = SHA3-256( mlkemSS || tradSS || tradCT || tradPK || Label )
 * with the component encodings documented in composite_kem_prov.h. Everything is
 * fixed-size per OID, so there is no length prefixing and the composite ciphertext
 * mlkemCT||tradCT splits at the (fixed) ML-KEM ciphertext length.
 *
 * SCOPE / caveats:
 *  - EC/X (DHKEM) combos reuse the same ephemeral-keygen + EVP_PKEY_derive shape
 *    as hybrid_kem.c and are validated byte-for-byte by the draft KAT vectors.
 *  - RSA-OAEP combos carry a fresh 32-byte tradSS under RSA-OAEP(SHA-256). The
 *    encoding of tradPK fed to the combiner for RSA is i2d_PublicKey (RSAPublicKey
 *    DER); both encaps and decaps use the same bytes, so round-trip holds — draft
 *    KAT fidelity for the RSA combos is a follow-up (see the composite-KEM plan).
 */
#include "composite_kem_prov.h"
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>

/*
 * Classify the traditional component so the RSA-vs-DH dispatch below is explicit
 * rather than "RSA-OAEP, else assume EC/X": an unrecognized trad_alg (e.g. a new
 * table row added for research) is rejected here instead of being silently fed
 * into the DH path. trad_alg is a compile-time-fixed value from the combo table,
 * so this only ever fails on a programming error, but it keeps the combiner
 * honest as the table grows. Returns 1 and sets *is_dh; 0 (with an error) if the
 * trad_alg is not one this combiner knows how to drive.
 */
static int trad_classify(const COMPOSITE_KEM_INFO *info, int *is_dh)
{
    if (strcmp(info->trad_alg, "RSA-OAEP") == 0) {
        *is_dh = 0;
        return 1;
    }
    if (strcmp(info->trad_alg, "EC") == 0
            || strcmp(info->trad_alg, "X25519") == 0
            || strcmp(info->trad_alg, "X448") == 0) {
        *is_dh = 1;
        return 1;
    }
    ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                   "composite-KEM: unsupported traditional algorithm '%s'",
                   info->trad_alg);
    return 0;
}

int composite_kem_combine(OSSL_LIB_CTX *libctx,
                          const unsigned char *mlkemss, size_t mlkemsslen,
                          const unsigned char *tradss, size_t tradsslen,
                          const unsigned char *tradct, size_t tradctlen,
                          const unsigned char *tradpk, size_t tradpklen,
                          const unsigned char *label, size_t labellen,
                          unsigned char *ss_out)
{
    /* Provider-neutral combiner digest: from the provider's libctx with default
     * properties. No component propquery — those steer the PQ/classical
     * providers, which need not supply SHA3. */
    EVP_MD *sha3 = EVP_MD_fetch(libctx, "SHA3-256", NULL);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    unsigned int outlen = 0;
    int ret = 0;

    if (sha3 == NULL || mc == NULL
            || EVP_DigestInit_ex2(mc, sha3, NULL) <= 0
            || EVP_DigestUpdate(mc, mlkemss, mlkemsslen) <= 0
            || EVP_DigestUpdate(mc, tradss, tradsslen) <= 0
            || EVP_DigestUpdate(mc, tradct, tradctlen) <= 0
            || EVP_DigestUpdate(mc, tradpk, tradpklen) <= 0
            || EVP_DigestUpdate(mc, label, labellen) <= 0
            || EVP_DigestFinal_ex(mc, ss_out, &outlen) <= 0
            || outlen != COMPOSITE_KEM_SS_BYTES)
        goto end;
    ret = 1;
end:
    EVP_MD_CTX_free(mc);
    EVP_MD_free(sha3);
    return ret;
}

/* Recipient/ephemeral public key bytes as fed to the combiner (tradPK / tradCT):
 * the raw encoded public key for EC (uncompressed point) and X (raw octets), or
 * i2d_PublicKey (RSAPublicKey DER) for RSA. Caller frees *buf. */
static int trad_pub_bytes(const COMPOSITE_KEM_INFO *info, EVP_PKEY *pkey,
                          unsigned char **buf, size_t *len)
{
    int is_dh;

    if (!trad_classify(info, &is_dh))
        return 0;
    if (!is_dh) {                          /* RSA-OAEP: RSAPublicKey DER */
        unsigned char *der = NULL;
        int dlen = i2d_PublicKey(pkey, &der);

        if (dlen <= 0)
            return 0;
        *buf = der;
        *len = (size_t)dlen;
        return 1;
    }
    /* EC / X25519 / X448: the encoded public key octets. */
    {
        size_t n = 0;

        if (EVP_PKEY_get_octet_string_param(pkey,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0, &n) <= 0 || n == 0)
            return 0;
        if ((*buf = OPENSSL_malloc(n)) == NULL
                || EVP_PKEY_get_octet_string_param(pkey,
                       OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, *buf, n, len) <= 0) {
            OPENSSL_free(*buf);
            *buf = NULL;
            return 0;
        }
        return 1;
    }
}

/* RSA-OAEP context configured per draft §6.1 (SHA-256, MGF1-SHA-256, empty pSource). */
static EVP_PKEY_CTX *rsa_oaep_ctx(OSSL_LIB_CTX *libctx, const char *propq,
                                  EVP_PKEY *key, int encrypt)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(libctx, key, propq);
    EVP_MD *md = EVP_MD_fetch(libctx, COMPOSITE_KEM_RSA_OAEP_MD, propq);

    if (c == NULL || md == NULL)
        goto err;
    if ((encrypt ? EVP_PKEY_encrypt_init(c) : EVP_PKEY_decrypt_init(c)) <= 0
            || EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_oaep_md(c, md) <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(c, md) <= 0)
        goto err;
    EVP_MD_free(md);
    return c;
err:
    EVP_MD_free(md);
    EVP_PKEY_CTX_free(c);
    return NULL;
}

/* Traditional encapsulation: produce tradCT and tradSS (both malloc'd). */
static int trad_encaps(const COMPOSITE_KEM_INFO *info, EVP_PKEY *trad_pub,
                       OSSL_LIB_CTX *libctx, const char *propq,
                       unsigned char **ct, size_t *ctlen,
                       unsigned char **ss, size_t *sslen)
{
    int is_dh;

    if (!trad_classify(info, &is_dh))
        return 0;
    if (!is_dh) {                          /* RSA-OAEP */
        EVP_PKEY_CTX *c = rsa_oaep_ctx(libctx, propq, trad_pub, 1);
        unsigned char *sec = NULL, *out = NULL;
        size_t outlen = 0;
        int ret = 0;

        if (c == NULL)
            goto rerr;
        if ((sec = OPENSSL_malloc(COMPOSITE_KEM_SS_BYTES)) == NULL
                || RAND_bytes_ex(libctx, sec, COMPOSITE_KEM_SS_BYTES, 0) <= 0)
            goto rerr;
        if (EVP_PKEY_encrypt(c, NULL, &outlen, sec, COMPOSITE_KEM_SS_BYTES) <= 0
                || (out = OPENSSL_malloc(outlen)) == NULL
                || EVP_PKEY_encrypt(c, out, &outlen, sec,
                                    COMPOSITE_KEM_SS_BYTES) <= 0)
            goto rerr;
        *ct = out; *ctlen = outlen; out = NULL;
        *ss = sec; *sslen = COMPOSITE_KEM_SS_BYTES; sec = NULL;
        ret = 1;
rerr:
        OPENSSL_free(out);
        OPENSSL_clear_free(sec, COMPOSITE_KEM_SS_BYTES);
        EVP_PKEY_CTX_free(c);
        return ret;
    }

    /* EC / X25519 / X448: ephemeral keygen, tradCT = ephemeral pub, tradSS = DH. */
    {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_pkey(libctx, trad_pub, propq);
        EVP_PKEY_CTX *dctx = NULL;
        EVP_PKEY *eph = NULL;
        size_t n = 0;
        int ret = 0;

        if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0
                || EVP_PKEY_keygen(kctx, &eph) <= 0)
            goto eerr;
        if (!trad_pub_bytes(info, eph, ct, ctlen))
            goto eerr;
        dctx = EVP_PKEY_CTX_new_from_pkey(libctx, eph, propq);
        if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0
                || EVP_PKEY_derive_set_peer(dctx, trad_pub) <= 0
                || EVP_PKEY_derive(dctx, NULL, &n) <= 0
                || (*ss = OPENSSL_malloc(n)) == NULL
                || EVP_PKEY_derive(dctx, *ss, &n) <= 0) {
            OPENSSL_free(*ct); *ct = NULL;
            goto eerr;
        }
        *sslen = n;
        ret = 1;
eerr:
        EVP_PKEY_free(eph);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_CTX_free(dctx);
        return ret;
    }
}

/* Traditional decapsulation from tradCT: recover tradSS (malloc'd). */
static int trad_decaps(const COMPOSITE_KEM_INFO *info, EVP_PKEY *trad_priv,
                       OSSL_LIB_CTX *libctx, const char *propq,
                       const unsigned char *ct, size_t ctlen,
                       unsigned char **ss, size_t *sslen)
{
    int is_dh;

    if (!trad_classify(info, &is_dh))
        return 0;
    if (!is_dh) {                          /* RSA-OAEP */
        EVP_PKEY_CTX *c = rsa_oaep_ctx(libctx, propq, trad_priv, 0);
        unsigned char *out = NULL;
        size_t outlen = 0;
        int ret = 0;

        if (c == NULL
                || EVP_PKEY_decrypt(c, NULL, &outlen, ct, ctlen) <= 0
                || (out = OPENSSL_malloc(outlen)) == NULL
                || EVP_PKEY_decrypt(c, out, &outlen, ct, ctlen) <= 0)
            goto rerr;
        *ss = out; *sslen = outlen; out = NULL;
        ret = 1;
rerr:
        OPENSSL_clear_free(out, outlen);
        EVP_PKEY_CTX_free(c);
        return ret;
    }

    /* EC / X: rebuild the peer (ephemeral) public key from tradCT, then derive. */
    {
        EVP_PKEY *peer = EVP_PKEY_new();
        EVP_PKEY_CTX *dctx = NULL;
        size_t n = 0;
        int ret = 0;

        if (peer == NULL
                || EVP_PKEY_copy_parameters(peer, trad_priv) <= 0
                || EVP_PKEY_set1_encoded_public_key(peer, ct, ctlen) <= 0)
            goto derr;
        dctx = EVP_PKEY_CTX_new_from_pkey(libctx, trad_priv, propq);
        if (dctx == NULL || EVP_PKEY_derive_init(dctx) <= 0
                || EVP_PKEY_derive_set_peer(dctx, peer) <= 0
                || EVP_PKEY_derive(dctx, NULL, &n) <= 0
                || (*ss = OPENSSL_malloc(n)) == NULL
                || EVP_PKEY_derive(dctx, *ss, &n) <= 0)
            goto derr;
        *sslen = n;
        ret = 1;
derr:
        EVP_PKEY_free(peer);
        EVP_PKEY_CTX_free(dctx);
        return ret;
    }
}

/* Fixed PQ ciphertext length for this combo, learned from a FRESH keypair rather
 * than the decapsulation private key: a private key reconstructed from a raw octet
 * (the experimental tier) may lack the public key that the encaps size query
 * needs, whereas the ciphertext length is a fixed scheme parameter, so any
 * freshly generated key of the same algorithm yields it. */
static size_t pq_ct_len(const char *pq_alg, OSSL_LIB_CTX *libctx,
                        const char *propq)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(libctx, pq_alg, propq);
    EVP_PKEY_CTX *e = NULL;
    EVP_PKEY *t = NULL;
    size_t ctlen = 0, sslen = 0;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0 && EVP_PKEY_keygen(g, &t) > 0
            && (e = EVP_PKEY_CTX_new_from_pkey(libctx, t, propq)) != NULL
            && EVP_PKEY_encapsulate_init(e, NULL) > 0)
        EVP_PKEY_encapsulate(e, NULL, &ctlen, NULL, &sslen);
    EVP_PKEY_CTX_free(e);
    EVP_PKEY_free(t);
    EVP_PKEY_CTX_free(g);
    return ctlen;
}

/* Cheap PQ ciphertext length: an encaps size query on the actual key. Returns 0
 * when the key cannot encapsulate — e.g. a private key reconstructed from a raw
 * octet (the experimental tier), which has no public half — so the caller falls
 * back to pq_ct_len (a throwaway keypair). Keygen'd keys keep their public half,
 * so this avoids the keygen entirely for them. */
static size_t pq_encaps_ctlen(EVP_PKEY *pq_key, OSSL_LIB_CTX *libctx,
                              const char *propq)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(libctx, pq_key, propq);
    size_t ctlen = 0, sslen = 0;

    if (c != NULL && EVP_PKEY_encapsulate_init(c, NULL) > 0)
        EVP_PKEY_encapsulate(c, NULL, &ctlen, NULL, &sslen);
    EVP_PKEY_CTX_free(c);
    return ctlen;
}

int composite_kem_encaps(const COMPOSITE_KEM_INFO *info,
                         EVP_PKEY *pq_pub, EVP_PKEY *trad_pub,
                         OSSL_LIB_CTX *libctx, const char *pq_propq,
                         const char *trad_propq,
                         unsigned char **ct, size_t *ctlen,
                         unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pq_pub, pq_propq);
    unsigned char *mlct = NULL, *mlss = NULL, *trct = NULL, *trss = NULL,
                  *trpk = NULL;
    unsigned char out_ss[COMPOSITE_KEM_SS_BYTES];
    size_t mlctlen = 0, mlsslen = 0;
    size_t trctlen = 0, trsslen = 0, trpklen = 0;
    int ret = 0;

    *ct = NULL; *ss = NULL;
    /* PQ KEM encapsulation -> pqCT, pqSS. The PQ shared-secret length is queried,
     * not assumed to be ML-KEM's 32 bytes, so a non-ML-KEM PQ component with a
     * different SS length (e.g. HQC's 64) works — the combiner just hashes it. */
    if (pctx == NULL || EVP_PKEY_encapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_encapsulate(pctx, NULL, &mlctlen, NULL, &mlsslen) <= 0
            || (mlct = OPENSSL_malloc(mlctlen)) == NULL
            || (mlss = OPENSSL_malloc(mlsslen)) == NULL
            || EVP_PKEY_encapsulate(pctx, mlct, &mlctlen, mlss, &mlsslen) <= 0)
        goto end;
    /* Traditional encapsulation -> tradCT, tradSS; plus tradPK for the combiner. */
    if (!trad_encaps(info, trad_pub, libctx, trad_propq,
                     &trct, &trctlen, &trss, &trsslen)
            || !trad_pub_bytes(info, trad_pub, &trpk, &trpklen))
        goto end;
    if (!composite_kem_combine(libctx, mlss, mlsslen, trss, trsslen,
                               trct, trctlen, trpk, trpklen,
                               (const unsigned char *)info->label,
                               strlen(info->label), out_ss))
        goto end;
    /* composite ciphertext = mlkemCT || tradCT (PQ first). */
    if ((*ct = OPENSSL_malloc(mlctlen + trctlen)) == NULL)
        goto end;
    memcpy(*ct, mlct, mlctlen);
    memcpy(*ct + mlctlen, trct, trctlen);
    *ctlen = mlctlen + trctlen;
    if ((*ss = OPENSSL_malloc(COMPOSITE_KEM_SS_BYTES)) == NULL) {
        OPENSSL_free(*ct); *ct = NULL;
        goto end;
    }
    memcpy(*ss, out_ss, COMPOSITE_KEM_SS_BYTES);
    *sslen = COMPOSITE_KEM_SS_BYTES;
    ret = 1;
end:
    OPENSSL_clear_free(mlss, mlsslen);
    OPENSSL_cleanse(out_ss, sizeof(out_ss));
    OPENSSL_free(mlct);
    OPENSSL_free(trct);
    OPENSSL_clear_free(trss, trsslen);
    OPENSSL_free(trpk);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

int composite_kem_decaps(const COMPOSITE_KEM_INFO *info,
                         EVP_PKEY *pq_priv, EVP_PKEY *trad_priv,
                         OSSL_LIB_CTX *libctx, const char *pq_propq,
                         const char *trad_propq,
                         const unsigned char *ct, size_t ctlen,
                         unsigned char **ss, size_t *sslen,
                         size_t *pq_ctlen)
{
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *mlss = NULL, *trss = NULL, *trpk = NULL;
    unsigned char out_ss[COMPOSITE_KEM_SS_BYTES];
    size_t mlsslen = 0, trsslen = 0, trpklen = 0, mlctlen;
    int ret = 0;

    *ss = NULL;
    /* The PQ ciphertext length is fixed per algorithm — learn it once and memoize
     * via *pq_ctlen (the provider passes its per-key cache). Cheap path: an encaps
     * size query on the actual private key (works, and no keygen, when the key
     * carries its public half); fall back to a throwaway keypair for a private key
     * reconstructed from a raw octet, which cannot encapsulate. */
    if (pq_ctlen != NULL && *pq_ctlen != 0) {
        mlctlen = *pq_ctlen;
    } else {
        mlctlen = pq_encaps_ctlen(pq_priv, libctx, pq_propq);
        if (mlctlen == 0)
            mlctlen = pq_ct_len(info->pq_alg, libctx, pq_propq);
        if (pq_ctlen != NULL)
            *pq_ctlen = mlctlen;
    }
    if (mlctlen == 0 || mlctlen >= ctlen)   /* need both components present */
        goto end;
    /* PQ KEM decapsulation of the leading pqCT. The PQ shared-secret length is
     * queried (NULL-buffer size call) rather than assumed to be 32, so non-ML-KEM
     * PQ components (e.g. HQC's 64-byte SS) work. */
    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, pq_priv, pq_propq);
    if (pctx == NULL || EVP_PKEY_decapsulate_init(pctx, NULL) <= 0
            || EVP_PKEY_decapsulate(pctx, NULL, &mlsslen, ct, mlctlen) <= 0
            || (mlss = OPENSSL_malloc(mlsslen)) == NULL
            || EVP_PKEY_decapsulate(pctx, mlss, &mlsslen, ct, mlctlen) <= 0)
        goto end;
    /* Traditional decapsulation of the trailing tradCT; own tradPK for combiner. */
    if (!trad_decaps(info, trad_priv, libctx, trad_propq,
                     ct + mlctlen, ctlen - mlctlen, &trss, &trsslen)
            || !trad_pub_bytes(info, trad_priv, &trpk, &trpklen))
        goto end;
    if (!composite_kem_combine(libctx, mlss, mlsslen, trss, trsslen,
                               ct + mlctlen, ctlen - mlctlen, trpk, trpklen,
                               (const unsigned char *)info->label,
                               strlen(info->label), out_ss))
        goto end;
    if ((*ss = OPENSSL_malloc(COMPOSITE_KEM_SS_BYTES)) == NULL)
        goto end;
    memcpy(*ss, out_ss, COMPOSITE_KEM_SS_BYTES);
    *sslen = COMPOSITE_KEM_SS_BYTES;
    ret = 1;
end:
    OPENSSL_clear_free(mlss, mlsslen);
    OPENSSL_cleanse(out_ss, sizeof(out_ss));
    OPENSSL_clear_free(trss, trsslen);
    OPENSSL_free(trpk);
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

/* --- Provider KEM dispatch (wraps the combiner over a COMPOSITE_KEM_KEY) --- */

typedef struct {
    COMPOSITE_KEM_KEY *key;
    int op;
} COMPOSITE_KEM_CTX;

static void *composite_kem_newctx(void *provctx)
{
    return OPENSSL_zalloc(sizeof(COMPOSITE_KEM_CTX));
}

static void composite_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static void *composite_kem_dupctx(void *vctx)
{
    COMPOSITE_KEM_CTX *c = OPENSSL_zalloc(sizeof(*c));

    if (c != NULL)
        *c = *(COMPOSITE_KEM_CTX *)vctx;
    return c;
}

static int composite_kem_encaps_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    COMPOSITE_KEM_CTX *c = vctx;
    COMPOSITE_KEM_KEY *k = vkey;

    if (k == NULL || k->state < COMPOSITE_KEM_HAVE_PUBKEY)
        return 0;
    c->key = k;
    return 1;
}

static int composite_kem_decaps_init(void *vctx, void *vkey,
                                     const OSSL_PARAM params[])
{
    COMPOSITE_KEM_CTX *c = vctx;
    COMPOSITE_KEM_KEY *k = vkey;

    if (k == NULL || k->state < COMPOSITE_KEM_HAVE_PRVKEY)
        return 0;
    c->key = k;
    return 1;
}

static int composite_kem_encapsulate(void *vctx,
                                     unsigned char *ctext, size_t *clen,
                                     unsigned char *shsec, size_t *slen)
{
    COMPOSITE_KEM_CTX *c = vctx;
    COMPOSITE_KEM_KEY *k = c->key;
    unsigned char *ct = NULL, *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    int ret = 0;

    if (ctext == NULL) {   /* size query: encapsulate once to learn the length */
        if (!composite_kem_encaps(k->info, k->pq_key, k->trad_key, k->libctx,
                                  k->pq_propq, k->trad_propq,
                                  &ct, &ctlen, &ss, &sslen))
            return 0;
        if (clen != NULL) *clen = ctlen;
        if (slen != NULL) *slen = sslen;
        OPENSSL_free(ct);
        OPENSSL_clear_free(ss, sslen);
        return 1;
    }
    if (shsec == NULL || clen == NULL || slen == NULL)
        return 0;
    if (!composite_kem_encaps(k->info, k->pq_key, k->trad_key, k->libctx,
                              k->pq_propq, k->trad_propq,
                              &ct, &ctlen, &ss, &sslen))
        return 0;
    if (*clen >= ctlen && *slen >= sslen) {
        memcpy(ctext, ct, ctlen);
        memcpy(shsec, ss, sslen);
        *clen = ctlen;
        *slen = sslen;
        ret = 1;
    }
    OPENSSL_free(ct);
    OPENSSL_clear_free(ss, sslen);
    return ret;
}

static int composite_kem_decapsulate(void *vctx,
                                     unsigned char *shsec, size_t *slen,
                                     const unsigned char *ctext, size_t clen)
{
    COMPOSITE_KEM_CTX *c = vctx;
    COMPOSITE_KEM_KEY *k = c->key;
    unsigned char *ss = NULL;
    size_t sslen = 0;
    int ret = 0;

    if (shsec == NULL) {   /* size query: composite ss is always 32 bytes */
        if (slen != NULL) *slen = COMPOSITE_KEM_SS_BYTES;
        return 1;
    }
    if (slen == NULL)
        return 0;
    if (!composite_kem_decaps(k->info, k->pq_key, k->trad_key, k->libctx,
                              k->pq_propq, k->trad_propq, ctext, clen,
                              &ss, &sslen, &k->pq_ctlen))
        return 0;
    if (*slen >= sslen) {
        memcpy(shsec, ss, sslen);
        *slen = sslen;
        ret = 1;
    }
    OPENSSL_clear_free(ss, sslen);
    return ret;
}

static const OSSL_PARAM *composite_kem_settable_ctx_params(void *vctx,
                                                           void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };
    return params;
}

static int composite_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

const OSSL_DISPATCH composite_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))composite_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))composite_kem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))composite_kem_dupctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))composite_kem_encaps_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))composite_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))composite_kem_decaps_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))composite_kem_decapsulate },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))composite_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))composite_kem_settable_ctx_params },
    { 0, NULL }
};
