/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"

/*
 * The operation context carries no libctx of its own: every component
 * encapsulate/decapsulate below sources its library context and property
 * queries from the key (key->libctx / HYBRID_KEY_*_PROPQ), which were captured
 * from the provider's component context at key construction (see
 * hybrid_keymgmt.c, HYBRID_COMPONENT_LIBCTX). This keeps a single, unambiguous
 * source for the component context and avoids ever fetching from the global
 * default libctx.
 */
typedef struct {
    HYBRID_KEY *key;
    int op;
} HYBRID_KEM_CTX;

static void *hybrid_kem_newctx(void *provctx)
{
    return OPENSSL_zalloc(sizeof(HYBRID_KEM_CTX));
}

static void hybrid_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int
hybrid_kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (!hybrid_have_pubkey(key))
        return 0;
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_ENCAPSULATE;
    return 1;
}

static int
hybrid_kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = vkey;

    if (!hybrid_have_prvkey(key))
        return 0;
    ctx->key = key;
    ctx->op = EVP_PKEY_OP_DECAPSULATE;
    return 1;
}

/*
 * Encapsulate for a key-exchange component (X25519/ECDH):
 * Generate ephemeral keypair, put public key into ctext, derive shared secret.
 */
static int
encap_keyexchange(OSSL_LIB_CTX *libctx, const char *propq,
                  EVP_PKEY *peer_pub,
                  uint8_t *ctext, size_t *ctlen,
                  uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *ephemeral = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    size_t publen, derlen;
    int ret = 0;

    /* Generate ephemeral key from the peer's key parameters */
    kctx = EVP_PKEY_CTX_new_from_pkey(libctx, peer_pub, propq);
    if (kctx == NULL
        || EVP_PKEY_keygen_init(kctx) <= 0
        || EVP_PKEY_keygen(kctx, &ephemeral) <= 0)
        goto end;
    EVP_PKEY_CTX_free(kctx);
    kctx = NULL;

    /* Extract ephemeral public key as "ciphertext" */
    publen = *ctlen;
    if (EVP_PKEY_get_octet_string_param(ephemeral,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            ctext, publen, &publen) <= 0)
        goto end;
    if (publen != *ctlen)
        goto end;

    /* Derive shared secret: ephemeral private + peer public */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, ephemeral, propq);
    if (dctx == NULL
        || EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        goto end;

    derlen = *sslen;
    if (EVP_PKEY_derive(dctx, shsec, &derlen) <= 0)
        goto end;
    if (derlen != *sslen)
        goto end;

    ret = 1;
end:
    EVP_PKEY_free(ephemeral);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/*
 * Decapsulate for a key-exchange component:
 * Load peer public key from ctext, derive shared secret with our private key.
 */
static int
decap_keyexchange(OSSL_LIB_CTX *libctx, const char *propq,
                  EVP_PKEY *own_prv,
                  const uint8_t *ctext, size_t ctlen,
                  uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY *peer_pub = NULL;
    EVP_PKEY_CTX *dctx = NULL;
    size_t derlen;
    int ret = 0;

    /* Reconstruct peer public key from ciphertext */
    peer_pub = EVP_PKEY_new();
    if (peer_pub == NULL
        || EVP_PKEY_copy_parameters(peer_pub, own_prv) <= 0
        || EVP_PKEY_set1_encoded_public_key(peer_pub, ctext, ctlen) <= 0)
        goto end;

    /* Derive shared secret: our private + peer public */
    dctx = EVP_PKEY_CTX_new_from_pkey(libctx, own_prv, propq);
    if (dctx == NULL
        || EVP_PKEY_derive_init(dctx) <= 0
        || EVP_PKEY_derive_set_peer(dctx, peer_pub) <= 0)
        goto end;

    derlen = *sslen;
    if (EVP_PKEY_derive(dctx, shsec, &derlen) <= 0)
        goto end;
    if (derlen != *sslen)
        goto end;

    ret = 1;
end:
    EVP_PKEY_free(peer_pub);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/*
 * Encapsulate for a native KEM component (ML-KEM).
 */
static int
encap_kem(OSSL_LIB_CTX *libctx, const char *propq,
          EVP_PKEY *pub_key,
          uint8_t *ctext, size_t *ctlen,
          uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY_CTX *ctx;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub_key, propq);
    if (ctx == NULL
        || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, ctext, ctlen, shsec, sslen) <= 0)
        goto end;
    ret = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Decapsulate for a native KEM component (ML-KEM).
 */
static int
decap_kem(OSSL_LIB_CTX *libctx, const char *propq,
          EVP_PKEY *prv_key,
          const uint8_t *ctext, size_t ctlen,
          uint8_t *shsec, size_t *sslen)
{
    EVP_PKEY_CTX *ctx;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, prv_key, propq);
    if (ctx == NULL
        || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, shsec, sslen, ctext, ctlen) <= 0)
        goto end;
    ret = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* X-Wing combiner output length (HYBRID_XWING_SS_LEN) lives in hybrid_prov.h,
 * shared with the test; the SHA3-256 label is local to this combiner. */
static const uint8_t XWING_LABEL[6] = {
    0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c
};

/*
 * X-Wing strongly-binding combiner (draft-connolly-cfrg-xwing-kem-11 §5.3):
 *
 *   ss = SHA3-256(ss_pq || ss_cl || ct_cl || pk_cl || XWingLabel)
 *
 * In the draft's instantiation ss_pq is the ML-KEM-768 secret, ss_cl the X25519
 * secret, ct_cl the X25519 ephemeral public key (the classical half of the
 * ciphertext) and pk_cl the recipient's X25519 public key; XWingLabel is the
 * fixed 6-byte ASCII string "\.//^\" (0x5c2e2f2f5e5c). Folding ct_cl and pk_cl in
 * is what makes the secret ciphertext/key-binding, unlike the RFC 10024 concat.
 *
 * Called only for a HYBRID_COMBINER_XWING key, but component-agnostic within
 * that: ss_pq/ss_cl/ct_cl are passed by (ptr, len) and pk_cl is read here at its
 * own length (key->sizes->a1_pub), so an X-Wing-style row over any classical
 * key-exchange + PQ KEM pair (e.g. ML-KEM-1024, or an experimental KEM) is
 * combined by this same code with nothing component-specific hardcoded. ss_pq is
 * the PQ (alg2) secret, ss_cl/ct_cl the classical (alg1) secret and ciphertext.
 * The output is always one SHA3-256 digest (a property of the combiner, not the
 * components); the digest is fetched with a NULL property query (not the
 * component propq, which may pin a provider without SHA-3) so it resolves from
 * the default provider in key->libctx. pk_cl is public, so it is not cleansed;
 * the component secrets live in the caller's scratch, which the caller cleanses.
 */
static int
hybrid_xwing_combine(const HYBRID_KEY *key,
                     const uint8_t *ss_pq, size_t ss_pq_len,
                     const uint8_t *ss_cl, size_t ss_cl_len,
                     const uint8_t *ct_cl, size_t ct_cl_len,
                     uint8_t *out, size_t outlen)
{
    EVP_MD *sha3 = NULL;
    EVP_MD_CTX *mdctx = NULL;
    size_t pklen = key->sizes->a1_pub, pkgot = 0;
    uint8_t *pk_cl = NULL;
    unsigned int dlen = 0;
    int ret = 0;

    if (outlen != HYBRID_XWING_SS_LEN || (pk_cl = OPENSSL_malloc(pklen)) == NULL)
        return 0;
    /* Recipient classical public key (pk_cl). Works for both an encapsulation
     * (public) key and a decapsulation (private) key, since the classical key
     * always exposes its public half via OSSL_PKEY_PARAM_PUB_KEY. */
    if (EVP_PKEY_get_octet_string_param(key->key1, OSSL_PKEY_PARAM_PUB_KEY,
                                        pk_cl, pklen, &pkgot) <= 0)
        goto end;

    sha3 = EVP_MD_fetch(key->libctx, "SHA3-256", NULL);
    mdctx = EVP_MD_CTX_new();
    if (sha3 == NULL || mdctx == NULL
        || EVP_DigestInit_ex(mdctx, sha3, NULL) <= 0
        || EVP_DigestUpdate(mdctx, ss_pq, ss_pq_len) <= 0
        || EVP_DigestUpdate(mdctx, ss_cl, ss_cl_len) <= 0
        || EVP_DigestUpdate(mdctx, ct_cl, ct_cl_len) <= 0
        || EVP_DigestUpdate(mdctx, pk_cl, pkgot) <= 0
        || EVP_DigestUpdate(mdctx, XWING_LABEL, sizeof(XWING_LABEL)) <= 0
        || EVP_DigestFinal_ex(mdctx, out, &dlen) <= 0
        || dlen != outlen)
        goto end;
    ret = 1;
end:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(sha3);
    OPENSSL_free(pk_cl);
    return ret;
}

static int hybrid_kem_encapsulate(void *vctx,
                                  unsigned char *ctext, size_t *clen,
                                  unsigned char *shsec, size_t *slen)
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_KEM_INFO *info = (const HYBRID_KEM_INFO *)key->info;
    int xwing = (key->combiner == HYBRID_COMBINER_XWING);
    size_t total_clen, total_slen, comb_slen;
    /* Scratch for the component secrets when the X-Wing combiner derives the
     * output into shsec itself. 2*EVP_MAX_MD_SIZE comfortably holds both. */
    uint8_t sscomp[2 * EVP_MAX_MD_SIZE];
    uint8_t *ssbuf;
    uint8_t *ct1, *ct2, *ss1, *ss2;
    size_t ct1len, ct2len, ss1len, ss2len;

    if (!hybrid_have_pubkey(key))
        return 0;

    /*
     * For key-exchange alg1, "ciphertext" = ephemeral public key.
     * For native KEM alg2, ciphertext = KEM ciphertext.
     */
    ct1len = key->sizes->a1_ct;
    ct2len = key->sizes->a2_ct;
    ss1len = key->sizes->a1_ss;
    ss2len = key->sizes->a2_ss;
    total_clen = ct1len + ct2len;
    total_slen = ss1len + ss2len;           /* concatenated component secrets */
    /* Output secret length: the X-Wing combiner hashes the component secrets
     * down to a fixed 32 bytes; plain concat returns their concatenation. */
    comb_slen = xwing ? HYBRID_XWING_SS_LEN : total_slen;

    /* Size query */
    if (ctext == NULL) {
        if (clen != NULL) *clen = total_clen;
        if (slen != NULL) *slen = comb_slen;
        return 1;
    }
    if (shsec == NULL || clen == NULL || slen == NULL)
        return 0;
    if (*clen < total_clen || *slen < comb_slen)
        return 0;
    if (xwing && total_slen > sizeof(sscomp))
        return 0;
    *clen = total_clen;
    *slen = comb_slen;

    /* The X-Wing combiner assembles the component secrets in scratch and
     * derives the output into shsec; plain concat writes them straight into the
     * caller's secret, slot-ordered. */
    ssbuf = xwing ? sscomp : shsec;

    /*
     * Slot ordering:
     * If alg2_slot == 0: [alg2_ct | alg1_ct], [alg2_ss | alg1_ss]
     * If alg2_slot == 1: [alg1_ct | alg2_ct], [alg1_ss | alg2_ss]
     */
    if (info->alg2_slot == 0) {
        ct2 = ctext;
        ct1 = ctext + ct2len;
        ss2 = ssbuf;
        ss1 = ssbuf + ss2len;
    } else {
        ct1 = ctext;
        ct2 = ctext + ct1len;
        ss1 = ssbuf;
        ss2 = ssbuf + ss1len;
    }

    /* Encapsulate alg2 (PQ KEM) */
    if (info->alg2_is_kem) {
        if (!encap_kem(key->libctx, HYBRID_KEY_PQ_PROPQ(key), key->key2,
                       ct2, &ct2len, ss2, &ss2len))
            goto err;
    }

    /* Encapsulate alg1 (key-exchange or KEM) */
    if (info->alg1_is_kem) {
        if (!encap_kem(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key), key->key1,
                       ct1, &ct1len, ss1, &ss1len))
            goto err;
    } else {
        if (!encap_keyexchange(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                               key->key1, ct1, &ct1len, ss1, &ss1len))
            goto err;
    }

    /* X-Wing combiner: derive the bound secret from the component outputs and
     * the recipient classical public key (read inside, per the key's row). */
    if (xwing) {
        if (!hybrid_xwing_combine(key, ss2, ss2len, ss1, ss1len,
                                  ct1, ct1len, shsec, comb_slen))
            goto err;
        OPENSSL_cleanse(sscomp, sizeof(sscomp));
    }

    return 1;

err:
    /* Don't leave a partial shared secret in the caller's buffer or scratch. */
    if (xwing)
        OPENSSL_cleanse(sscomp, sizeof(sscomp));
    OPENSSL_cleanse(shsec, comb_slen);
    return 0;
}

static int hybrid_kem_decapsulate(void *vctx,
                                  unsigned char *shsec, size_t *slen,
                                  const unsigned char *ctext, size_t clen)
{
    HYBRID_KEM_CTX *ctx = vctx;
    HYBRID_KEY *key = ctx->key;
    const HYBRID_KEM_INFO *info = (const HYBRID_KEM_INFO *)key->info;
    int xwing = (key->combiner == HYBRID_COMBINER_XWING);
    size_t total_clen, total_slen, comb_slen;
    uint8_t sscomp[2 * EVP_MAX_MD_SIZE];
    uint8_t *ssbuf;
    const uint8_t *ct1, *ct2;
    uint8_t *ss1, *ss2;
    size_t ct1len, ct2len, ss1len, ss2len;

    if (!hybrid_have_prvkey(key))
        return 0;

    ct1len = key->sizes->a1_ct;
    ct2len = key->sizes->a2_ct;
    ss1len = key->sizes->a1_ss;
    ss2len = key->sizes->a2_ss;
    total_clen = ct1len + ct2len;
    total_slen = ss1len + ss2len;           /* concatenated component secrets */
    comb_slen = xwing ? HYBRID_XWING_SS_LEN : total_slen;  /* see hybrid_kem_encapsulate */

    /* Size query */
    if (shsec == NULL) {
        if (slen != NULL) *slen = comb_slen;
        return 1;
    }
    if (slen == NULL)
        return 0;
    if (*slen < comb_slen)
        return 0;
    if (xwing && total_slen > sizeof(sscomp))
        return 0;
    /*
     * Length/count sanity check BEFORE splitting the concatenated ciphertext at
     * its fixed component offsets (issue #46). The two component ciphertext
     * lengths are compile-time constants for the variant, so the only valid
     * total is their sum; a truncated, oversized or otherwise wrong-length input
     * would make the slot pointers below run past the caller's buffer. Reject it
     * with a defined error rather than reading out of bounds or splitting garbage.
     */
    if (clen != total_clen) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                       "hybrid KEM decapsulate: ciphertext length %zu != "
                       "expected %zu", clen, total_clen);
        return 0;
    }
    *slen = comb_slen;

    ssbuf = xwing ? sscomp : shsec;

    /* Slot ordering */
    if (info->alg2_slot == 0) {
        ct2 = ctext;
        ct1 = ctext + ct2len;
        ss2 = ssbuf;
        ss1 = ssbuf + ss2len;
    } else {
        ct1 = ctext;
        ct2 = ctext + ct1len;
        ss1 = ssbuf;
        ss2 = ssbuf + ss1len;
    }

    /* Decapsulate alg2 (PQ KEM) */
    if (info->alg2_is_kem) {
        if (!decap_kem(key->libctx, HYBRID_KEY_PQ_PROPQ(key), key->key2,
                       ct2, ct2len, ss2, &ss2len))
            goto err;
    }

    /* Decapsulate alg1 (key-exchange or KEM) */
    if (info->alg1_is_kem) {
        if (!decap_kem(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key), key->key1,
                       ct1, ct1len, ss1, &ss1len))
            goto err;
    } else {
        if (!decap_keyexchange(key->libctx, HYBRID_KEY_CLASSIC_PROPQ(key),
                               key->key1, ct1, ct1len, ss1, &ss1len))
            goto err;
    }

    /* X-Wing combiner: derive the bound secret (see hybrid_kem_encapsulate). */
    if (xwing) {
        if (!hybrid_xwing_combine(key, ss2, ss2len, ss1, ss1len,
                                  ct1, ct1len, shsec, comb_slen))
            goto err;
        OPENSSL_cleanse(sscomp, sizeof(sscomp));
    }

    return 1;

err:
    /* Don't leave a partial shared secret in the caller's buffer or scratch. */
    if (xwing)
        OPENSSL_cleanse(sscomp, sizeof(sscomp));
    OPENSSL_cleanse(shsec, comb_slen);
    return 0;
}

static const OSSL_PARAM *hybrid_kem_settable_ctx_params(void *vctx,
                                                         void *provctx)
{
    static const OSSL_PARAM params[] = { OSSL_PARAM_END };
    return params;
}

static int hybrid_kem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

const OSSL_DISPATCH hybrid_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))hybrid_kem_newctx },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))hybrid_kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))hybrid_kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))hybrid_kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))hybrid_kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))hybrid_kem_decapsulate },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))hybrid_kem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))hybrid_kem_settable_ctx_params },
    { 0, NULL }
};
