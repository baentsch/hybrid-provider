/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#include "hybrid_prov.h"
#include <openssl/x509.h>

/* --- Key lifecycle --- */

static void hybrid_key_free(void *vkey)
{
    HYBRID_KEY *key = vkey;
    unsigned i;

    if (key == NULL)
        return;
    OPENSSL_free(key->propq);
    for (i = 0; i < HYBRID_KEY_NCOMP(key); i++)
        EVP_PKEY_free(HYBRID_KEY_COMP(key, i));
    OPENSSL_free(key);
}

/*
 * Materialize a key from a decoder-provided reference (the decoder hands back a
 * pointer to a HYBRID_KEY it built; ownership transfers to the EVP_PKEY).
 */
static void *hybrid_key_load(const void *reference, size_t reference_sz)
{
    HYBRID_KEY *key = NULL;

    if (reference_sz == sizeof(key)) {
        key = *(HYBRID_KEY **)reference;
        *(HYBRID_KEY **)reference = NULL;   /* avoid a double free */
        return key;
    }
    ERR_raise_data(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
                   "hybrid load: unexpected key-reference size %zu (expected %zu)",
                   reference_sz, sizeof(key));
    return NULL;
}

static void *
hybrid_key_new(int is_kem, unsigned int variant,
               OSSL_LIB_CTX *libctx, char *propq)
{
    HYBRID_KEY *key;

    if (is_kem && variant >= HYBRID_KEM_ALG_COUNT)
        return NULL;
    if (!is_kem && variant >= HYBRID_SIG_ALG_COUNT)
        return NULL;
    if ((key = OPENSSL_zalloc(sizeof(*key))) == NULL) {
        OPENSSL_free(propq);
        return NULL;
    }
    key->libctx = libctx;
    key->is_kem = is_kem;
    key->info = is_kem ? (const void *)&hybrid_kem_table[variant]
                       : (const void *)&hybrid_sig_table[variant];
    /* Point at this variant's row in the constant size table — no per-key copy,
     * no runtime discovery, no cache, no lock. The table is static-lifetime. */
    key->sizes = is_kem ? &hybrid_kem_sizes[variant] : &hybrid_sig_sizes[variant];
    /* Shared-secret combiner is a per-variant KEM property (concat vs X-Wing);
     * signatures have none. Stored as a value so the KEM op need not re-derive
     * the variant index from the (possibly cross-TU) info pointer. */
    key->combiner = is_kem ? hybrid_kem_combiner[variant] : HYBRID_COMBINER_CONCAT;
    /* Component handles are already NULL (OPENSSL_zalloc above). Component count
     * is 2 for every current KEM and signature hybrid; per-variant counts (the
     * deferred 3-component groups) arrive with the wire-ordered descriptors. */
    key->n_comp = 2;
    key->state = HYBRID_HAVE_NOKEYS;
    key->propq = propq;
    return key;
}

/* --- has / match / dup --- */

static int hybrid_kem_has(const void *vkey, int selection)
{
    const HYBRID_KEY *key = vkey;

    if (key == NULL)
        return 0;
    switch (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return hybrid_have_pubkey(key);
    default:
        return hybrid_have_prvkey(key);
    }
}

static int hybrid_kem_match(const void *vkey1, const void *vkey2, int selection)
{
    const HYBRID_KEY *key1 = vkey1;
    const HYBRID_KEY *key2 = vkey2;
    unsigned i;

    if (key1->info != key2->info)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 1;
    if (hybrid_have_pubkey(key1) != hybrid_have_pubkey(key2))
        return 0;
    if (!hybrid_have_pubkey(key1))
        return 1;
    for (i = 0; i < HYBRID_KEY_NCOMP(key1); i++)
        if (!EVP_PKEY_eq(HYBRID_KEY_COMP(key1, i), HYBRID_KEY_COMP(key2, i)))
            return 0;
    return 1;
}

static void *hybrid_kem_dup(const void *vkey, int selection)
{
    const HYBRID_KEY *key = vkey;
    HYBRID_KEY *ret;
    unsigned i;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return NULL;
    ret->libctx = key->libctx;
    ret->is_kem = key->is_kem;
    ret->info = key->info;
    ret->sizes = key->sizes;
    ret->combiner = key->combiner;
    ret->n_comp = key->n_comp;
    ret->state = HYBRID_HAVE_NOKEYS;
    ret->propq = NULL;
    ret->alg2_propq = key->alg2_propq;
    ret->alg1_propq = key->alg1_propq;

    if (key->propq != NULL
        && (ret->propq = OPENSSL_strdup(key->propq)) == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            || HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) == NULL)
        return ret;

    for (i = 0; i < HYBRID_KEY_NCOMP(key); i++)
        HYBRID_KEY_COMP(ret, i) = EVP_PKEY_dup(HYBRID_KEY_COMP(key, i));
    for (i = 0; i < HYBRID_KEY_NCOMP(key); i++)
        if (HYBRID_KEY_COMP(ret, i) == NULL) {
            hybrid_key_free(ret);
            return NULL;
        }
    ret->state = key->state;
    return ret;
}

/* --- Import / Export --- */

static int
load_component(OSSL_LIB_CTX *libctx, const char *propq,
               const char *alg_name, const char *group_name,
               const char *param_name, int selection,
               const uint8_t *raw, size_t rawlen,
               EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM parr[3];
    int idx = 0;
    int ret = 0;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq);
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;

    parr[idx++] = OSSL_PARAM_construct_octet_string(param_name,
                                                     (void *)raw, rawlen);
    if (group_name != NULL)
        parr[idx++] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, (char *)group_name, 0);
    parr[idx] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(ctx, out, selection, parr) > 0)
        ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Build a component key from BOTH its private and public raw material. Needed
 * for the PQ component when decoding a private key: some component providers
 * (oqsprovider's research signatures) do not re-derive the public key from
 * private-only fromdata the way ML-DSA does, yet a certificate needs it. Our own
 * PKCS8 blob carries the PQ public key, so we hand both to the provider. Uses
 * only the public EVP fromdata API — no dependency on any provider's key format.
 */
static int
load_component_privpub(OSSL_LIB_CTX *libctx, const char *propq,
                       const char *alg_name,
                       const uint8_t *priv, size_t privlen,
                       const uint8_t *pub, size_t publen,
                       EVP_PKEY **out)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq);
    OSSL_PARAM parr[3];
    int ret = 0;

    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;
    parr[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                (void *)priv, privlen);
    parr[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                (void *)pub, publen);
    parr[2] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_fromdata(ctx, out,
                          OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                          | OSSL_KEYMGMT_SELECT_KEYPAIR, parr) > 0)
        ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/* --- Decoder support: build a public key from oqs blob components --- */

/* Free a hybrid key (public wrapper over the static free, for decoders). */
void hybrid_keymgmt_free(void *vkey)
{
    hybrid_key_free(vkey);
}

/* Create an empty hybrid key of the given family/variant (used by decoders). */
void *hybrid_keymgmt_new_by_variant(void *provctx, int is_kem,
                                    unsigned int variant)
{
    HYBRID_PROV_CTX *ctx = provctx;
    OSSL_LIB_CTX *lc = ctx ? HYBRID_COMPONENT_LIBCTX(ctx) : NULL;
    HYBRID_KEY *k = hybrid_key_new(is_kem, variant, lc, NULL);

    if (k != NULL && ctx != NULL) {
        k->alg2_propq = ctx->alg2_propq;
        k->alg1_propq = ctx->alg1_propq;
    }
    return k;
}

/* Load the classical + PQ public components from their raw byte ranges. */
int hybrid_key_load_pub_components(HYBRID_KEY *key,
                                  const unsigned char *classic, size_t clen,
                                  const unsigned char *pq, size_t plen)
{
    int sel = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
            | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    if (strcmp(HYBRID_KEY_ALG1_NAME(key), "RSA") == 0) {
        /* RSA public key is i2d_PublicKey (RSAPublicKey) DER, not an octet. */
        const unsigned char *p = classic;

        HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, (long)clen);
        if (HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) == NULL)
            return 0;
    } else if (!load_component(key->libctx, HYBRID_KEY_ALG1_PROPQ(key),
                        HYBRID_KEY_ALG1_NAME(key), HYBRID_KEY_ALG1_GROUP(key),
                        OSSL_PKEY_PARAM_PUB_KEY, sel, classic, clen,
                        &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1))) {
        return 0;
    }
    if (!load_component(key->libctx, HYBRID_KEY_ALG2_PROPQ(key),
                        HYBRID_KEY_ALG2_NAME(key), HYBRID_KEY_ALG2_GROUP(key),
                        OSSL_PKEY_PARAM_PUB_KEY, sel, pq, plen, &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2)))
        return 0;
    key->state = HYBRID_HAVE_PUBKEY;
    return 1;
}

/* Load the classical (DER) + PQ (raw) private components (decoders). */
int hybrid_key_load_prv_components(HYBRID_KEY *key,
                                  const unsigned char *cder, size_t cderlen,
                                  const unsigned char *pqv, size_t pqvlen,
                                  const unsigned char *pqpub, size_t pqpublen)
{
    int sel = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
            | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    const char *a1 = HYBRID_KEY_ALG1_NAME(key);
    int ok;

    /* Raw-key classical types (X25519/X448) are stored raw, not DER. The
     * classical public key is always derivable from its private key, so we only
     * ever load the classical private component. */
    if (strcmp(a1, "X25519") == 0 || strcmp(a1, "X448") == 0) {
        HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) =
            EVP_PKEY_new_raw_private_key_ex(key->libctx, a1,
                                            HYBRID_KEY_ALG1_PROPQ(key),
                                            cder, cderlen);
    } else {
        const unsigned char *p = cder;

        HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) =
            d2i_AutoPrivateKey_ex(NULL, &p, (long)cderlen, key->libctx,
                                  HYBRID_KEY_ALG1_PROPQ(key));
    }
    if (HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) == NULL)
        return 0;
    /* Load the PQ component. When the stored PQ public key is available, hand it
     * to the provider alongside the private key: research keytypes cannot
     * re-derive it from private material, and without it the decoded key could
     * not produce a certificate. Otherwise fall back to a private-only load. */
    if (pqpub != NULL && pqpublen > 0)
        ok = load_component_privpub(key->libctx, HYBRID_KEY_ALG2_PROPQ(key),
                                    HYBRID_KEY_ALG2_NAME(key),
                                    pqv, pqvlen, pqpub, pqpublen,
                                    &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2));
    else
        ok = load_component(key->libctx, HYBRID_KEY_ALG2_PROPQ(key),
                            HYBRID_KEY_ALG2_NAME(key), HYBRID_KEY_ALG2_GROUP(key),
                            OSSL_PKEY_PARAM_PRIV_KEY, sel, pqv, pqvlen,
                            &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2));
    if (!ok) {
        EVP_PKEY_free(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1));
        HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) = NULL;
        return 0;
    }
    key->state = HYBRID_HAVE_PRVKEY;
    return 1;
}

/*
 * Reconstruct one private component (which = 1 or 2) from its on-wire bytes,
 * dispatched by kind (mirror of the encoder's encode_component_priv): a classical
 * component from DER (d2i_AutoPrivateKey, or raw for X25519/X448); a PQ component
 * from raw private || raw public, split by the fixed sizes (the public handed to
 * the provider so a research keytype that cannot re-derive it still loads). This
 * is the slot-symmetric analogue of hybrid_key_load_prv_components, which fixes
 * classical = slot 1 for the KEM wire format.
 */
static int load_prv_bykind(HYBRID_KEY *key, int which,
                           const unsigned char *data, size_t len,
                           EVP_PKEY **out)
{
    const char *alg   = which == 1 ? HYBRID_KEY_ALG1_NAME(key)
                                   : HYBRID_KEY_ALG2_NAME(key);
    const char *group = which == 1 ? HYBRID_KEY_ALG1_GROUP(key)
                                   : HYBRID_KEY_ALG2_GROUP(key);
    const char *propq = which == 1 ? HYBRID_KEY_ALG1_PROPQ(key)
                                   : HYBRID_KEY_ALG2_PROPQ(key);

    if (hybrid_component_is_classical(alg, group)) {
        if (strcmp(alg, "X25519") == 0 || strcmp(alg, "X448") == 0) {
            *out = EVP_PKEY_new_raw_private_key_ex(key->libctx, alg, propq,
                                                   data, len);
        } else {
            const unsigned char *p = data;

            *out = d2i_AutoPrivateKey_ex(NULL, &p, (long)len, key->libctx, propq);
        }
        return *out != NULL;
    } else {
        /* PQ: raw private (prv bytes) then raw public (pub bytes). */
        size_t prv = hybrid_key_comp_prv_bytes(key, (unsigned)(which - 1));
        size_t pub = hybrid_key_comp_pub_bytes(key, (unsigned)(which - 1));
        int sel = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

        if (len < prv)
            return 0;
        if (pub > 0 && len >= prv + pub)
            return load_component_privpub(key->libctx, propq, alg,
                                          data, prv, data + prv, pub, out);
        return load_component(key->libctx, propq, alg, group,
                              OSSL_PKEY_PARAM_PRIV_KEY, sel, data, prv, out);
    }
}

/*
 * Slot-symmetric private load: reconstruct both components from their on-wire
 * byte ranges by kind (either slot classical or PQ). Used by the signature
 * decoder; KEMs stay on hybrid_key_load_prv_components (fixed classical slot).
 */
int hybrid_key_load_prv_components_sym(HYBRID_KEY *key,
                                       const unsigned char *s1, size_t l1,
                                       const unsigned char *s2, size_t l2)
{
    if (!load_prv_bykind(key, 1, s1, l1, &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1)))
        return 0;
    if (!load_prv_bykind(key, 2, s2, l2, &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2))) {
        EVP_PKEY_free(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1));
        HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) = NULL;
        return 0;
    }
    key->state = HYBRID_HAVE_PRVKEY;
    return 1;
}

/* --- Component keygen forward declaration --- */

/* Forward declaration; defined in the Key Generation section below. */
static EVP_PKEY *
hybrid_component_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                        const char *alg_name, const char *group_name);

/*
 * Determine slot offsets for concatenated key material.
 * KEM keys use alg2_slot to control ordering; SIG keys always use alg1 first.
 */
static void
key_slot_offsets(const HYBRID_KEY *key, int is_pub,
                 size_t *off1, size_t *len1, size_t *off2, size_t *len2)
{
    size_t a1, a2;
    int alg2_first = 0;

    if (is_pub) {
        a1 = HYBRID_KEY_ALG1_PUBKEY_BYTES(key);
        a2 = HYBRID_KEY_ALG2_PUBKEY_BYTES(key);
    } else {
        a1 = HYBRID_KEY_ALG1_PRVKEY_BYTES(key);
        a2 = HYBRID_KEY_ALG2_PRVKEY_BYTES(key);
    }

    if (key->is_kem)
        alg2_first = (((const HYBRID_KEM_INFO *)key->info)->alg2_slot == 0);

    if (alg2_first) {
        *off2 = 0;  *len2 = a2;
        *off1 = a2; *len1 = a1;
    } else {
        *off1 = 0;  *len1 = a1;
        *off2 = a1; *len2 = a2;
    }
}

static int
load_keys(HYBRID_KEY *key,
          const uint8_t *pubenc, size_t publen,
          const uint8_t *prvenc, size_t prvlen)
{
    int selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                  | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    const uint8_t *alg1_data, *alg2_data;
    size_t off1, len1, off2, len2;
    const char *pname;

    if (prvlen > 0) {
        pname = OSSL_PKEY_PARAM_PRIV_KEY;
        key_slot_offsets(key, 0, &off1, &len1, &off2, &len2);
        alg1_data = prvenc + off1;
        alg2_data = prvenc + off2;
    } else if (publen > 0) {
        selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                  | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        pname = OSSL_PKEY_PARAM_PUB_KEY;
        key_slot_offsets(key, 1, &off1, &len1, &off2, &len2);
        alg1_data = pubenc + off1;
        alg2_data = pubenc + off2;
    } else {
        return 0;
    }

    if (publen > 0
            && strcmp(HYBRID_KEY_ALG1_NAME(key), "RSA") == 0) {
        /* RSA public key is i2d_PublicKey DER (no PUB_KEY octet); parse the
         * classical slot the same way the decoder does. Symmetric with
         * extract_component_pub()'s i2d_PublicKey export. */
        const unsigned char *p = alg1_data;

        HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, (long)len1);
        if (HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) == NULL)
            goto err;
    } else if (!load_component(key->libctx, HYBRID_KEY_ALG1_PROPQ(key),
                        HYBRID_KEY_ALG1_NAME(key),
                        HYBRID_KEY_ALG1_GROUP(key),
                        pname, selection,
                        alg1_data, len1, &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1)))
        goto err;
    if (!load_component(key->libctx, HYBRID_KEY_ALG2_PROPQ(key),
                        HYBRID_KEY_ALG2_NAME(key), HYBRID_KEY_ALG2_GROUP(key),
                        pname, selection,
                        alg2_data, len2, &HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2)))
        goto err;

    key->state = (prvlen > 0) ? HYBRID_HAVE_PRVKEY : HYBRID_HAVE_PUBKEY;
    return 1;

err:
    EVP_PKEY_free(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1));
    EVP_PKEY_free(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2));
    HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1) = HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2) = NULL;
    key->state = HYBRID_HAVE_NOKEYS;
    return 0;
}

static int hybrid_import(void *vkey, int selection,
                          const OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    int include_private;

    if (key == NULL || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) ? 1 : 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p == NULL)
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL
            && OSSL_PARAM_get_octet_string_ptr(p, &pubenc, &publen) != 1)
        return 0;

    if (include_private) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p != NULL
                && OSSL_PARAM_get_octet_string_ptr(p, &prvenc, &prvlen) != 1)
            return 0;
    }

    if (publen == 0 && prvlen == 0)
        return 0;

    if (publen != 0 && publen != hybrid_key_pubkey_bytes(key))
        return 0;
    if (prvlen != 0 && prvlen != hybrid_key_prvkey_bytes(key))
        return 0;

    return load_keys(key, pubenc, publen, prvenc, prvlen);
}

/*
 * Extract concatenated public key bytes from both sub-keys.
 * Caller provides buffer of hybrid_key_pubkey_bytes(key) size.
 */
/* Write one component's raw public key into buf[..len]; must fill exactly len.
 * Classical EC/X25519 and PQ components expose a PUB_KEY octet; RSA does not, so
 * fall back to i2d_PublicKey (constant length, matched by discover_sig_component_
 * sizes and the d2i_PublicKey import in hybrid_key_load_pub_components). */
static int extract_component_pub(EVP_PKEY *pk, uint8_t *buf, size_t len)
{
    size_t out = 0;
    unsigned char *p = buf;
    int dlen;

    if (EVP_PKEY_get_octet_string_param(pk, OSSL_PKEY_PARAM_PUB_KEY,
                                        buf, len, &out) > 0)
        return out == len;
    ERR_clear_error();
    dlen = i2d_PublicKey(pk, &p);
    return dlen > 0 && (size_t)dlen == len;
}

static int
extract_pubkey(const HYBRID_KEY *key, uint8_t *buf, size_t buflen)
{
    size_t off1, len1, off2, len2;

    if (buflen < hybrid_key_pubkey_bytes(key))
        return 0;

    key_slot_offsets(key, 1, &off1, &len1, &off2, &len2);

    return extract_component_pub(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1), buf + off1, len1)
        && extract_component_pub(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2), buf + off2, len2);
}

/* Callback arg for EVP_PKEY_export — used for private key extraction */
typedef struct {
    uint8_t *buf;
    size_t off;
    size_t len;
    int found;
} EXPORT_PRV_ARG;

static int export_prv_cb(const OSSL_PARAM *params, void *varg)
{
    EXPORT_PRV_ARG *arg = varg;
    const OSSL_PARAM *p;
    const void *data;
    size_t len;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p == NULL)
        return 1;

    if (OSSL_PARAM_get_octet_string_ptr(p, &data, &len) != 1)
        return 0;
    if (len != arg->len)
        return 0;

    memcpy(arg->buf + arg->off, data, len);
    arg->found = 1;
    return 1;
}

static int hybrid_export(void *vkey, int selection,
                          OSSL_CALLBACK *param_cb, void *cbarg)
{
    HYBRID_KEY *key = vkey;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    uint8_t *pubbuf = NULL, *prvbuf = NULL;
    size_t publen, prvlen;
    size_t off1, len1, off2, len2;
    int ret = 0;

    if (key == NULL || !hybrid_have_pubkey(key))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    publen = hybrid_key_pubkey_bytes(key);
    prvlen = hybrid_key_prvkey_bytes(key);

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        return 0;

    /* Export public keys via direct param extraction */
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        pubbuf = OPENSSL_malloc(publen);
        if (pubbuf == NULL)
            goto err;
        if (!extract_pubkey(key, pubbuf, publen))
            goto err;
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                               pubbuf, publen))
            goto err;
    }

    /* Export private keys via EVP_PKEY_export callback */
    if (hybrid_have_prvkey(key)
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)) {
        EXPORT_PRV_ARG sub;
        int prv_sel = OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                    | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;

        prvbuf = OPENSSL_secure_zalloc(prvlen);
        if (prvbuf == NULL)
            goto err;

        key_slot_offsets(key, 0, &off1, &len1, &off2, &len2);

        sub.buf = prvbuf;
        sub.found = 0;
        sub.off = off1;
        sub.len = len1;
        if (!EVP_PKEY_export(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1), prv_sel, export_prv_cb, &sub)
            || !sub.found)
            goto err;

        sub.found = 0;
        sub.off = off2;
        sub.len = len2;
        if (!EVP_PKEY_export(HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2), prv_sel, export_prv_cb, &sub)
            || !sub.found)
            goto err;

        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                               prvbuf, prvlen))
            goto err;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);

err:
    /*
     * OSSL_PARAM_free() does not wipe payloads, so cleanse the private-key
     * copy the param builder made before releasing it.
     */
    if (params != NULL) {
        OSSL_PARAM *pp = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

        if (pp != NULL && pp->data != NULL)
            OPENSSL_cleanse(pp->data, pp->data_size);
    }
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_secure_clear_free(prvbuf, prvlen);
    OPENSSL_free(pubbuf);
    return ret;
}

static const OSSL_PARAM hybrid_imexport_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_kem_imexport_types(int selection)
{
    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        return hybrid_imexport_types;
    return NULL;
}

/* --- get_params / gettable_params --- */

static const OSSL_PARAM hybrid_gettable[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    /* Signature keys advertise an empty mandatory digest ("no prehash"), which
     * is how CMS/ASN1 detect a one-shot signer (cms_signature_nomd) and take the
     * EVP_DigestSign one-shot path instead of streaming Update/Final, which we
     * do not implement. Mirrors ML-DSA/EdDSA. */
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    /* Component extraction (item 13): each component's standalone SPKI (public)
     * and PKCS#8 (private) DER. */
    OSSL_PARAM_octet_string(HYBRID_PKEY_PARAM_CLASSIC_PUB, NULL, 0),
    OSSL_PARAM_octet_string(HYBRID_PKEY_PARAM_PQ_PUB, NULL, 0),
    OSSL_PARAM_octet_string(HYBRID_PKEY_PARAM_CLASSIC_PRIV, NULL, 0),
    OSSL_PARAM_octet_string(HYBRID_PKEY_PARAM_PQ_PRIV, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_kem_gettable_params(void *provctx)
{
    return hybrid_gettable;
}

static int hybrid_get_params_fn(void *vkey, OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    OSSL_PARAM *p;
    size_t max_size;

    if (key == NULL)
        return 0;

    /* Report the PQ component's key size; a hybrid's "bits" is otherwise
     * ill-defined and the PQ half dominates. */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL) {
        EVP_PKEY *pq = HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2);
        int bits = pq != NULL ? EVP_PKEY_get_bits(pq) : 0;

        if (!OSSL_PARAM_set_int(p, bits))
            return 0;
    }

    /* Hybrid security is bounded by the weaker component — derive it, don't
     * hardcode (it differs per algorithm: e.g. ML-DSA-44/65/87 -> ~128/192/256,
     * P-256/384/521 -> 128/192/256). */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL) {
        int sec = 0;
        unsigned i;

        for (i = 0; i < HYBRID_KEY_NCOMP(key); i++) {
            int s;

            if (HYBRID_KEY_COMP(key, i) == NULL)
                continue;
            s = EVP_PKEY_get_security_bits(HYBRID_KEY_COMP(key, i));
            if (sec == 0 || s < sec)
                sec = s;
        }
        if (!OSSL_PARAM_set_int(p, sec))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL) {
        if (key->is_kem)
            max_size = hybrid_kem_ctext_bytes(key);
        else
            max_size = hybrid_sig_max_sig_bytes(key);
        if (!OSSL_PARAM_set_size_t(p, max_size))
            return 0;
    }

    /* Signature keys are one-shot: report an empty mandatory digest so CMS and
     * the ASN1 signing machinery skip streaming DigestSignUpdate (unimplemented)
     * and use EVP_DigestSign directly. See hybrid_gettable[]. */
    if (!key->is_kem) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
        if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ""))
            return 0;
    }

    /* Return encoded public key if requested and available */
    if (hybrid_have_pubkey(key)) {
        p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
        if (p == NULL)
            p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p != NULL) {
            size_t publen = hybrid_key_pubkey_bytes(key);

            p->return_size = publen;
            if (p->data != NULL) {
                if (p->data_size < publen)
                    return 0;
                if (!extract_pubkey(key, p->data, publen))
                    return 0;
            }
        }

        /* Component extraction (item 13): each component's standalone SPKI,
         * d2i_PUBKEY-able into a usable EVP_PKEY. key1 = classical, key2 = PQ. */
        p = OSSL_PARAM_locate(params, HYBRID_PKEY_PARAM_CLASSIC_PUB);
        if (p != NULL && !hybrid_component_spki_param(p, HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1)))
            return 0;
        p = OSSL_PARAM_locate(params, HYBRID_PKEY_PARAM_PQ_PUB);
        if (p != NULL && !hybrid_component_spki_param(p, HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2)))
            return 0;
    }

    /* The private halves, as standalone PKCS#8, when this key holds them. */
    if (hybrid_have_prvkey(key)) {
        p = OSSL_PARAM_locate(params, HYBRID_PKEY_PARAM_CLASSIC_PRIV);
        if (p != NULL && !hybrid_component_pkcs8_param(p, HYBRID_KEY_COMP(key, HYBRID_COMP_ALG1)))
            return 0;
        p = OSSL_PARAM_locate(params, HYBRID_PKEY_PARAM_PQ_PRIV);
        if (p != NULL && !hybrid_component_pkcs8_param(p, HYBRID_KEY_COMP(key, HYBRID_COMP_ALG2)))
            return 0;
    }

    return 1;
}

/* --- set_params / settable_params --- */

static const OSSL_PARAM hybrid_settable[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hybrid_kem_settable_params(void *provctx)
{
    return hybrid_settable;
}

static int hybrid_set_params_fn(void *vkey, const OSSL_PARAM params[])
{
    HYBRID_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pubenc;
    size_t publen;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(key->propq);
        key->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &key->propq, 0))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p == NULL)
        return 1;

    if (hybrid_have_pubkey(key))
        return 0; /* no mutation */

    if (!OSSL_PARAM_get_octet_string_ptr(p, &pubenc, &publen))
        return 0;
    if (publen != hybrid_key_pubkey_bytes(key))
        return 0;

    return load_keys(key, pubenc, publen, NULL, 0);
}

/* --- Key Generation --- */

/*
 * Generate a component key via the generic EVP keygen path.
 *
 * We deliberately avoid EVP_PKEY_Q_keygen(): that convenience helper only
 * accepts algorithm names from a hardcoded allowlist in libcrypto (RSA, EC,
 * the EdDSA/ECDH curves, SM2). ML-KEM/ML-DSA were not added to that list until
 * OpenSSL 3.5, so relying on it would both break on 3.4.x and contradict the
 * provider's goal of composing arbitrary sub-algorithms from any provider.
 * EVP_PKEY_CTX_new_from_name() resolves the algorithm purely by name and
 * property query, with no such restriction.
 */
static EVP_PKEY *
hybrid_component_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                        const char *alg_name, const char *group_name)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, alg_name, propq);
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0)
        goto err;

    if (group_name != NULL) {
        OSSL_PARAM parr[2];

        parr[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                   (char *)group_name, 0);
        parr[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, parr) <= 0)
            goto err;
    } else if (strcmp(alg_name, "RSA") == 0) {
        /* The only RSA classical component in the hybrid sigs is RSA-3072. */
        size_t bits = 3072;
        OSSL_PARAM parr[2];

        parr[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits);
        parr[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_CTX_set_params(ctx, parr) <= 0)
            goto err;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

err:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const char *alg2_propq;       /* borrowed from provctx */
    const char *alg1_propq;  /* borrowed from provctx */
    int selection;
    int is_kem;
    unsigned int algo_idx;
} HYBRID_GEN_CTX;

static void *hybrid_gen(void *vgctx, OSSL_CALLBACK *cb, void *cbarg)
{
    HYBRID_GEN_CTX *gctx = vgctx;
    HYBRID_KEY *key;
    char *propq;
    unsigned i;

    if (gctx == NULL)
        return NULL;

    propq = gctx->propq;
    gctx->propq = NULL;
    key = hybrid_key_new(gctx->is_kem, gctx->algo_idx, gctx->libctx, propq);
    if (key == NULL)
        return NULL;
    key->alg2_propq = gctx->alg2_propq;
    key->alg1_propq = gctx->alg1_propq;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    for (i = 0; i < HYBRID_KEY_NCOMP(key); i++) {
        HYBRID_KEY_COMP(key, i) =
            hybrid_component_keygen(key->libctx, hybrid_key_comp_propq(key, i),
                                    hybrid_key_comp_name(key, i),
                                    hybrid_key_comp_group(key, i));
        /* Any component failing leaves an unusable hybrid: free the whole
         * (partially generated) key so no component leaks, and fail. */
        if (HYBRID_KEY_COMP(key, i) == NULL) {
            hybrid_key_free(key);
            return NULL;
        }
    }
    key->state = HYBRID_HAVE_PRVKEY;
    return key;
}

static void hybrid_gen_cleanup(void *vgctx)
{
    HYBRID_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static const OSSL_PARAM gen_settable[] = {
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};

static int hybrid_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    HYBRID_GEN_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(gctx->propq);
        gctx->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &gctx->propq, 0))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *hybrid_gen_settable_params(void *vgctx,
                                                      void *provctx)
{
    return gen_settable;
}

/*
 * Macro to declare per-algorithm keymgmt_new and keymgmt_gen_init,
 * plus the dispatch table. is_kem_val: 1=KEM, 0=SIG.
 */
#define DECLARE_HYBRID_KMGMT(name, is_kem_val, variant)                      \
    static void *hybrid_##name##_new(void *provctx)                          \
    {                                                                        \
        HYBRID_PROV_CTX *ctx = provctx;                                      \
        OSSL_LIB_CTX *libctx =                                               \
            ctx ? HYBRID_COMPONENT_LIBCTX(ctx) : NULL;                       \
        HYBRID_KEY *k = hybrid_key_new(is_kem_val, variant, libctx, NULL);   \
        if (k != NULL && ctx != NULL) {                                      \
            k->alg2_propq = ctx->alg2_propq;                                     \
            k->alg1_propq = ctx->alg1_propq;                          \
        }                                                                    \
        return k;                                                            \
    }                                                                        \
    static void *hybrid_##name##_gen_init(void *provctx, int selection,      \
                                          const OSSL_PARAM params[])         \
    {                                                                        \
        HYBRID_PROV_CTX *pctx = provctx;                                     \
        HYBRID_GEN_CTX *gctx;                                               \
        /* Accept any selection asking for key material — in particular the   \
         * OSSL_KEYMGMT_SELECT_KEYPAIR libssl passes when generating a TLS     \
         * key-share (issue #45). KEYPAIR covers PUBLIC_KEY|PRIVATE_KEY;       \
         * DOMAIN_PARAMETERS is also accepted (paramgen-style init). gen()     \
         * always produces a full keypair regardless. */                      \
        if (pctx == NULL                                                     \
                || (selection & (OSSL_KEYMGMT_SELECT_KEYPAIR                  \
                        | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)) == 0)      \
            return NULL;                                                     \
        gctx = OPENSSL_zalloc(sizeof(*gctx));                                \
        if (gctx == NULL) return NULL;                                       \
        gctx->is_kem = is_kem_val;                                          \
        gctx->algo_idx = variant;                                            \
        gctx->libctx = HYBRID_COMPONENT_LIBCTX(pctx);                       \
        gctx->alg2_propq = pctx->alg2_propq;                                     \
        gctx->alg1_propq = pctx->alg1_propq;                          \
        gctx->selection = selection;                                         \
        if (!hybrid_gen_set_params(gctx, params)) {                          \
            hybrid_gen_cleanup(gctx);                                        \
            return NULL;                                                     \
        }                                                                    \
        return gctx;                                                         \
    }                                                                        \
    const OSSL_DISPATCH hybrid_##name##_kmgmt_functions[] = {                \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hybrid_##name##_new },      \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))hybrid_key_load },         \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hybrid_key_free },         \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hybrid_kem_has },           \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hybrid_kem_match },       \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))hybrid_kem_dup },           \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hybrid_import },         \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                   \
          (void (*)(void))hybrid_kem_imexport_types },                       \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hybrid_export },         \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                   \
          (void (*)(void))hybrid_kem_imexport_types },                       \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                     \
          (void (*)(void))hybrid_get_params_fn },                            \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                \
          (void (*)(void))hybrid_kem_gettable_params },                      \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                     \
          (void (*)(void))hybrid_set_params_fn },                            \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                \
          (void (*)(void))hybrid_kem_settable_params },                      \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,                                       \
          (void (*)(void))hybrid_##name##_gen_init },                        \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                 \
          (void (*)(void))hybrid_gen_set_params },                           \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                            \
          (void (*)(void))hybrid_gen_settable_params },                      \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))hybrid_gen },               \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                    \
          (void (*)(void))hybrid_gen_cleanup },                              \
        { 0, NULL }                                                          \
    }

/* KEM keymgmt instances — generated from the master list in hybrid_prov.h.
 * Each row binds its keymgmt thunks to the matching info-table index. */
#define HYBRID_KEM_KMGMT_ROW(cf, ...) \
    DECLARE_HYBRID_KMGMT(cf, 1, HYBRID_KEM_IDX_##cf);
HYBRID_KEM_LIST(HYBRID_KEM_KMGMT_ROW)
#undef HYBRID_KEM_KMGMT_ROW

/* Signature keymgmt instances — generated from the master list. */
#define HYBRID_SIG_KMGMT_ROW(cf, ...) \
    DECLARE_HYBRID_KMGMT(cf, 0, HYBRID_SIG_IDX_##cf);
HYBRID_SIG_LIST(HYBRID_SIG_KMGMT_ROW)
#undef HYBRID_SIG_KMGMT_ROW
