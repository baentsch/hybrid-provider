/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Decoder robustness against real-world and hostile inputs. The existing
 * encode tests only exercise well-formed round-trips. This adds:
 *
 *   1. Multi-object PEM, target key NOT first: a leading unrelated PEM object (an
 *      EC "PUBLIC KEY" block) precedes our hybrid PKCS#8. Decoding via the GENERIC
 *      PEM_read_bio_PrivateKey_ex() (not a type-specific call) must skip the
 *      leading object and return OUR key -- this also proves the decoder is
 *      registered for generic private-key decode, not only via a pinned decoder.
 *
 *   2. Malformed / truncated / garbage DER on the SPKI path must fail cleanly
 *      (no key produced) and never crash -- run under ASan on the sanitize leg,
 *      so a bad-length read or over-read is caught.
 *
 *   3. A structurally valid PKCS#8 whose *inner* hybrid blob is malformed must
 *      fail cleanly in the slot-symmetric private loader
 *      (hybrid_key_load_prv_components_sym). DER truncation (case 2) fails at the
 *      ASN.1 layer and never reaches that code, so this crafts the inner blob
 *      directly to hit the UINT32 slot-1 length bound and the per-slot size
 *      checks (empty slot 1, empty slot 2, garbage components).
 *
 *   4. A structurally valid SPKI carrying one of OUR OIDs but a malformed public
 *      key (empty, shorter than the length prefix, prefix past the end, garbage
 *      components) must fail cleanly in the OID-routed loaders -- for every
 *      OID-bearing row of every family (hybrid sig/KEM, composite sig/KEM).
 *      The PKCS#8 cases of (3) are likewise driven for every family's OIDs.
 *
 *   5. Input over the decoder size cap (HYBRID_MAX_KEY_DER) is refused, and a
 *      well-formed SPKI with a FOREIGN OID is declined (not ours, no key).
 *
 *   6. A genuine key whose DER-encoded classical component is swapped for a
 *      well-formed key of the wrong curve or RSA size is refused (type pinning).
 *
 * All families share one SPKI parser (hybrid_spki_parse) and one read-all/OID
 * routing path; the composite families are additionally iterated when built
 * (-DHYBRID_COMPOSITE).
 *
 * Driven through the public OSSL_ENCODER / OSSL_DECODER / PEM APIs by name.
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "hybrid_prov.h"
#include "hybrid_asn1_compat.h"
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */
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

/* Encode `selection` of `pk` to a text/DER blob via provider `prop`. */
static unsigned char *encode(EVP_PKEY *pk, int selection, const char *outtype,
                             const char *structure, const char *prop, size_t *len)
{
    OSSL_ENCODER_CTX *e = OSSL_ENCODER_CTX_new_for_pkey(pk, selection, outtype,
                                                        structure, prop);
    unsigned char *out = NULL;

    if (e == NULL || OSSL_ENCODER_CTX_get_num_encoders(e) == 0
            || OSSL_ENCODER_to_data(e, &out, len) <= 0) {
        OPENSSL_free(out);
        out = NULL;
    }
    OSSL_ENCODER_CTX_free(e);
    return out;
}

/* Decode a SubjectPublicKeyInfo DER blob via the hybrid provider (NULL on fail). */
static EVP_PKEY *decode_spki_der(OSSL_LIB_CTX *ctx, const unsigned char *der,
                                 size_t derlen)
{
    EVP_PKEY *pk = NULL;
    OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(
        &pk, "DER", "SubjectPublicKeyInfo", NULL, EVP_PKEY_PUBLIC_KEY, ctx,
        "provider=hybrid");
    const unsigned char *p = der;
    size_t l = derlen;

    if (d == NULL || OSSL_DECODER_from_data(d, &p, &l) <= 0)
        pk = NULL;
    OSSL_DECODER_CTX_free(d);
    return pk;
}

/* Decode a PKCS#8 PrivateKeyInfo DER blob via the hybrid provider (NULL on fail). */
static EVP_PKEY *decode_p8_der(OSSL_LIB_CTX *ctx, const unsigned char *der,
                               size_t derlen)
{
    EVP_PKEY *pk = NULL;
    OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(
        &pk, "DER", "PrivateKeyInfo", NULL, EVP_PKEY_KEYPAIR, ctx,
        "provider=hybrid");
    const unsigned char *p = der;
    size_t l = derlen;

    if (d == NULL || OSSL_DECODER_from_data(d, &p, &l) <= 0)
        pk = NULL;
    OSSL_DECODER_CTX_free(d);
    return pk;
}

/* Wrap `inner` (innerlen bytes) as the privateKey OCTET STRING of a well-formed
 * PKCS#8 with algorithm `oidstr` -- i.e. a structurally valid PKCS#8 whose inner
 * hybrid blob we control. DER truncation alone fails at the ASN.1 layer and never
 * reaches hybrid_key_load_prv_components_sym; this routes by OID and drives that
 * slot-symmetric loader directly. Returns i2d DER (caller OPENSSL_free). */
static unsigned char *make_p8_wrap(const char *oidstr, int octet_wrap,
                                   const unsigned char *inner, size_t innerlen,
                                   size_t *outlen)
{
    ASN1_OBJECT *oid = OBJ_txt2obj(oidstr, 1);
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO_new();
    unsigned char *innder = NULL, *der = NULL;
    int innderlen, derlen;

    if (oid == NULL || oct == NULL || p8 == NULL)
        goto err;
    if (octet_wrap) {
        if (!hybrid_asn1_octet_set(oct, inner, innerlen)
                || (innderlen = i2d_ASN1_OCTET_STRING(oct, &innder)) < 0)
            goto err;
    } else if ((innder = OPENSSL_memdup(inner, innerlen)) == NULL) {
        goto err;
    } else {
        innderlen = (int)innerlen;
    }
    if (!PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, innder, innderlen))
        goto err;
    oid = NULL; innder = NULL;           /* ownership transferred to p8 */
    if ((derlen = i2d_PKCS8_PRIV_KEY_INFO(p8, &der)) < 0)
        goto err;
    *outlen = (size_t)derlen;
    ASN1_OCTET_STRING_free(oct);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return der;
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(innder);
    ASN1_OCTET_STRING_free(oct);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return NULL;
}

/* The hybrid families' layout: the blob in an inner OCTET STRING. */
static unsigned char *make_p8(const char *oidstr, const unsigned char *inner,
                              size_t innerlen, size_t *outlen)
{
    return make_p8_wrap(oidstr, 1, inner, innerlen, outlen);
}

/* Feed one crafted-inner PKCS#8 to the private decoder; pass iff it fails cleanly
 * (no key, no crash -- the crash being the point under ASan). */
static int reject_p8(OSSL_LIB_CTX *ctx, const char *oid, const char *what,
                     const unsigned char *inner, size_t innerlen)
{
    unsigned char *der = NULL;
    size_t derlen = 0;
    EVP_PKEY *got = NULL;
    int ok;

    if ((der = make_p8(oid, inner, innerlen, &derlen)) == NULL) {
        printf("FAIL: could not build PKCS#8 (%s)\n", what);
        ERR_print_errors_fp(stdout);
        return 0;
    }
    got = decode_p8_der(ctx, der, derlen);
    ERR_clear_error();
    ok = (got == NULL);
    if (!ok)
        printf("FAIL: %s decoded to a key\n", what);
    EVP_PKEY_free(got);
    OPENSSL_free(der);
    return ok;
}

/* Structurally valid PKCS#8 carrying a malformed inner hybrid blob must
 * fail cleanly in the slot-symmetric private loader. Targets the UINT32 slot-1
 * length prefix (clen) bound and the per-slot size checks in load_prv_bykind. */
static void check_malformed_p8(OSSL_LIB_CTX *ctx, const char *oid)
{
    /* UINT32(clen) big-endian prefix helper. */
    unsigned char blob[96];
    int all = 1;

    printf("  %-28s malformed PKCS#8 inner -> clean fail ... ", oid);
    fflush(stdout);
    tests++;

    /* (a) clen = 0xFFFFFFFF with a short body: 4 + clen overflows octlen, so the
     * common slot-1 bound must reject before any slot read. */
    memset(blob, 0xAB, sizeof(blob));
    blob[0] = blob[1] = blob[2] = blob[3] = 0xFF;
    all &= reject_p8(ctx, oid, "clen=0xFFFFFFFF", blob, 32);

    /* (b) clen = 0: slot 1 is empty. A PQ slot-1 component (len < the classical
     * component's prv size) and a classical slot-1 (d2i over 0 bytes) both reject. */
    memset(blob, 0xAB, sizeof(blob));
    blob[0] = blob[1] = blob[2] = blob[3] = 0x00;
    all &= reject_p8(ctx, oid, "clen=0 (empty slot1)", blob, 32);

    /* (c) clen = octlen-4: slot 2 is empty. Neither a PQ nor a classical slot-2
     * component reconstructs from zero bytes. */
    memset(blob, 0xAB, sizeof(blob));
    blob[0] = 0x00; blob[1] = 0x00; blob[2] = 0x00; blob[3] = 28;   /* 4 + 28 = 32 */
    all &= reject_p8(ctx, oid, "clen=octlen-4 (empty slot2)", blob, 32);

    /* (d) internally consistent lengths, pure-garbage content of a plausible size:
     * routes to the component loaders, which must reject the junk key material. */
    memset(blob, 0xAB, sizeof(blob));
    blob[0] = 0x00; blob[1] = 0x00; blob[2] = 0x00; blob[3] = 48;   /* slot1 = 48 */
    all &= reject_p8(ctx, oid, "garbage components", blob, sizeof(blob));

    if (all) {
        printf("PASS (no key, no crash)\n");
        passed++;
    } else {
        failed++;
    }
}

/* A SubjectPublicKeyInfo with algorithm `oidstr` (absent parameters) and the
 * given public-key bits, as i2d DER (caller OPENSSL_free) -- built without any
 * key decode, so the bits can be anything. */
static unsigned char *make_spki(const char *oidstr, const unsigned char *pub,
                                size_t publen, size_t *outlen)
{
    ASN1_OBJECT *oid = OBJ_txt2obj(oidstr, 1);
    X509_PUBKEY *xp = X509_PUBKEY_new();
    unsigned char *bits = OPENSSL_malloc(publen > 0 ? publen : 1), *der = NULL;
    int derlen;

    if (oid == NULL || xp == NULL || bits == NULL)
        goto err;
    memcpy(bits, pub, publen);
    if (!X509_PUBKEY_set0_param(xp, oid, V_ASN1_UNDEF, NULL, bits, (int)publen))
        goto err;
    oid = NULL; bits = NULL;             /* ownership transferred to xp */
    if ((derlen = i2d_X509_PUBKEY(xp, &der)) < 0)
        goto err;
    *outlen = (size_t)derlen;
    X509_PUBKEY_free(xp);
    return der;
err:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(bits);
    X509_PUBKEY_free(xp);
    return NULL;
}

/* Feed one crafted SPKI to the public decoder; pass iff it fails cleanly. */
static int reject_spki(OSSL_LIB_CTX *ctx, const char *oid, const char *what,
                       const unsigned char *pub, size_t publen)
{
    unsigned char *der;
    size_t derlen = 0;
    EVP_PKEY *got;
    int ok;

    if ((der = make_spki(oid, pub, publen, &derlen)) == NULL) {
        printf("FAIL: could not build SPKI (%s)\n", what);
        ERR_print_errors_fp(stdout);
        return 0;
    }
    got = decode_spki_der(ctx, der, derlen);
    ERR_clear_error();
    ok = (got == NULL);
    if (!ok)
        printf("FAIL: %s decoded to a key\n", what);
    EVP_PKEY_free(got);
    OPENSSL_free(der);
    return ok;
}

/* Structurally valid SPKI, one of our OIDs, malformed public-key bits. The
 * cases target the hybrid UINT32(len1) prefix bounds and the component loaders;
 * for the composite layouts (fixed-length PQ part first) they are simply too
 * short / garbage, hitting the split-length bound and the loaders. */
static void check_malformed_spki_oid(OSSL_LIB_CTX *ctx, const char *oid)
{
    unsigned char blob[64];
    int all = 1;

    printf("  %-28s malformed SPKI bits -> clean fail ... ", oid);
    fflush(stdout);
    tests++;

    memset(blob, 0xAB, sizeof(blob));
    all &= reject_spki(ctx, oid, "empty public key", blob, 0);
    all &= reject_spki(ctx, oid, "public key shorter than the prefix", blob, 3);
    blob[0] = blob[1] = blob[2] = blob[3] = 0xFF;
    all &= reject_spki(ctx, oid, "len1=0xFFFFFFFF", blob, 32);
    blob[0] = blob[1] = blob[2] = 0x00; blob[3] = 8;   /* consistent split */
    all &= reject_spki(ctx, oid, "garbage components", blob, sizeof(blob));

    if (all) {
        printf("PASS (no key, no crash)\n");
        passed++;
    } else {
        failed++;
    }
}

/* Input past the decoder size cap must be refused on both the SPKI and the
 * PKCS#8 path. hybrid_dec_read_all() doubles its buffer from 4 KiB and gives
 * up once a full buffer already exceeds HYBRID_MAX_KEY_DER, i.e. at 2 * the
 * cap. */
static void check_oversize(OSSL_LIB_CTX *ctx)
{
    const size_t n = 2 * (size_t)HYBRID_MAX_KEY_DER + 1;
    unsigned char *big = OPENSSL_malloc(n);
    EVP_PKEY *a = NULL, *b = NULL;

    printf("  %-28s input > decoder cap -> refused ... ", "oversize");
    fflush(stdout);
    tests++;
    if (big == NULL) {
        printf("FAIL: alloc\n");
        failed++;
        return;
    }
    memset(big, 0xAB, n);
    big[0] = 0x30;                       /* looks like the start of a SEQUENCE */
    a = decode_spki_der(ctx, big, n);
    b = decode_p8_der(ctx, big, n);
    ERR_clear_error();
    if (a == NULL && b == NULL) {
        printf("PASS (no key, no crash)\n");
        passed++;
    } else {
        printf("FAIL: oversize input decoded to a key\n");
        failed++;
    }
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    OPENSSL_free(big);
}

/* A well-formed SPKI with an OID none of our families claims (a real P-256
 * key) is declined by our decoders: no hybrid key, no crash. On OpenSSL 3.0 the
 * decoder ctx does not filter decoders by the property query, so another
 * provider's decoder may still (correctly) return the EC key; what must not
 * happen is a key from OUR provider. */
static void check_foreign_oid(OSSL_LIB_CTX *ctx)
{
    EVP_PKEY *ec = EVP_PKEY_Q_keygen(ctx, NULL, "EC", "P-256"), *got = NULL;
    unsigned char *spki = NULL;
    size_t len = 0;

    printf("  %-28s foreign-OID SPKI -> declined ... ", "id-ecPublicKey");
    fflush(stdout);
    tests++;
    if (ec == NULL || (spki = encode(ec, EVP_PKEY_PUBLIC_KEY, "DER",
                                     "SubjectPublicKeyInfo", NULL, &len)) == NULL) {
        printf("FAIL: setup (EC keygen / SPKI encode)\n");
        ERR_print_errors_fp(stdout);
        failed++;
        goto end;
    }
    got = decode_spki_der(ctx, spki, len);
    ERR_clear_error();
    if (got == NULL || strcmp(OSSL_PROVIDER_get0_name(
                                  EVP_PKEY_get0_provider(got)), "hybrid") != 0) {
        printf("PASS (not ours, declined)\n");
        passed++;
    } else {
        printf("FAIL: the hybrid decoder claimed a foreign key\n");
        failed++;
    }
end:
    OPENSSL_free(spki);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(got);
}

/* Both malformed-OID-routed checks for one OID (NULL: not key-file encodable). */
static void check_oid(OSSL_LIB_CTX *ctx, const char *oid)
{
    if (oid == NULL)
        return;
    check_malformed_spki_oid(ctx, oid);
    check_malformed_p8(ctx, oid);
}

/* Hybrid key as the SECOND object of a multi-object PEM, decoded via
 * the generic PEM private-key API. */
static void check_multiobj(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY *k = NULL, *ec = NULL, *got = NULL;
    unsigned char *hpem = NULL, *ecpem = NULL, *buf = NULL;
    size_t hlen = 0, eclen = 0;
    BIO *bio = NULL;

    printf("  %-28s multi-object PEM (not first) ... ", alg);
    fflush(stdout);
    tests++;

    if ((k = keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto end;
    }
    /* Leading unrelated object: an EC public key -- NOT a private key, so the
     * generic PEM private-key reader must skip it. */
    ec = EVP_PKEY_Q_keygen(ctx, NULL, "EC", "P-256");
    hpem = encode(k, EVP_PKEY_KEYPAIR, "PEM", "PrivateKeyInfo", "provider=hybrid",
                  &hlen);
    ecpem = encode(ec, EVP_PKEY_PUBLIC_KEY, "PEM", "SubjectPublicKeyInfo", NULL,
                   &eclen);
    if (ec == NULL || hpem == NULL || ecpem == NULL) {
        printf("FAIL: setup (EC keygen / PEM encode)\n");
        ERR_print_errors_fp(stdout); failed++;
        goto end;
    }

    if ((buf = OPENSSL_malloc(eclen + hlen)) == NULL)
        goto end;
    memcpy(buf, ecpem, eclen);           /* unrelated object first */
    memcpy(buf + eclen, hpem, hlen);     /* our key second */

    bio = BIO_new_mem_buf(buf, (int)(eclen + hlen));
    if (bio == NULL
            || PEM_read_bio_PrivateKey_ex(bio, &got, NULL, NULL, ctx, NULL) == NULL
            || got == NULL) {
        printf("FAIL: generic PEM read did not return a key\n");
        ERR_print_errors_fp(stdout); failed++;
        goto end;
    }
    if (EVP_PKEY_eq(k, got) != 1) {
        printf("FAIL: decoded key is not our hybrid key\n");
        failed++;
        goto end;
    }
    printf("PASS (leading object skipped, our key decoded)\n");
    passed++;
end:
    OPENSSL_free(hpem);
    OPENSSL_free(ecpem);
    OPENSSL_free(buf);
    BIO_free(bio);
    EVP_PKEY_free(k);
    EVP_PKEY_free(ec);
    EVP_PKEY_free(got);
}

/* Malformed SPKI DER must fail cleanly, no crash, no key. */
static void check_malformed(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY *k = NULL, *got = NULL;
    unsigned char *spki = NULL;
    unsigned char garbage[64];
    size_t spkilen = 0;

    printf("  %-28s malformed SPKI -> clean fail ... ", alg);
    fflush(stdout);
    tests++;

    if ((k = keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        goto end;
    }
    if ((spki = encode(k, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo",
                       "provider=hybrid", &spkilen)) == NULL || spkilen < 8) {
        printf("FAIL: SPKI encode\n"); ERR_print_errors_fp(stdout); failed++;
        goto end;
    }

    /* (a) truncated to half length. */
    got = decode_spki_der(ctx, spki, spkilen / 2);
    ERR_clear_error();
    if (got != NULL) {
        printf("FAIL: truncated SPKI decoded to a key\n");
        failed++;
        goto end;
    }

    /* (b) pure garbage. */
    memset(garbage, 0xAB, sizeof(garbage));
    got = decode_spki_der(ctx, garbage, sizeof(garbage));
    ERR_clear_error();
    if (got != NULL) {
        printf("FAIL: garbage decoded to a key\n");
        failed++;
        goto end;
    }
    printf("PASS (no key, no crash)\n");
    passed++;
end:
    OPENSSL_free(spki);
    EVP_PKEY_free(k);
    EVP_PKEY_free(got);
}

/*
 * 6. Classical component pinning. The classical half of a key file is a DER
 *    blob that names its own key type, so a well-formed key of the WRONG type,
 *    curve or RSA size could be spliced in. For every row whose classical
 *    component is DER-encoded (EC/RSA), splice a mismatched key (another curve,
 *    or RSA-1024) into a genuine key's blob: the decoder must refuse it. The
 *    unmodified re-spliced blob must still decode (control), so the rejection
 *    is the mismatch, not the harness.
 */
/* A classical key that does NOT fit the row: RSA-1024 (below every RSA row)
 * for an RSA slot, else an EC key on a different curve (P-384 for a P-256 row,
 * P-256 otherwise -- also a same-size mismatch for the brainpool rows). */
static EVP_PKEY *mismatched_classical(OSSL_LIB_CTX *ctx, int is_rsa,
                                      const char *group)
{
    if (is_rsa)
        return EVP_PKEY_Q_keygen(ctx, NULL, "RSA", (size_t)1024);
    return EVP_PKEY_Q_keygen(ctx, NULL, "EC",
                             group != NULL && strcmp(group, "P-256") == 0
                                 ? "P-384" : "P-256");
}

/* The provider's inner key blob (PKCS#8 privateKey octets -- inside an inner
 * OCTET STRING when octet_wrap, as the hybrid families write it; directly for
 * composite -- or SPKI bits) of `k`, as a fresh copy (caller OPENSSL_free). */
static unsigned char *key_blob(EVP_PKEY *k, int pub, int octet_wrap,
                               size_t *len)
{
    size_t derlen = 0;
    unsigned char *der = encode(k, pub ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR,
                                "DER", pub ? "SubjectPublicKeyInfo"
                                           : "PrivateKeyInfo",
                                "provider=hybrid", &derlen);
    const unsigned char *p = der, *data = NULL;
    unsigned char *out = NULL;
    X509_PUBKEY *xp = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    int dlen = 0;

    if (der == NULL)
        return NULL;
    if (pub) {
        if ((xp = d2i_X509_PUBKEY(NULL, &p, (long)derlen)) != NULL
                && X509_PUBKEY_get0_param(NULL, &data, &dlen, NULL, xp))
            out = OPENSSL_memdup(data, (size_t)dlen);
    } else if ((p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)derlen)) != NULL
               && PKCS8_pkey_get0(NULL, &data, &dlen, NULL, p8)) {
        if (!octet_wrap) {
            out = OPENSSL_memdup(data, (size_t)dlen);
        } else if ((oct = d2i_ASN1_OCTET_STRING(NULL, &data, dlen)) != NULL) {
            out = OPENSSL_memdup(ASN1_STRING_get0_data(oct),
                                 hybrid_asn1_string_length(oct));
            dlen = (int)hybrid_asn1_string_length(oct);
        }
    }
    if (out != NULL)
        *len = (size_t)dlen;
    ERR_clear_error();
    ASN1_STRING_clear_free(oct);
    PKCS8_PRIV_KEY_INFO_free(p8);
    X509_PUBKEY_free(xp);
    OPENSSL_clear_free(der, derlen);
    return out;
}

/* A classical component's on-wire bytes, as the encoders write them:
 * i2d_PrivateKey (private) or i2d_PublicKey (RSA public). */
static unsigned char *classical_der(EVP_PKEY *k, int pub, size_t *len)
{
    unsigned char *der = NULL;
    int n = pub ? i2d_PublicKey(k, &der) : i2d_PrivateKey(k, &der);

    if (n <= 0)
        return NULL;
    *len = (size_t)n;
    return der;
}

/* 1 iff the blob, wrapped as `oid`'s SPKI (pub) or PKCS#8, decodes to a key. */
static int blob_decodes(OSSL_LIB_CTX *ctx, const char *oid, int pub,
                        int octet_wrap, const unsigned char *blob, size_t len)
{
    size_t derlen = 0;
    unsigned char *der = pub ? make_spki(oid, blob, len, &derlen)
                             : make_p8_wrap(oid, octet_wrap, blob, len, &derlen);
    EVP_PKEY *got = NULL;

    if (der != NULL)
        got = pub ? decode_spki_der(ctx, der, derlen)
                  : decode_p8_der(ctx, der, derlen);
    ERR_clear_error();
    EVP_PKEY_free(got);
    OPENSSL_clear_free(der, derlen);
    return got != NULL;
}

/* head || mid || tail, with mid's length written as a UINT32 prefix when
 * `prefix` is set (the hybrid slot-1 layout). Caller OPENSSL_clear_free. */
static unsigned char *splice(int prefix, const unsigned char *head, size_t hl,
                             const unsigned char *mid, size_t ml,
                             const unsigned char *tail, size_t tl, size_t *len)
{
    size_t pl = prefix ? 4 : 0;
    unsigned char *b = OPENSSL_malloc(pl + hl + ml + tl);

    if (b == NULL)
        return NULL;
    if (prefix) {
        b[0] = (unsigned char)(ml >> 24); b[1] = (unsigned char)(ml >> 16);
        b[2] = (unsigned char)(ml >> 8);  b[3] = (unsigned char)ml;
    }
    if (hl > 0)                          /* memcpy from NULL is UB even for 0 */
        memcpy(b + pl, head, hl);
    if (ml > 0)
        memcpy(b + pl + hl, mid, ml);
    if (tl > 0)
        memcpy(b + pl + hl + ml, tail, tl);
    *len = pl + hl + ml + tl;
    return b;
}

/* Record one pinning case: the re-spliced original (orig) must decode and the
 * mismatched splice (bad) must not. NULL buffers are a setup failure. */
static int pin_case(OSSL_LIB_CTX *ctx, const char *oid, int pub,
                    int octet_wrap, const char *what,
                    const unsigned char *orig, size_t ol,
                    const unsigned char *bad, size_t bl)
{
    if (orig == NULL || bad == NULL) {
        printf("FAIL: setup (%s)\n", what);
        ERR_print_errors_fp(stdout);
        return 0;
    }
    if (!blob_decodes(ctx, oid, pub, octet_wrap, orig, ol)) {
        printf("FAIL: control (%s): unmodified blob did not decode\n", what);
        return 0;
    }
    if (blob_decodes(ctx, oid, pub, octet_wrap, bad, bl)) {
        printf("FAIL: %s: mismatched classical component accepted\n", what);
        return 0;
    }
    return 1;
}

/* Hybrid signatures: slot-symmetric UINT32(len1) || slot1 || slot2, either slot
 * may be the classical one; RSA additionally in the SPKI (RSAPublicKey DER). */
static void check_pin_hybrid_sig(OSSL_LIB_CTX *ctx, const HYBRID_SIG_INFO *row)
{
    const char *grp[2] = { row->alg1_group, row->alg2_group };
    /* DER-encoded classical slots: EC (a group) or RSA. */
    int rsa[2] = { strcmp(row->alg1_name, "RSA") == 0,
                   strcmp(row->alg2_name, "RSA") == 0 };
    int der[2] = { rsa[0] || strcmp(row->alg1_name, "EC") == 0,
                   rsa[1] || strcmp(row->alg2_name, "EC") == 0 };
    EVP_PKEY *k = NULL;
    int slot, pub, all = 1;

    if (!der[0] && !der[1])
        return;
    printf("  %-28s mismatched classical -> refused ... ", row->hybrid_name);
    fflush(stdout);
    tests++;
    if ((k = keygen(ctx, row->hybrid_name)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        return;
    }
    for (slot = 0; slot < 2; slot++) {
        EVP_PKEY *sub;

        if (!der[slot])
            continue;
        sub = mismatched_classical(ctx, rsa[slot], grp[slot]);
        for (pub = 0; pub <= 1; pub++) {
            unsigned char *blob, *sd = NULL, *orig = NULL, *bad = NULL;
            size_t bl = 0, sl = 0, ol = 0, xl = 0, l1;

            /* An EC public point goes through a group-pinned fromdata already;
             * only RSA's public half is self-describing DER. */
            if (pub && !rsa[slot])
                continue;
            blob = key_blob(k, pub, 1, &bl);
            if (sub != NULL)
                sd = classical_der(sub, pub, &sl);
            if (blob != NULL && bl >= 4) {
                l1 = ((size_t)blob[0] << 24) | ((size_t)blob[1] << 16)
                   | ((size_t)blob[2] << 8) | blob[3];
                if (l1 <= bl - 4) {
                    const unsigned char *s1 = blob + 4, *s2 = blob + 4 + l1;
                    size_t l2 = bl - 4 - l1;

                    orig = splice(1, NULL, 0, s1, l1, s2, l2, &ol);
                    if (sd != NULL)
                        bad = slot == 0
                            ? splice(1, NULL, 0, sd, sl, s2, l2, &xl)
                            : splice(1, NULL, 0, s1, l1, sd, sl, &xl);
                }
            }
            all &= pin_case(ctx, row->oid, pub, 1,
                            pub ? "public slot" : "private slot",
                            orig, ol, bad, xl);
            OPENSSL_clear_free(orig, ol);
            OPENSSL_clear_free(bad, xl);
            OPENSSL_clear_free(sd, sl);
            OPENSSL_clear_free(blob, bl);
        }
        EVP_PKEY_free(sub);
    }
    if (all) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    EVP_PKEY_free(k);
}

#ifdef HYBRID_COMPOSITE
/* Length of `param` on a throwaway `pq_alg` key: the fixed PQ prefix length of
 * a composite blob (the provider discovers it the same way). */
static size_t pq_param_len(OSSL_LIB_CTX *ctx, const char *pq_alg,
                           const char *param)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, pq_alg, NULL);
    EVP_PKEY *t = NULL;
    size_t n = 0;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0 && EVP_PKEY_keygen(c, &t) > 0)
        EVP_PKEY_get_octet_string_param(t, param, NULL, 0, &n);
    EVP_PKEY_free(t);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return n;
}

/* Composite (sig and KEM): pq || trad, the PQ part at a fixed length. */
static void check_pin_composite(OSSL_LIB_CTX *ctx, const char *name,
                                const char *oid, const char *pq_alg,
                                const char *pq_priv_param,
                                const char *trad_alg, const char *trad_group,
                                int trad_rsa_bits)
{
    EVP_PKEY *k = NULL, *sub = NULL;
    int is_rsa = trad_rsa_bits != 0, pub, all = 1;

    /* DER-encoded classical: RSA (any padding) or EC; Ed/X are raw. */
    if (oid == NULL || !(is_rsa || strcmp(trad_alg, "EC") == 0))
        return;
    printf("  %-28s mismatched classical -> refused ... ", name);
    fflush(stdout);
    tests++;
    if ((k = keygen(ctx, name)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--; ERR_clear_error();
        return;
    }
    sub = mismatched_classical(ctx, is_rsa, trad_group);
    for (pub = 0; pub <= 1; pub++) {
        unsigned char *blob, *sd = NULL, *bad = NULL;
        size_t bl = 0, sl = 0, xl = 0;
        size_t pqn = pq_param_len(ctx, pq_alg, pub ? OSSL_PKEY_PARAM_PUB_KEY
                                                   : pq_priv_param);

        if (pub && !is_rsa)
            continue;                    /* see check_pin_hybrid_sig */
        blob = key_blob(k, pub, 0, &bl);
        if (sub != NULL)
            sd = classical_der(sub, pub, &sl);
        if (blob != NULL && sd != NULL && pqn > 0 && pqn < bl)
            bad = splice(0, blob, pqn, sd, sl, NULL, 0, &xl);
        all &= pin_case(ctx, oid, pub, 0,
                        pub ? "public trad" : "private trad",
                        blob, bl, bad, xl);
        OPENSSL_clear_free(bad, xl);
        OPENSSL_clear_free(sd, sl);
        OPENSSL_clear_free(blob, bl);
    }
    if (all) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    EVP_PKEY_free(sub);
    EVP_PKEY_free(k);
}
#endif

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (hybrid_test_load(ctx, "default") == NULL
            || hybrid_test_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    hybrid_test_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("decoder robustness: external + malformed inputs\n");
    printf("========================================================\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++) {
        /* An operation-only row (no OID) has no SPKI encoding to malform, so the
         * decoder-robustness premise does not apply. No shipped sig row is
         * operation-only (the §3.4 PQ/PQ rows now carry a private-use OID), but
         * the guard stays for the runtime-declared hybrids #112 will add. */
        if (hybrid_sig_table[i].oid == NULL)
            continue;
        check_multiobj(ctx, hybrid_sig_table[i].hybrid_name);
        check_malformed(ctx, hybrid_sig_table[i].hybrid_name);
        check_oid(ctx, hybrid_sig_table[i].oid);
    }
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check_oid(ctx, hybrid_kem_table[i].oid);
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        check_multiobj(ctx, composite_sig_table[i].name);
        check_malformed(ctx, composite_sig_table[i].name);
        check_oid(ctx, composite_sig_table[i].oid);
    }
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        check_oid(ctx, composite_kem_table[i].oid);
#endif
    check_oversize(ctx);
    check_foreign_oid(ctx);

    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        if (hybrid_sig_table[i].oid != NULL)
            check_pin_hybrid_sig(ctx, &hybrid_sig_table[i]);
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check_pin_composite(ctx, composite_sig_table[i].name,
                            composite_sig_table[i].oid,
                            composite_sig_table[i].pq_alg,
                            composite_sig_table[i].pq_priv_param,
                            composite_sig_table[i].trad_alg,
                            composite_sig_table[i].trad_group,
                            composite_sig_table[i].trad_rsa_bits);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        check_pin_composite(ctx, composite_kem_table[i].name,
                            composite_kem_table[i].oid,
                            composite_kem_table[i].pq_alg,
                            composite_kem_table[i].pq_priv_param,
                            composite_kem_table[i].trad_alg,
                            composite_kem_table[i].trad_group,
                            composite_kem_table[i].trad_rsa_bits);
#endif

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
