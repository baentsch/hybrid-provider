/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Item 7: decoder robustness against real-world and hostile inputs. The existing
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
 * All families share one SPKI parser (hybrid_spki_parse) and one read-all/OID
 * routing path, so driving the hybrid signature family here exercises the same
 * code the composite decoders reuse; the composite families are additionally
 * iterated when built (-DHYBRID_COMPOSITE).
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
#include <openssl/err.h>
#include "hybrid_prov.h"
#include "hybrid_asn1_compat.h"
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
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
static unsigned char *make_p8(const char *oidstr, const unsigned char *inner,
                              size_t innerlen, size_t *outlen)
{
    ASN1_OBJECT *oid = OBJ_txt2obj(oidstr, 1);
    ASN1_OCTET_STRING *oct = ASN1_OCTET_STRING_new();
    PKCS8_PRIV_KEY_INFO *p8 = PKCS8_PRIV_KEY_INFO_new();
    unsigned char *innder = NULL, *der = NULL;
    int innderlen, derlen;

    if (oid == NULL || oct == NULL || p8 == NULL
            || !hybrid_asn1_octet_set(oct, inner, innerlen)
            || (innderlen = i2d_ASN1_OCTET_STRING(oct, &innder)) < 0
            || !PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, innder, innderlen))
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

/* Item 7.3: structurally valid PKCS#8 carrying a malformed inner hybrid blob must
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

    /* (b) clen = 0: slot 1 is empty. A PQ slot-1 component (len < a1_prv) and a
     * classical slot-1 (d2i over 0 bytes) both reject. */
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

/* Item 7.1: hybrid key as the SECOND object of a multi-object PEM, decoded via
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

/* Item 7.2: malformed SPKI DER must fail cleanly, no crash, no key. */
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
    OSSL_PROVIDER_load(ctx, "oqsprovider");
    ERR_clear_error();

    printf("decoder robustness: external + malformed inputs (item 7)\n");
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
        check_malformed_p8(ctx, hybrid_sig_table[i].oid);
    }
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++) {
        check_multiobj(ctx, composite_sig_table[i].name);
        check_malformed(ctx, composite_sig_table[i].name);
    }
#endif

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
