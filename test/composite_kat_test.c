/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Composite (LAMPS) KAT interop test (issue #6) — the real draft-19 cross-
 * implementation check against the reference test vectors of
 * draft-ietf-lamps-pq-composite-sigs (lamps-wg/draft-composite-sigs,
 * src/testvectors.json, distilled into test/composite_kat.txt). EVERY field the
 * draft ships is exercised, per vector:
 *
 *   K1. `s` (over m, empty ctx) verifies under the reference `pk`.
 *   K2. `sWithContext` verifies under `pk` with the draft's `ctx`.
 *   K3. ...and the context is bound: `sWithContext` fails without ctx, and `s`
 *       fails with it.
 *   K4. `sk` (raw private key) imports, and its public key equals `pk`.
 *   K5. a fresh signature by `sk` under `ctx` verifies under `pk` (ML-DSA
 *       signing is randomized, so there is no byte-exact signing KAT).
 *   K6. `sk_pkcs8` decodes to the same key: public equals `pk`, and the raw
 *       private export equals `sk` byte-for-byte.
 *   K7. `x5c` decodes, carries `pk`, and its self-signature verifies.
 *   K8. External prehash: `s`/`sWithContext` verify over PH(m), a PH(m)
 *       signature verifies over m, a short ph / other digest is refused.
 *   K9. cms-composite-sigs-05 Appendix B (argv[2]): the SignedData example
 *       verifies under the mldsa65_ecdsa_p256 `x5c`; a flipped signature
 *       byte does not.
 *
 * Verifying reference signatures proves our combiner byte-compatible with the
 * reference across the whole construction — prefix, per-algorithm label,
 * len(ctx) || ctx, prehash, RSA-PSS params, ML-DSA context, component split and
 * encoding — which self-consistent sign/verify cannot establish.
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
#include <openssl/decoder.h>
#include <openssl/x509.h>
#include <openssl/pem.h>   /* before cms.h: it declares PEM_read_bio_CMS */
#include <openssl/cms.h>
#include "hybrid_asn1_compat.h"
#include "composite_prov.h"   /* composite_sig_table: map KAT name -> PQ component */
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */

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

/*
 * Column offsets of a composite_kat.txt vector row: the name, then the FIELDS
 * of regen_composite_kat.py in order. The file's "#! columns:" header names
 * them, and main() refuses a file whose header differs from kat_col_name.
 */
enum {
    KAT_NAME, KAT_PK, KAT_S, KAT_SWC, KAT_SK, KAT_SK_PKCS8, KAT_X5C, KAT_COLS
};
static const char *const kat_col_name[KAT_COLS] = {
    "name", "pk", "s", "sWithContext", "sk", "sk_pkcs8", "x5c"
};
#define KAT_HEADER "#! columns:"

/* One decoded KAT row: v[c]/len[c] hold column c (KAT_NAME is in name). */
#define KAT_FIELD(k, c) (k)->v[c], (k)->len[c]     /* buffer, length */
typedef struct {
    const char *name;
    unsigned char *v[KAT_COLS];
    size_t len[KAT_COLS];
} KAT;

#define PROPQ "provider=hybrid"
#define EXPECT(cond, what)                                                 \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL (%s)\n", what);                                   \
            ERR_print_errors_fp(stdout);                                   \
            ok = 0;                                                        \
            goto end;                                                      \
        }                                                                  \
    } while (0)

/* Init params carrying context string `cs` (NULL: none). */
static const OSSL_PARAM *ctx_params(OSSL_PARAM p[2], const unsigned char *cs,
                                    size_t cslen)
{
    if (cs == NULL)
        return NULL;
    p[0] = OSSL_PARAM_construct_octet_string(
               OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)cs, cslen);
    p[1] = OSSL_PARAM_construct_end();
    return p;
}

/* 1 iff `sig` verifies over msg under `key` with context string `cs`. */
static int verifies(OSSL_LIB_CTX *ctx, EVP_PKEY *key,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *msg, size_t msglen,
                    const unsigned char *cs, size_t cslen)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    OSSL_PARAM p[2];
    int r = m != NULL
        && EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, PROPQ, key,
                                   ctx_params(p, cs, cslen)) > 0
        && EVP_DigestVerify(m, sig, siglen, msg, msglen) == 1;

    EVP_MD_CTX_free(m);
    ERR_clear_error();
    return r;
}

/* Import a raw key blob as `name` (`param` PUB_KEY or PRIV_KEY). */
static EVP_PKEY *import_raw(OSSL_LIB_CTX *ctx, const char *name,
                            const char *param, int selection,
                            unsigned char *blob, size_t len)
{
    EVP_PKEY_CTX *fc = EVP_PKEY_CTX_new_from_name(ctx, name, PROPQ);
    EVP_PKEY *key = NULL;
    OSSL_PARAM p[2];

    p[0] = OSSL_PARAM_construct_octet_string(param, blob, len);
    p[1] = OSSL_PARAM_construct_end();
    if (fc == NULL || EVP_PKEY_fromdata_init(fc) <= 0
            || EVP_PKEY_fromdata(fc, &key, selection, p) <= 0)
        key = NULL;
    EVP_PKEY_CTX_free(fc);
    return key;
}

/* 1 iff `key`'s exported raw private key equals want[0..wantlen). */
static int priv_equals(EVP_PKEY *key, const unsigned char *want,
                       size_t wantlen)
{
    OSSL_PARAM *params = NULL;
    const OSSL_PARAM *p;
    const void *got;
    size_t gotlen = 0;
    int r = EVP_PKEY_todata(key, EVP_PKEY_KEYPAIR, &params) > 0
        && (p = OSSL_PARAM_locate_const(params,
                                        OSSL_PKEY_PARAM_PRIV_KEY)) != NULL
        && OSSL_PARAM_get_octet_string_ptr(p, &got, &gotlen) == 1
        && gotlen == wantlen && memcmp(got, want, wantlen) == 0;

    OSSL_PARAM_free(params);
    return r;
}

/* Decode a DER PrivateKeyInfo as `name` with the hybrid provider. */
static EVP_PKEY *decode_p8(OSSL_LIB_CTX *ctx, const char *name,
                           const unsigned char *der, size_t len)
{
    EVP_PKEY *key = NULL;
    OSSL_DECODER_CTX *dc = OSSL_DECODER_CTX_new_for_pkey(
        &key, "DER", "PrivateKeyInfo", name, EVP_PKEY_KEYPAIR, ctx, PROPQ);

    if (dc == NULL || !OSSL_DECODER_from_data(dc, &der, &len)) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    OSSL_DECODER_CTX_free(dc);
    return key;
}

/* ph = PH(msg) for this combo: SHAKE256 at 64 bytes, else the natural size. */
static int prehash(OSSL_LIB_CTX *ctx, const COMPOSITE_SIG_INFO *info,
                   const unsigned char *msg, size_t msglen,
                   unsigned char *ph, size_t *phlen)
{
    EVP_MD *md = EVP_MD_fetch(ctx, info->prehash, NULL);
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    unsigned int l = 0;
    int r = md != NULL && mc != NULL && EVP_DigestInit_ex2(mc, md, NULL) > 0
            && EVP_DigestUpdate(mc, msg, msglen) > 0;

    if (r && (EVP_MD_get_flags(md) & EVP_MD_FLAG_XOF) != 0) {
        *phlen = COMPOSITE_XOF_PH_BYTES;
        r = EVP_DigestFinalXOF(mc, ph, *phlen) > 0;
    } else if (r) {
        r = EVP_DigestFinal_ex(mc, ph, &l) > 0;
        *phlen = l;
    }
    EVP_MD_CTX_free(mc);
    EVP_MD_free(md);
    return r;
}

/*
 * A real digest that is not `ph`: SHA-256 for the SHA-512 combos, else
 * SHA-512 -- the realistic wrong choice for each combo.
 */
static const char *other_digest(const char *ph)
{
    return OPENSSL_strcasecmp(ph, "SHA512") == 0 ? "SHA256" : "SHA512";
}

/*
 * Raw EVP_PKEY_sign/verify over ph = PH(M) (draft-19 "External Pre-hashing"):
 * op 0 = verify sig, 1 = sign into *sig. digest (optional) is set as the
 * signature digest param the way EVP_SignFinal_ex does.
 */
static int ph_op(OSSL_LIB_CTX *ctx, EVP_PKEY *key, int op, const char *digest,
                 const unsigned char *ph, size_t phlen,
                 const unsigned char *cs, size_t cslen,
                 unsigned char **sig, size_t *siglen)
{
    EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_pkey(ctx, key, PROPQ);
    OSSL_PARAM p[3], *q = p;
    int r = 0;

    if (digest != NULL)
        *q++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST,
                                                (char *)digest, 0);
    if (cs != NULL)
        *q++ = OSSL_PARAM_construct_octet_string(
                   OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void *)cs, cslen);
    *q = OSSL_PARAM_construct_end();
    if (pc == NULL
            || (op ? EVP_PKEY_sign_init(pc) : EVP_PKEY_verify_init(pc)) <= 0
            || EVP_PKEY_CTX_set_params(pc, p) <= 0)
        goto end;
    if (op) {
        r = EVP_PKEY_sign(pc, NULL, siglen, ph, phlen) > 0
            && (*sig = OPENSSL_malloc(*siglen)) != NULL
            && EVP_PKEY_sign(pc, *sig, siglen, ph, phlen) > 0;
    } else {
        r = EVP_PKEY_verify(pc, *sig, *siglen, ph, phlen) == 1;
    }
end:
    ERR_clear_error();
    EVP_PKEY_CTX_free(pc);
    return r;
}

/* K9 input: the CMS draft's Appendix B example, signed by this tcId's x5c. */
static const char *appb_file;
static const char APPB_ALG[] = "mldsa65_ecdsa_p256";
static int appb_done;

/* 1 iff the Appendix B SignedData verifies under signer cert x (tamper=0), or
 * still verifies after one signature byte is flipped (tamper=1). */
static int appb_verifies(OSSL_LIB_CTX *ctx, X509 *x, int tamper)
{
    BIO *b = BIO_new_file(appb_file, "r");
    CMS_ContentInfo *cms = CMS_ContentInfo_new_ex(ctx, NULL);
    STACK_OF(X509) *certs = sk_X509_new_null();
    X509_STORE *store = X509_STORE_new();
    int r = 0;

    if (b == NULL || cms == NULL || certs == NULL || store == NULL
            || PEM_read_bio_CMS(b, &cms, NULL, NULL) == NULL
            || !sk_X509_push(certs, x) || X509_STORE_add_cert(store, x) <= 0)
        goto end;
    if (tamper) {
        CMS_SignerInfo *si =
            sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
        ASN1_OCTET_STRING *sig = si != NULL ? CMS_SignerInfo_get0_signature(si)
                                            : NULL;

        if (sig == NULL || hybrid_asn1_string_length(sig) == 0)
            goto end;
        ((unsigned char *)ASN1_STRING_get0_data(sig))[0] ^= 1;
    }
    /* The signature is the subject, not the example cert's validity window. */
    r = CMS_verify(cms, certs, store, NULL, NULL,
                   CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY) > 0;
end:
    ERR_clear_error();
    X509_STORE_free(store);
    sk_X509_free(certs);
    CMS_ContentInfo_free(cms);
    BIO_free(b);
    return r;
}

static void check(OSSL_LIB_CTX *ctx, const KAT *k,
                  const unsigned char *msg, size_t msglen,
                  const unsigned char *cs, size_t cslen)
{
    const COMPOSITE_SIG_INFO *info = find_info(k->name);
    EVP_PKEY *pub = NULL, *prv = NULL, *p8 = NULL;
    EVP_MD_CTX *m = NULL;
    X509 *x = NULL;
    const unsigned char *q;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    OSSL_PARAM p[2];
    int ok = 1;

    tests++;
    printf("  %-22s all draft vector fields ... ", k->name);
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
    EXPECT((pub = import_raw(ctx, k->name, OSSL_PKEY_PARAM_PUB_KEY,
                             EVP_PKEY_PUBLIC_KEY, KAT_FIELD(k, KAT_PK)))
           != NULL,
           "pk import");
    /* K1-K3 */
    EXPECT(verifies(ctx, pub, KAT_FIELD(k, KAT_S), msg, msglen, NULL, 0),
           "K1: s does not verify");
    EXPECT(verifies(ctx, pub, KAT_FIELD(k, KAT_SWC), msg, msglen, cs, cslen),
           "K2: sWithContext does not verify under ctx");
    EXPECT(!verifies(ctx, pub, KAT_FIELD(k, KAT_SWC), msg, msglen, NULL, 0),
           "K3: sWithContext verifies without ctx");
    EXPECT(!verifies(ctx, pub, KAT_FIELD(k, KAT_S), msg, msglen, cs, cslen),
           "K3: s verifies under ctx");
    /* K4-K5 */
    EXPECT((prv = import_raw(ctx, k->name, OSSL_PKEY_PARAM_PRIV_KEY,
                             EVP_PKEY_KEYPAIR, KAT_FIELD(k, KAT_SK))) != NULL,
           "K4: sk import");
    EXPECT(EVP_PKEY_eq(prv, pub) == 1, "K4: sk's public key != pk");
    EXPECT((m = EVP_MD_CTX_new()) != NULL
           && EVP_DigestSignInit_ex(m, NULL, NULL, ctx, PROPQ, prv,
                                    ctx_params(p, cs, cslen)) > 0
           && EVP_DigestSign(m, NULL, &siglen, msg, msglen) > 0
           && (sig = OPENSSL_malloc(siglen)) != NULL
           && EVP_DigestSign(m, sig, &siglen, msg, msglen) > 0,
           "K5: sign with sk under ctx");
    EXPECT(verifies(ctx, pub, sig, siglen, msg, msglen, cs, cslen),
           "K5: our signature does not verify under pk");
    /* K6 */
    EXPECT((p8 = decode_p8(ctx, k->name, KAT_FIELD(k, KAT_SK_PKCS8))) != NULL,
           "K6: sk_pkcs8 decode");
    EXPECT(EVP_PKEY_eq(p8, pub) == 1, "K6: sk_pkcs8 public key != pk");
    EXPECT(priv_equals(p8, KAT_FIELD(k, KAT_SK)), "K6: sk_pkcs8 private != sk");
    /* K7 */
    /* Decode in the test's libctx, where the hybrid provider is loaded. No
     * propq: verify maps the signature OID to (PH, key) and fetches PH under
     * it, and the hybrid provider serves no digests. */
    q = k->v[KAT_X5C];
    EXPECT((x = X509_new_ex(ctx, NULL)) != NULL
           && d2i_X509(&x, &q, (long)k->len[KAT_X5C]) != NULL
           && q == k->v[KAT_X5C] + k->len[KAT_X5C], "K7: x5c decode");
    EXPECT(EVP_PKEY_eq(X509_get0_pubkey(x), pub) == 1,
           "K7: x5c public key != pk");
    EXPECT(X509_verify(x, pub) == 1, "K7: x5c self-signature");
    /* K8: external prehash (draft-19), the route CMS takes: s and
     * sWithContext verify over ph = PH(m); a ph signature verifies over m;
     * a wrong-length ph or a digest other than PH is refused. */
    {
        unsigned char ph[EVP_MAX_MD_SIZE], *phsig = NULL;
        unsigned char *s = k->v[KAT_S], *sc = k->v[KAT_SWC];
        size_t phlen = 0, slen = k->len[KAT_S], sclen = k->len[KAT_SWC];
        size_t phsiglen = 0;
        int got;

        EXPECT(prehash(ctx, info, msg, msglen, ph, &phlen), "K8: PH(m)");
        EXPECT(ph_op(ctx, pub, 0, info->prehash, ph, phlen, NULL, 0, &s,
                     &slen), "K8: s does not verify over PH(m)");
        EXPECT(ph_op(ctx, pub, 0, NULL, ph, phlen, cs, cslen, &sc, &sclen),
               "K8: sWithContext does not verify over PH(m) under ctx");
        got = ph_op(ctx, prv, 1, info->prehash, ph, phlen, cs, cslen, &phsig,
                    &phsiglen);
        EXPECT(got && verifies(ctx, pub, phsig, phsiglen, msg, msglen, cs,
                               cslen),
               "K8: a PH(m) signature does not verify over m");
        OPENSSL_free(phsig);
        EXPECT(!ph_op(ctx, pub, 0, NULL, ph, phlen - 1, NULL, 0, &s, &slen),
               "K8: a short ph verified");
        EXPECT(!ph_op(ctx, pub, 0, other_digest(info->prehash), ph, phlen,
                      NULL, 0, &s, &slen),
               "K8: a digest other than PH accepted");
    }
    /* K9 */
    if (appb_file != NULL && strcmp(k->name, APPB_ALG) == 0) {
        appb_done = 1;
        EXPECT(appb_verifies(ctx, x, 0), "K9: Appendix B SignedData");
        EXPECT(!appb_verifies(ctx, x, 1),
               "K9: Appendix B verified with a flipped signature byte");
    }
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    ERR_clear_error();
    OPENSSL_free(sig);
    EVP_MD_CTX_free(m);
    X509_free(x);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(prv);
    EVP_PKEY_free(p8);
}

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    const char *katfile = argc > 1 ? argv[1] : "composite_kat.txt";
    FILE *f;
    char *line = NULL;
    size_t cap = 0, msglen = 0, cslen = 0;
    unsigned char *msg = NULL, *cs = NULL;
    const char *bad = NULL;
    int have_header = 0;
    ssize_t n;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (hybrid_test_load(ctx, "default") == NULL
            || hybrid_test_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        hybrid_test_libctx_free(ctx);
        return 1;
    }
    ERR_clear_error();
    appb_file = argc > 2 ? argv[2] : NULL;

    if ((f = fopen(katfile, "r")) == NULL) {
        fprintf(stderr, "cannot open KAT file: %s\n", katfile);
        hybrid_test_libctx_free(ctx);
        return 1;
    }

    printf("composite (LAMPS) KAT interop vs draft-19 reference vectors\n");
    printf("(K1-K9: s, sWithContext+ctx binding, sk, sk_pkcs8, x5c, external "
           "prehash, CMS Appendix B)\n");
    printf("==========================================================\n");
    while ((n = getline(&line, &cap, f)) > 0) {
        char *save, *t, *tok[KAT_COLS + 1] = { NULL };
        size_t c, nt = 0;
        int hex_ok;
        KAT k = { 0 };

        if (strncmp(line, KAT_HEADER, strlen(KAT_HEADER)) == 0) {
            /* The column layout must be exactly the one this test indexes. */
            for (t = strtok_r(line + strlen(KAT_HEADER), " \t\r\n", &save);
                 t != NULL && nt < KAT_COLS;
                 t = strtok_r(NULL, " \t\r\n", &save))
                if (strcmp(t, kat_col_name[nt++]) != 0)
                    break;
            if (nt != KAT_COLS || t != NULL) {
                bad = "column header differs from this test's layout";
                break;
            }
            have_header = 1;
            continue;
        }
        if (line[0] == '#' || line[0] == '\n')
            continue;
        /* Collect one token more than a row has, to tell a long row apart. */
        for (t = strtok_r(line, " \t\r\n", &save);
             t != NULL && nt <= KAT_COLS;
             t = strtok_r(NULL, " \t\r\n", &save))
            tok[nt++] = t;
        if (strcmp(tok[0], "m") == 0 || strcmp(tok[0], "ctx") == 0) {
            unsigned char **dst = tok[0][0] == 'm' ? &msg : &cs;
            size_t *dlen = tok[0][0] == 'm' ? &msglen : &cslen;

            OPENSSL_free(*dst);
            if (nt != 2 || (*dst = hexdec(tok[1], dlen)) == NULL) {
                bad = "malformed m/ctx line";
                break;
            }
            continue;
        }
        if (!have_header || nt != KAT_COLS || msg == NULL || cs == NULL) {
            bad = "malformed vector row, or header/m/ctx missing before it";
            break;
        }
        k.name = tok[KAT_NAME];
        for (c = KAT_NAME + 1; c < KAT_COLS; c++)
            if ((k.v[c] = hexdec(tok[c], &k.len[c])) == NULL)
                break;
        hex_ok = c == KAT_COLS;
        if (hex_ok)
            check(ctx, &k, msg, msglen, cs, cslen);
        for (c = KAT_NAME + 1; c < KAT_COLS; c++)
            OPENSSL_free(k.v[c]);
        if (!hex_ok) {
            bad = "bad hex in a vector row";
            break;
        }
    }
    /* A malformed vendored file is a broken test, not a failed vector:
     * stop at once rather than test a partial set. */
    if (bad != NULL) {
        printf("  FAIL: %s: %s\n", katfile, bad);
        failed++;
        tests++;
    }
    OPENSSL_free(msg);
    OPENSSL_free(cs);
    free(line);
    fclose(f);

    if (appb_file != NULL && !appb_done)
        printf("  NOTE: K9 (CMS Appendix B) not run: %s skipped\n", APPB_ALG);
    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);

    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
