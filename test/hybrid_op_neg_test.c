/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Operation-level negative tests: the sign/verify and encaps/decaps entry
 * points must reject hostile or misused input with a clean failure (no crash,
 * no over-read under ASan, no key/secret produced). The round-trip suites only
 * drive well-formed operations, so these guards were otherwise never reached:
 *
 *   Signatures (hybrid + composite):
 *     S1. sign-init on a public-only key, verify-init on a key with no material
 *     S2. sign into a buffer one byte smaller than the size query reported
 *     S3. verify a signature that is empty / shorter than the length prefix /
 *         carries a component-1 length past its end / is truncated / is flipped
 *     S4. context string (3.2+): the wrong OSSL_PARAM type is refused; a
 *         signature made under one never verifies under another or none —
 *         every component binds it or refuses it (fail closed, whatever its
 *         provider); composite binds it into M', so there it must sign,
 *         and refuses one over 255 bytes. Delivered every way (init param,
 *         set_ctx_params after init, a copied context, the streaming
 *         message-signature API), the outcome must be the same
 *     S5. streaming verify-final without the SIGNATURE ctx-param (3.4+)
 *     S6. digest sign/verify-init with an explicit digest name
 *
 *   KEMs (hybrid + composite):
 *     K1. encaps-init on a key with no material, decaps-init on a public-only
 *         key
 *     K2. encaps into a too-small ciphertext / secret buffer
 *     K3. decaps a ciphertext one byte short, one byte long, and empty
 *     K4. decaps into a too-small secret buffer
 *     K5. decaps a garbage ciphertext of the right length: either a clean fail
 *         or (implicit rejection) a secret different from the real one
 *
 * Every family is iterated from its info table; a row whose components are not
 * available in this build self-skips. Driven through the public EVP API only.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include "hybrid_prov.h"
#include "prov_util.h"   /* hybrid_test_load, hybrid_test_libctx_free */
#include "key_util.h"    /* keygen/reimport/empty-key/verify/decaps helpers */
#ifdef HYBRID_COMPOSITE
# include "composite_prov.h"
# include "composite_kem_prov.h"
#endif

#define PROPQ HYBRID_TEST_PROPQ
#define EXPECT HYBRID_TEST_EXPECT
/* `sig` (len bytes) is a valid signature by `k` over this test's message. */
#define VERIFIES(k, sig, len) \
    hybrid_test_verify(ctx, (k), (sig), (len), msg, sizeof(msg), NULL)

/* The hybrid signature's UINT32 big-endian component-1 length prefix. */
#define PREFIX_LEN sizeof(uint32_t)

static int tests, passed, failed, skipped;

static void put_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}
static const unsigned char msg[] = "hybrid-provider negative-path message";

/* --- signatures --- */

static int sign_init(OSSL_LIB_CTX *ctx, EVP_MD_CTX *m, EVP_PKEY *k,
                     const OSSL_PARAM *params)
{
    int r = EVP_DigestSignInit_ex(m, NULL, NULL, ctx, PROPQ, k, params) > 0;

    ERR_clear_error();
    return r;
}

/*
 * The ways a context string reaches a signature operation besides the one-shot
 * init param (S4): set through set_ctx_params after init, carried into a
 * copied operation context, or given to the streaming message-signature API.
 */
enum { CS_SET, CS_DUP, CS_STREAM, CS_HOWS };
static const char *const cs_how[CS_HOWS] = {
    "set after init", "copied context", "streaming API"
};

/*
 * Sign (sign = 1: into sig, capacity *len in, length out) or verify (sign = 0:
 * sig of *len bytes) msg with `k`, delivering `params` (may be NULL) the `how`
 * way. Returns 1 on success, 0 on failure, -1 if `how` is unavailable here.
 */
static int cs_op(OSSL_LIB_CTX *ctx, const char *alg, EVP_PKEY *k, int sign,
                 int how, const OSSL_PARAM *params,
                 unsigned char *sig, size_t *len)
{
    EVP_MD_CTX *m = NULL, *m2 = NULL;
    EVP_PKEY_CTX *pc = NULL;
    int r = 0;

    if (how == CS_STREAM) {
#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(ctx, alg, PROPQ);
        size_t half = sizeof(msg) / 2;

        pc = EVP_PKEY_CTX_new_from_pkey(ctx, k, PROPQ);
        r = s != NULL && pc != NULL
            && (sign ? EVP_PKEY_sign_message_init(pc, s, params)
                     : EVP_PKEY_verify_message_init(pc, s, params)) > 0
            && (sign || EVP_PKEY_CTX_set_signature(pc, sig, *len) > 0)
            && (sign ? EVP_PKEY_sign_message_update(pc, msg, half)
                     : EVP_PKEY_verify_message_update(pc, msg, half)) > 0
            && (sign ? EVP_PKEY_sign_message_update(pc, msg + half,
                                                    sizeof(msg) - half)
                     : EVP_PKEY_verify_message_update(pc, msg + half,
                                                      sizeof(msg) - half)) > 0
            && (sign ? EVP_PKEY_sign_message_final(pc, sig, len) > 0
                     : EVP_PKEY_verify_message_final(pc) == 1);
        EVP_SIGNATURE_free(s);
#else
        r = -1;
#endif
        goto end;
    }
    if ((m = EVP_MD_CTX_new()) == NULL)
        goto end;
    if (sign) {
        if (EVP_DigestSignInit_ex(m, &pc, NULL, ctx, PROPQ, k,
                                  how == CS_DUP ? params : NULL) <= 0)
            goto end;
    } else if (EVP_DigestVerifyInit_ex(m, &pc, NULL, ctx, PROPQ, k,
                                       how == CS_DUP ? params : NULL) <= 0) {
        goto end;
    }
    pc = NULL;                          /* owned by m */
    if (how == CS_SET && params != NULL
            && EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(m), params) <= 0)
        goto end;
    if (how == CS_DUP) {
        if ((m2 = EVP_MD_CTX_new()) == NULL || !EVP_MD_CTX_copy_ex(m2, m))
            goto end;
        EVP_MD_CTX_free(m);             /* the copy must stand on its own */
        m = m2;
        m2 = NULL;
    }
    r = sign ? EVP_DigestSign(m, sig, len, msg, sizeof(msg)) > 0
             : EVP_DigestVerify(m, sig, *len, msg, sizeof(msg)) == 1;
end:
    EVP_MD_CTX_free(m);
    EVP_MD_CTX_free(m2);
    EVP_PKEY_CTX_free(pc);
    ERR_clear_error();
    return r;
}

static void check_sig(OSSL_LIB_CTX *ctx, const char *alg, int is_hybrid)
{
    EVP_PKEY *k = NULL, *pub = NULL, *empty = NULL;
    EVP_MD_CTX *m = NULL;
    unsigned char *sig = NULL, *bad = NULL;
    size_t maxlen = 0, siglen = 0, small;
    int ok = 1;

    printf("  %-34s sig negatives ... ", alg);
    fflush(stdout);
    tests++;
    if ((k = hybrid_test_keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--;
        return;
    }
    EXPECT((pub = hybrid_test_reimport(ctx, alg, k,
                                       EVP_PKEY_PUBLIC_KEY)) != NULL,
           "public-only copy");

    /* S1: no private key -> sign-init fails; no material -> verify-init
     * fails. */
    EXPECT((m = EVP_MD_CTX_new()) != NULL, "EVP_MD_CTX_new");
    EXPECT(!sign_init(ctx, m, pub, NULL), "sign-init on a public-only key");
    if ((empty = hybrid_test_empty_key(ctx, alg)) != NULL) {
        EVP_MD_CTX_reset(m);
        EXPECT(EVP_DigestVerifyInit_ex(m, NULL, NULL, ctx, PROPQ, empty,
                                       NULL) <= 0,
               "verify-init on a key without material");
        ERR_clear_error();
    }

    /* S2: a buffer one byte short of the size query must be refused. */
    EVP_MD_CTX_reset(m);
    EXPECT(sign_init(ctx, m, k, NULL), "sign-init");
    EXPECT(EVP_DigestSign(m, NULL, &maxlen, msg, sizeof(msg)) > 0 && maxlen > 1,
           "signature size query");
    EXPECT((sig = OPENSSL_malloc(maxlen)) != NULL, "alloc");
    /* The hybrid wire format needs the full size-query bound (one byte short
     * fails); a composite signature may be shorter than its bound (variable
     * ECDSA DER), so it is offered half the bound, always below the fixed PQ
     * part plus any classical signature. */
    small = is_hybrid ? maxlen - 1 : maxlen / 2;
    EXPECT(EVP_DigestSign(m, sig, &small, msg, sizeof(msg)) <= 0,
           "sign into a too-small buffer");
    ERR_clear_error();

    /* A real signature as the base for the verify mutations. */
    EVP_MD_CTX_reset(m);
    siglen = maxlen;
    EXPECT(sign_init(ctx, m, k, NULL)
           && EVP_DigestSign(m, sig, &siglen, msg, sizeof(msg)) > 0, "sign");
    EXPECT(VERIFIES(pub, sig, siglen), "genuine signature verifies");

    /* S3: malformed signatures. */
    EXPECT((bad = OPENSSL_malloc(siglen)) != NULL, "alloc");
    EXPECT(!VERIFIES(pub, sig, 0), "empty signature");
    EXPECT(!VERIFIES(pub, sig, PREFIX_LEN - 1),
           "signature shorter than a prefix");
    EXPECT(!VERIFIES(pub, sig, siglen - 1), "truncated signature");
    memcpy(bad, sig, siglen);
    bad[siglen - 1] ^= 0x01;
    EXPECT(!VERIFIES(pub, bad, siglen), "bit-flipped signature");
    if (is_hybrid) {
        /* Hybrid wire format: UINT32(len1) || sig1 || sig2. */
        memcpy(bad, sig, siglen);
        put_be32(bad, 0xFFFFFFFFu);
        EXPECT(!VERIFIES(pub, bad, siglen),
               "len1 past the end");
        put_be32(bad, (uint32_t)(siglen - PREFIX_LEN));
        EXPECT(!VERIFIES(pub, bad, siglen),
               "empty component 2");
        put_be32(bad, 0);
        EXPECT(!VERIFIES(pub, bad, siglen),
               "empty component 1");
    }

#ifdef OSSL_SIGNATURE_PARAM_CONTEXT_STRING
    /* S4: context string. */
    {
        static unsigned char cs_a[] = "context A", cs_b[] = "context B";
        OSSL_PARAM pa[2], pb[2];
        size_t cslen = maxlen;
        int bound, how;
        char what[128];

        pa[0] = OSSL_PARAM_construct_utf8_string(
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING, "ctx", 0);
        pa[1] = OSSL_PARAM_construct_end();
        EVP_MD_CTX_reset(m);
        EXPECT(!sign_init(ctx, m, k, pa), "utf8 context-string accepted");

        pa[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING, cs_a, sizeof(cs_a));
        pb[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING, cs_b, sizeof(cs_b));
        pb[1] = OSSL_PARAM_construct_end();
        EVP_MD_CTX_reset(m);
        bound = sign_init(ctx, m, k, pa)
                && EVP_DigestSign(m, sig, &cslen, msg, sizeof(msg)) > 0;
        ERR_clear_error();
        /* Refusing is fail-closed for a hybrid (a component cannot honour
         * it); composite binds it into M' itself, so must sign. */
        EXPECT(bound || is_hybrid, "composite refused a context string");
        if (bound) {
            EXPECT(hybrid_test_verify(ctx, pub, sig, cslen, msg, sizeof(msg),
                                      pa),
                   "signature does not verify under its context string");
            EXPECT(!hybrid_test_verify(ctx, pub, sig, cslen, msg, sizeof(msg),
                                       pb),
                   "context string ignored: verifies under another one");
            EXPECT(!VERIFIES(pub, sig, cslen),
                   "context string ignored: verifies without one");
        }
        /* The other delivery paths must give the same outcome: bound
         * (verifies under its own context string only), or refused. */
        for (how = 0; how < CS_HOWS; how++) {
            int got;

            cslen = maxlen;
            if ((got = cs_op(ctx, alg, k, 1, how, pa, sig, &cslen)) < 0)
                continue;                       /* API absent on this build */
            snprintf(what, sizeof(what), "%s: %s", cs_how[how],
                     bound ? "refused a context string the init path binds"
                           : "signed although the init path refuses");
            EXPECT(got == bound, what);
            if (!bound)
                continue;
            snprintf(what, sizeof(what), "%s: not bound to its context string",
                     cs_how[how]);
            EXPECT(cs_op(ctx, alg, pub, 0, how, pa, sig, &cslen) == 1
                   && cs_op(ctx, alg, pub, 0, how, pb, sig, &cslen) == 0
                   && cs_op(ctx, alg, pub, 0, how, NULL, sig, &cslen) == 0
                   && hybrid_test_verify(ctx, pub, sig, cslen, msg,
                                         sizeof(msg), pa),
                   what);
        }
#ifdef HYBRID_COMPOSITE
        if (!is_hybrid) {
            /* draft-19: len(ctx) > 255 MUST be an error. */
            static unsigned char cs_long[COMPOSITE_SIG_CTX_MAX + 1];

            pa[0] = OSSL_PARAM_construct_octet_string(
                        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, cs_long,
                        sizeof(cs_long));
            EVP_MD_CTX_reset(m);
            EXPECT(!sign_init(ctx, m, k, pa),
                   "composite accepted a context string over 255 bytes");
        }
#endif
    }
#endif

    /* S6: the component digests are fixed by the algorithm, so a caller digest
     * must be refused, not silently overridden. */
    EVP_MD_CTX_reset(m);
    EXPECT(EVP_DigestSignInit_ex(m, NULL, "SHA256", ctx, PROPQ, k, NULL) <= 0,
           "sign-init accepted an explicit digest");
    EVP_MD_CTX_reset(m);
    EXPECT(EVP_DigestVerifyInit_ex(m, NULL, "SHA256", ctx, PROPQ, pub,
                                   NULL) <= 0,
           "verify-init accepted an explicit digest");
    ERR_clear_error();

#ifdef OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT
    /* S5: streaming verify needs the signature delivered as a ctx-param. */
    {
        EVP_SIGNATURE *s = EVP_SIGNATURE_fetch(ctx, alg, PROPQ);
        EVP_PKEY_CTX *pc = EVP_PKEY_CTX_new_from_pkey(ctx, pub, PROPQ);
        int r = 1;

        if (s != NULL && pc != NULL
                && EVP_PKEY_verify_message_init(pc, s, NULL) > 0
                && EVP_PKEY_verify_message_update(pc, msg, sizeof(msg)) > 0)
            r = EVP_PKEY_verify_message_final(pc);
        EVP_PKEY_CTX_free(pc);
        EVP_SIGNATURE_free(s);
        ERR_clear_error();
        EXPECT(r <= 0, "verify-message-final without a signature");
    }
#endif
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    OPENSSL_free(sig);
    OPENSSL_free(bad);
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(empty);
}

/* --- KEMs --- */

static void check_kem(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY *k = NULL, *pub = NULL, *empty = NULL;
    EVP_PKEY_CTX *c = NULL;
    unsigned char *ct = NULL, *ss = NULL, *ss2 = NULL, *junk = NULL;
    size_t ctlen = 0, sslen = 0, l1, l2;
    int ok = 1;

    printf("  %-34s KEM negatives ... ", alg);
    fflush(stdout);
    tests++;
    if ((k = hybrid_test_keygen(ctx, alg)) == NULL) {
        printf("SKIP (components unavailable)\n");
        skipped++; tests--;
        return;
    }
    EXPECT((pub = hybrid_test_reimport(ctx, alg, k,
                                       EVP_PKEY_PUBLIC_KEY)) != NULL,
           "public-only copy");

    /* K1 */
    EXPECT((c = EVP_PKEY_CTX_new_from_pkey(ctx, pub, PROPQ)) != NULL, "ctx");
    EXPECT(EVP_PKEY_decapsulate_init(c, NULL) <= 0,
           "decaps-init on a public-only key");
    ERR_clear_error();
    EVP_PKEY_CTX_free(c);
    c = NULL;
    if ((empty = hybrid_test_empty_key(ctx, alg)) != NULL) {
        EXPECT((c = EVP_PKEY_CTX_new_from_pkey(ctx, empty, PROPQ)) != NULL,
               "ctx");
        EXPECT(EVP_PKEY_encapsulate_init(c, NULL) <= 0,
               "encaps-init on a key without material");
        ERR_clear_error();
        EVP_PKEY_CTX_free(c);
        c = NULL;
    }

    /* K2: size query, then too-small output buffers. */
    EXPECT((c = EVP_PKEY_CTX_new_from_pkey(ctx, pub, PROPQ)) != NULL
           && EVP_PKEY_encapsulate_init(c, NULL) > 0
           && EVP_PKEY_encapsulate(c, NULL, &ctlen, NULL, &sslen) > 0
           && ctlen > 1 && sslen > 1, "encaps size query");
    EXPECT((ct = OPENSSL_malloc(ctlen)) != NULL
           && (ss = OPENSSL_malloc(sslen)) != NULL
           && (ss2 = OPENSSL_malloc(sslen)) != NULL
           && (junk = OPENSSL_malloc(ctlen + 1)) != NULL, "alloc");
    l1 = ctlen - 1; l2 = sslen;
    EXPECT(EVP_PKEY_encapsulate(c, ct, &l1, ss, &l2) <= 0,
           "encaps into a too-small ciphertext buffer");
    l1 = ctlen; l2 = sslen - 1;
    EXPECT(EVP_PKEY_encapsulate(c, ct, &l1, ss, &l2) <= 0,
           "encaps into a too-small secret buffer");
    ERR_clear_error();
    l1 = ctlen; l2 = sslen;
    EXPECT(EVP_PKEY_encapsulate(c, ct, &l1, ss, &l2) > 0 && l1 == ctlen,
           "encaps");
    sslen = l2;

    /* K3: wrong-length ciphertexts. */
    memcpy(junk, ct, ctlen);
    junk[ctlen] = 0;
    l2 = sslen;
    EXPECT(!hybrid_test_decaps(ctx, k, ct, ctlen - 1, ss2, &l2),
           "short ciphertext");
    l2 = sslen;
    EXPECT(!hybrid_test_decaps(ctx, k, junk, ctlen + 1, ss2, &l2),
           "long ciphertext");
    l2 = sslen;
    EXPECT(!hybrid_test_decaps(ctx, k, ct, 0, ss2, &l2),
           "empty ciphertext");

    /* K4: secret buffer one byte short. */
    l2 = sslen - 1;
    EXPECT(!hybrid_test_decaps(ctx, k, ct, ctlen, ss2, &l2),
           "too-small secret buffer");

    /* Sanity: the genuine ciphertext still decapsulates to the same secret. */
    l2 = sslen;
    EXPECT(hybrid_test_decaps(ctx, k, ct, ctlen, ss2, &l2) && l2 == sslen
           && memcmp(ss, ss2, sslen) == 0, "genuine decaps");

    /* K5: garbage of the right length. A component may reject it (invalid EC
     * point) or implicitly reject (ML-KEM), but must never yield the real
     * secret. */
    memset(junk, 0xAB, ctlen);
    l2 = sslen;
    if (hybrid_test_decaps(ctx, k, junk, ctlen, ss2, &l2))
        EXPECT(l2 != sslen || memcmp(ss, ss2, sslen) != 0,
               "garbage ciphertext yielded the real secret");
end:
    if (ok) {
        printf("PASS\n");
        passed++;
    } else {
        failed++;
    }
    if (ss != NULL)
        OPENSSL_clear_free(ss, sslen);
    if (ss2 != NULL)
        OPENSSL_clear_free(ss2, sslen);
    OPENSSL_free(ct);
    OPENSSL_free(junk);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(k);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(empty);
}

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

    printf("operation negatives: sign/verify + encaps/decaps misuse\n");
    printf("========================================================\n");
    for (i = 0; i < HYBRID_SIG_ALG_COUNT; i++)
        check_sig(ctx, hybrid_sig_table[i].hybrid_name, 1);
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        check_kem(ctx, hybrid_kem_table[i].hybrid_name);
#ifdef HYBRID_COMPOSITE
    for (i = 0; i < COMPOSITE_SIG_ALG_COUNT; i++)
        check_sig(ctx, composite_sig_table[i].name, 0);
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        check_kem(ctx, composite_kem_table[i].name);
#endif

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);
    hybrid_test_libctx_free(ctx);
    return failed == 0 ? 0 : 1;
}
