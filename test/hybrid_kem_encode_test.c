/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * KEM key-file interop test (gated by HYBRID_KEM_ENCODERS, mirroring
 * oqsprovider's OQS_KEM_ENCODERS). For each hybrid KEM that has an assigned OID,
 * round-trips SPKI (public) and PKCS8 (private) key files between the hybrid
 * provider and oqsprovider, in both directions, and proves the reconstructed key
 * works by completing a cross-provider encapsulate/decapsulate whose shared
 * secrets must match.
 *
 * Self-skips when the hybrid provider was built without KEM encoders, or when
 * oqsprovider is unavailable / built without OQS_KEM_ENCODERS.
 *
 * The three encodable hybrid KEMs cover both component orderings and classical
 * key encodings: p256_mlkem512 (EC, forward), SecP384r1MLKEM1024 (EC, forward),
 * x25519_mlkem512 (X25519 raw, reverse-share).
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/err.h>

static int tests, passed, failed;

/*
 * Hybrid KEMs with an assigned OID (key-file encodable). Their interop peer is
 * oqsprovider: the default provider implements the MLX KEMs as TLS groups only
 * and has NO key-file encoders for them, so oqsprovider is the sole peer that
 * both owns and serializes these keys. SecP384r1MLKEM1024 is owned+encoded by
 * oqsprovider on OpenSSL < 3.5 but ceded to default (which can't encode it) on
 * >= 3.5; the per-alg peer check below then skips it rather than failing.
 */
static const char *kems[] = {
    "p256_mlkem512", "x25519_mlkem512", "SecP384r1MLKEM1024",
};

/* Can `prop` generate this algorithm? (peer-availability probe) */
static int provider_has(OSSL_LIB_CTX *ctx, const char *alg, const char *prop)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, prop);
    int ok = g != NULL && EVP_PKEY_keygen_init(g) > 0;

    ERR_clear_error();
    EVP_PKEY_CTX_free(g);
    return ok;
}

/* Encode key to DER of `structure` ("SubjectPublicKeyInfo"/"PrivateKeyInfo"). */
static int encode(EVP_PKEY *pk, int sel, const char *structure, const char *prop,
                  unsigned char **der, size_t *derlen)
{
    OSSL_ENCODER_CTX *e =
        OSSL_ENCODER_CTX_new_for_pkey(pk, sel, "DER", structure, prop);
    int ok = e != NULL && OSSL_ENCODER_CTX_get_num_encoders(e) > 0
             && OSSL_ENCODER_to_data(e, der, derlen) > 0;

    OSSL_ENCODER_CTX_free(e);
    return ok;
}

/* Does the hybrid provider expose a KEM encoder for `alg`? (feature gate) */
static int hybrid_kem_encoders_present(OSSL_LIB_CTX *ctx, const char *alg)
{
    EVP_PKEY_CTX *g = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *k = NULL;
    OSSL_ENCODER_CTX *e = NULL;
    int present = 0;

    if (g != NULL && EVP_PKEY_keygen_init(g) > 0 && EVP_PKEY_keygen(g, &k) > 0) {
        e = OSSL_ENCODER_CTX_new_for_pkey(k, EVP_PKEY_PUBLIC_KEY, "DER",
                                          "SubjectPublicKeyInfo",
                                          "provider=hybrid");
        present = e != NULL && OSSL_ENCODER_CTX_get_num_encoders(e) > 0;
    }
    ERR_clear_error();
    OSSL_ENCODER_CTX_free(e);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(g);
    return present;
}

static EVP_PKEY *decode(OSSL_LIB_CTX *ctx, const char *structure, int sel,
                        const char *prop, const unsigned char *der, size_t derlen)
{
    EVP_PKEY *pk = NULL;
    OSSL_DECODER_CTX *d = OSSL_DECODER_CTX_new_for_pkey(
        &pk, "DER", structure, NULL, sel, ctx, prop);
    const unsigned char *p = der;

    if (d == NULL || OSSL_DECODER_from_data(d, &p, &derlen) <= 0)
        pk = NULL;
    OSSL_DECODER_CTX_free(d);
    return pk;
}

static int kem_encaps(OSSL_LIB_CTX *ctx, EVP_PKEY *pub, const char *prop,
                      unsigned char **ct, size_t *ctlen,
                      unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, pub, prop);
    int ok = 0;

    if (c == NULL || EVP_PKEY_encapsulate_init(c, NULL) <= 0
        || EVP_PKEY_encapsulate(c, NULL, ctlen, NULL, sslen) <= 0)
        goto end;
    *ct = OPENSSL_malloc(*ctlen);
    *ss = OPENSSL_malloc(*sslen);
    if (*ct == NULL || *ss == NULL
        || EVP_PKEY_encapsulate(c, *ct, ctlen, *ss, sslen) <= 0)
        goto end;
    ok = 1;
end:
    EVP_PKEY_CTX_free(c);
    return ok;
}

static int kem_decaps(OSSL_LIB_CTX *ctx, EVP_PKEY *priv, const char *prop,
                      const unsigned char *ct, size_t ctlen,
                      unsigned char **ss, size_t *sslen)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_pkey(ctx, priv, prop);
    int ok = 0;

    if (c == NULL || EVP_PKEY_decapsulate_init(c, NULL) <= 0
        || EVP_PKEY_decapsulate(c, NULL, sslen, ct, ctlen) <= 0)
        goto end;
    *ss = OPENSSL_malloc(*sslen);
    if (*ss == NULL || EVP_PKEY_decapsulate(c, *ss, sslen, ct, ctlen) <= 0)
        goto end;
    ok = 1;
end:
    EVP_PKEY_CTX_free(c);
    return ok;
}

/*
 * Encapsulate to `encaps_key` (via encaps_prop) and decapsulate with
 * `decaps_key` (via decaps_prop); the shared secrets must match. Used to prove a
 * key survived a key-file round-trip across the two providers.
 */
static int ss_match(OSSL_LIB_CTX *ctx, EVP_PKEY *encaps_key, const char *ep,
                    EVP_PKEY *decaps_key, const char *dp)
{
    unsigned char *ct = NULL, *ssa = NULL, *ssb = NULL;
    size_t ctlen = 0, ssalen = 0, ssblen = 0;
    int ok = 0;

    if (!kem_encaps(ctx, encaps_key, ep, &ct, &ctlen, &ssa, &ssalen)
        || !kem_decaps(ctx, decaps_key, dp, ct, ctlen, &ssb, &ssblen))
        goto end;
    ok = ssalen == ssblen && ssalen > 0 && memcmp(ssa, ssb, ssalen) == 0;
end:
    OPENSSL_free(ct);
    OPENSSL_free(ssa);
    OPENSSL_free(ssb);
    return ok;
}

/* One direction: keygen with `src`, encode via `src`, decode via `dst`. */
static void one_dir(OSSL_LIB_CTX *ctx, const char *alg, const char *label,
                    const char *srcprop, const char *dstprop)
{
    EVP_PKEY_CTX *g = NULL;
    EVP_PKEY *a = NULL, *pub_b = NULL, *prv_b = NULL;
    unsigned char *spki = NULL, *p8 = NULL;
    size_t spkilen = 0, p8len = 0;

    /* --- SPKI (public) round-trip --- */
    tests++;
    printf("  %-22s %s SPKI ... ", alg, label);
    fflush(stdout);
    g = EVP_PKEY_CTX_new_from_name(ctx, alg, srcprop);
    if (g != NULL && EVP_PKEY_keygen_init(g) > 0 && EVP_PKEY_keygen(g, &a) > 0
        && encode(a, EVP_PKEY_PUBLIC_KEY, "SubjectPublicKeyInfo", srcprop,
                  &spki, &spkilen)
        && (pub_b = decode(ctx, "SubjectPublicKeyInfo", EVP_PKEY_PUBLIC_KEY,
                           dstprop, spki, spkilen)) != NULL
        /* encaps to the decoded pub (dst), decaps with the original priv (src) */
        && ss_match(ctx, pub_b, dstprop, a, srcprop)) {
        printf("PASS\n"); passed++;
    } else {
        printf("FAIL\n"); ERR_print_errors_fp(stdout); failed++;
    }

    /* --- PKCS8 (private) round-trip --- */
    tests++;
    printf("  %-22s %s PKCS8 ... ", alg, label);
    fflush(stdout);
    if (a != NULL
        && encode(a, EVP_PKEY_KEYPAIR, "PrivateKeyInfo", srcprop, &p8, &p8len)
        && (prv_b = decode(ctx, "PrivateKeyInfo", EVP_PKEY_KEYPAIR, dstprop,
                           p8, p8len)) != NULL
        /* encaps to the original pub (src), decaps with the decoded priv (dst) */
        && ss_match(ctx, a, srcprop, prv_b, dstprop)) {
        printf("PASS\n"); passed++;
    } else {
        printf("FAIL\n"); ERR_print_errors_fp(stdout); failed++;
    }

    OPENSSL_free(spki);
    OPENSSL_clear_free(p8, p8len);
    EVP_PKEY_free(a);
    EVP_PKEY_free(pub_b);
    EVP_PKEY_free(prv_b);
    EVP_PKEY_CTX_free(g);
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
        fprintf(stderr, "failed to load default/hybrid\n");
        return 1;
    }
    if (OSSL_PROVIDER_load(ctx, "oqsprovider") == NULL) {
        printf("oqsprovider unavailable -- SKIPPING\n");
        return 0;
    }
    if (!hybrid_kem_encoders_present(ctx, kems[0])) {
        printf("hybrid provider built without HYBRID_KEM_ENCODERS -- SKIPPING\n");
        return 0;
    }

    printf("hybrid <-> oqsprovider KEM key-file interop\n");
    printf("==========================================\n");
    for (i = 0; i < sizeof(kems) / sizeof(kems[0]); i++) {
        if (!provider_has(ctx, kems[i], "provider=oqsprovider")) {
            printf("  %-22s SKIPPED (oqsprovider does not provide it here)\n",
                   kems[i]);
            continue;
        }
        one_dir(ctx, kems[i], "hybrid->oqs", "provider=hybrid",
                "provider=oqsprovider");
        one_dir(ctx, kems[i], "oqs->hybrid", "provider=oqsprovider",
                "provider=hybrid");
    }
    printf("\nResults: %d/%d passed, %d failed\n", passed, tests, failed);

    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
