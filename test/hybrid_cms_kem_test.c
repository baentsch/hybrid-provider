/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * An encodable (SPKI) provider KEM as a CMS EnvelopedData KEMRI recipient
 * (issue #108).
 *
 * RFC 9629 KEMRI is KEM-GENERIC, NOT composite- or ML-KEM-specific: ANY KEM whose
 * public key has an X.509 SPKI encoding can be a CMS recipient — nothing about the
 * CMS path is tied to the primitive inside. OpenSSL's CMS layer is provider-
 * generic: CMS_encrypt resolves the recipient type via ossl_cms_pkey_get_ri_type(),
 * which — because our keymgmt does not advertise OSSL_PKEY_PARAM_CMS_RI_TYPE and
 * the key is neither EC/RSA/DH — falls through to probing
 * EVP_PKEY_encapsulate_init(ctx, NULL); that succeeds for any KEM, so the recipient
 * is auto-selected as CMS_RECIPINFO_KEM. No new crypto is needed.
 * cms_kemri_supported() below demonstrates exactly this with plain native
 * ML-KEM-768 (the default provider's) as its capability probe — naked ML-KEM KEMRI
 * rides the same generic path before this test touches any our-provider key.
 *
 * What this test adds on top of that generic path is coverage of THIS provider's
 * encodable KEMs as recipients. The KEMs our provider serves with a standalone
 * X.509 key encoding are the composite KEM family (draft-ietf-lamps-pq-composite-
 * kem): our MLX/X-Wing/SM2 TLS-group hybrids are KEMs too, but have no standalone
 * SPKI encoding and so cannot be CMS recipients (the limit is key serialization,
 * not the KEM). We run BOTH composite tiers to prove the path is primitive-generic:
 *   - the standardized ML-KEM tier (IANA/LAMPS OIDs 1.3.6.1.5.5.7.6.55..66); and
 *   - the experimental tier (Frodo/BIKE/HQC + ECDH, private OID arc 1.3.9999.99.x),
 *     which carries the same SPKI encoder and thus rides the same KEMRI path —
 *     exercising it over NON-ML-KEM PQ, the strongest evidence that KEMRI cares
 *     only about encapsulate-ability + SPKI, not the underlying KEM.
 *
 * For each such combo we:
 *   1. generate the KEM keypair via the provider (provider=hybrid);
 *   2. issue a recipient cert for it — a KEM key cannot self-sign, so a separate
 *      default-provider Ed25519 issuer signs the cert (keeps the test minimal),
 *      with X509_set_pubkey() driving the KEM's SPKI encoder;
 *   3. CMS_encrypt to that cert (AES-256-CBC -> EnvelopedData; the CEK is wrapped
 *      under the KEM-derived KEK via OpenSSL's default HKDF-SHA256 + AES-wrap);
 *   4. round-trip the CMS through DER (libctx-bound decode, as the KEM algorithm
 *      is resolved by name from the ContentInfo's own library context);
 *   5. CMS_decrypt with the KEM private key and assert the plaintext is
 *      recovered byte-for-byte;
 *   6. negative: decrypt the same message with a DIFFERENT key of the same type
 *      bound to the same cert identity -> wrong KEK -> AES key-unwrap integrity
 *      check fails -> CMS_decrypt must fail.
 *
 * Floors: *driving a KEM recipient through CMS* needs 3.6.0+ — OpenSSL 3.5's
 * ossl_cms_pkey_get_ri_type() knows only RSA/EC/DH and defaults a KEM key to key
 * transport. KEMRI (RFC 9629) and its KEM auto-selection landed in 3.6.0 (commit
 * d0899abb, PR 27681). So the whole suite self-skips via a runtime capability
 * probe (not a version check), and each combo additionally self-skips if its PQ
 * component is missing. No provider change is required: the CMS layer auto-probes
 * EVP_PKEY_encapsulate_init() and selects our KEM recipient on its own (the
 * OSSL_PKEY_PARAM_CMS_RI_TYPE provider hint is a later 4.0 addition, not needed).
 *
 * The algorithm set is driven off the master composite_kem_table (no hardcoded
 * name list), both tiers. cede-to-default is irrelevant here (the default provider
 * does not serve composite OIDs) but forced off in CMakeLists per convention. The
 * standardized tier's ML-KEM half comes from the default provider on 3.5+ (seed
 * API); the experimental tier's Frodo/BIKE/HQC half needs oqsprovider — loaded
 * optionally, so those combos self-skip when it is absent. (The test is built
 * under the 3.5+ seed-API gate, but that costs the experimental tier nothing: its
 * 3.6.0 KEMRI floor already implies 3.5, and the experimental keytype itself does
 * not use the seed API.)
 *
 * In-process self-interop only. Cross-implementation interop lives in two opt-in
 * harnesses: test/pqc_kem_cms_interop.sh (both ways against kemri_toy) and
 * test/pqc_kem_cms_certificates_interop.sh (one-way read of the IETF Hackathon
 * pqc-certificates cms_v3 EnvelopedData corpus).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "composite_kem_prov.h"
#include "hybrid_prov.h"   /* hybrid_kem_table: the (non-composite) hybrid family */

static int tests, passed, failed, skipped;

/* Resolve the ML-KEM component from any loaded provider (default on 3.5+). */
static int have_alg(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, NULL);
    int ok = c != NULL && EVP_PKEY_keygen_init(c) > 0;

    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

/* Generate a provider KEM keypair through the hybrid provider, by registered
 * name (a composite combo from either tier). */
static EVP_PKEY *gen_kem(OSSL_LIB_CTX *ctx, const char *name)
{
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(ctx, name, "provider=hybrid");
    EVP_PKEY *k = NULL;

    if (c != NULL && EVP_PKEY_keygen_init(c) > 0)
        EVP_PKEY_keygen(c, &k);
    EVP_PKEY_CTX_free(c);
    return k;
}

/*
 * Issue a recipient cert carrying the KEM public key (via its SPKI encoder) and
 * signed by a separate default-provider Ed25519 issuer — a KEM key cannot sign its
 * own trust anchor. Generic over the KEM: used both for the composite recipients
 * under test and for the native ML-KEM key in the capability probe. The issuer key
 * is not returned; the cert is self-named for a minimal standalone recipient.
 *
 * The finished cert is round-tripped through DER (i2d, then d2i into an X509
 * preallocated via X509_new_ex(ctx)) so the recipient public key the caller gets
 * is reconstructed from its
 * SubjectPublicKeyInfo via OpenSSL's generic, OID-driven decode — exactly as
 * `openssl cms -encrypt -recip <cert-file>` loads a recipient from a file, NOT from
 * the live in-process key. For the composite and experimental hybrid rows alike,
 * this proves the keytype resolves from the SPKI OID (the hybrid KEMs rely on the
 * provider's OID<->name registration for it); the native ML-KEM probe rides the
 * same path.
 */
static int make_kem_cert(OSSL_LIB_CTX *ctx, EVP_PKEY *kem, X509 **cert_out)
{
    EVP_PKEY *ca = EVP_PKEY_Q_keygen(ctx, "provider=default", "ED25519");
    X509 *cert = NULL, *rt = NULL;
    X509_NAME *name = X509_NAME_new();
    unsigned char *der = NULL;
    const unsigned char *p;
    int derlen, ok = 0;

    if (ca == NULL || name == NULL)
        goto end;                                   /* no Ed25519: give up */
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (unsigned char *)"hybrid-cms-kem", -1, -1, 0))
        goto end;
    if ((cert = X509_new_ex(ctx, NULL)) == NULL
            || !X509_set_version(cert, X509_VERSION_3)
            || !ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
            || X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL
            || X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L) == NULL
            || !X509_set_pubkey(cert, kem)          /* drives the KEM SPKI encoder */
            || !X509_set_subject_name(cert, name)
            || !X509_set_issuer_name(cert, name)
            || X509_sign(cert, ca, NULL) == 0)      /* Ed25519: one-shot, md NULL */
        goto end;
    /* File-based recipient: re-decode so the pubkey comes from the SPKI OID.
     * d2i into an X509 preallocated via X509_new_ex(ctx) keeps the decode (and the
     * cert's lazy pubkey resolution) bound to ctx, so the hybrid provider is in
     * scope — exactly as loading the cert from a file would be.
     *
     * Ownership/cleanup: `rt` is freed exactly once. On success it is handed to
     * *cert_out and cleared, so the X509_free(rt) at `end:` is a no-op. On a d2i
     * decode failure d2i_X509() frees the reused object AND sets rt = NULL itself
     * (ASN1_item_ex_free), so again the cleanup free is a no-op — never a
     * double-free, and `cert` (the pre-encode original) is the separately-owned
     * object freed alongside it. */
    if ((derlen = i2d_X509(cert, &der)) <= 0)
        goto end;
    p = der;
    if ((rt = X509_new_ex(ctx, NULL)) == NULL
            || d2i_X509(&rt, &p, derlen) == NULL)
        goto end;
    *cert_out = rt; rt = NULL;
    ok = 1;
end:
    OPENSSL_free(der);
    X509_free(rt);
    EVP_PKEY_free(ca);
    X509_NAME_free(name);
    X509_free(cert);
    return ok;
}

/* DER-encode a CMS structure into a fresh buffer. */
static int cms_to_der(CMS_ContentInfo *cms, unsigned char **der, long *derlen)
{
    BIO *b = BIO_new(BIO_s_mem());
    const unsigned char *p;
    long n;
    int ok = 0;

    if (b != NULL && i2d_CMS_bio(b, cms) > 0) {
        n = BIO_get_mem_data(b, &p);
        if (n > 0 && (*der = OPENSSL_memdup(p, n)) != NULL) {
            *derlen = n;
            ok = 1;
        }
    }
    BIO_free(b);
    return ok;
}

/*
 * Decode CMS DER into a ContentInfo bound to libctx. KEMRI decryption resolves
 * the KEM algorithm BY NAME from the ContentInfo's own library context, so a
 * libctx-less d2i (global default context) could not find the hybrid provider.
 */
static CMS_ContentInfo *cms_from_der(OSSL_LIB_CTX *ctx,
                                     const unsigned char *der, long derlen)
{
    CMS_ContentInfo *cms = CMS_ContentInfo_new_ex(ctx, NULL);
    const unsigned char *p = der;

    if (cms == NULL)
        return NULL;
    if (d2i_CMS_ContentInfo(&cms, &p, derlen) == NULL) {
        CMS_ContentInfo_free(cms);
        return NULL;
    }
    return cms;
}

/* Decrypt the DER-encoded CMS with (pkey, cert); return 1 and recovered content
 * on success. */
static int cms_decrypt_der(OSSL_LIB_CTX *ctx, const unsigned char *der,
                           long derlen, EVP_PKEY *pkey, X509 *cert,
                           unsigned char **out, long *outlen)
{
    CMS_ContentInfo *cms = cms_from_der(ctx, der, derlen);
    BIO *mem = BIO_new(BIO_s_mem());
    const unsigned char *p;
    long n;
    int ok = 0;

    if (cms != NULL && mem != NULL
            && CMS_decrypt(cms, pkey, cert, NULL, mem, CMS_BINARY) > 0) {
        n = BIO_get_mem_data(mem, &p);
        if (out != NULL) {
            if (n >= 0 && (*out = OPENSSL_memdup(p, n > 0 ? n : 1)) != NULL) {
                *outlen = n;
                ok = 1;
            }
        } else {
            ok = 1;
        }
    }
    ERR_clear_error();
    BIO_free(mem);
    CMS_ContentInfo_free(cms);
    return ok;
}

/*
 * Can this OpenSSL drive a KEM recipient through CMS at all? RFC 9629 KEMRI is
 * provider-generic, but the CMS layer must auto-select CMS_RECIPINFO_KEM for a
 * KEM key. OpenSSL 3.5 cannot: ossl_cms_pkey_get_ri_type() there only knows
 * RSA/EC/DH by name and defaults everything else to key transport. KEMRI and the
 * EVP_PKEY_encapsulate_init() auto-probe that selects it arrived in 3.6.0 (the
 * OSSL_PKEY_PARAM_CMS_RI_TYPE provider hint came later in 4.0, and is not what we
 * rely on). So probe the capability at runtime with native ML-KEM-768 (always
 * present with the default provider on 3.5+) rather than hard-coding a version:
 * if a KEMRI EnvelopedData round-trip succeeds for native ML-KEM, our composite
 * KEM rides the same path.
 */
static int cms_kemri_supported(OSSL_LIB_CTX *ctx)
{
    EVP_PKEY *kem = EVP_PKEY_Q_keygen(ctx, "provider=default", "ML-KEM-768");
    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL;
    STACK_OF(X509) *certs = NULL;
    unsigned char *der = NULL;
    long derlen = 0;
    const unsigned char probe[] = "kemri-probe";
    int ok = 0;

    if (kem == NULL || !make_kem_cert(ctx, kem, &cert))
        goto end;                                   /* no ML-KEM: unsupported */
    certs = sk_X509_new_null();
    in = BIO_new_mem_buf(probe, sizeof(probe) - 1);
    if (certs == NULL || in == NULL || !sk_X509_push(certs, cert))
        goto end;
    cms = CMS_encrypt_ex(certs, in, EVP_aes_256_cbc(), CMS_BINARY, ctx, NULL);
    if (cms != NULL && cms_to_der(cms, &der, &derlen))
        ok = cms_decrypt_der(ctx, der, derlen, kem, cert, NULL, NULL);
end:
    ERR_clear_error();
    OPENSSL_free(der);
    BIO_free(in);
    sk_X509_free(certs);
    CMS_ContentInfo_free(cms);
    X509_free(cert);
    EVP_PKEY_free(kem);
    return ok;
}

/* Generic over any provider KEM with a cert-representable public key: `name` is
 * the registered algorithm, `pq_alg` the PQ component to probe for availability
 * (ML-KEM for a standardized composite, Frodo/BIKE/HQC for an experimental
 * composite, or the alg2 PQ KEM for a hybrid row). */
static void check(OSSL_LIB_CTX *ctx, const char *name, const char *pq_alg,
                  int kemri_supported)
{
    EVP_PKEY *kem = NULL, *kem_wrong = NULL;
    X509 *cert = NULL;
    CMS_ContentInfo *cms = NULL;
    BIO *in = NULL;
    STACK_OF(X509) *certs = NULL;
    unsigned char *der = NULL, *recovered = NULL;
    long derlen = 0, reclen = 0;
    const unsigned char content[] = "composite KEM CMS EnvelopedData payload";

    tests++;
    printf("  %-22s CMS EnvelopedData encrypt/decrypt ... ", name);
    fflush(stdout);

    if (!kemri_supported) {
        printf("SKIP (CMS KEMRI not driveable by this OpenSSL; needs 3.6.0+)\n");
        skipped++; tests--;
        return;
    }
    if (!have_alg(ctx, pq_alg)) {
        printf("SKIP (%s unavailable)\n", pq_alg);
        skipped++; tests--;
        return;
    }
    if ((kem = gen_kem(ctx, name)) == NULL
            || !make_kem_cert(ctx, kem, &cert)) {
        printf("SKIP (keygen/cert failed)\n");
        skipped++; tests--; ERR_clear_error();
        goto done;
    }

    /* Encrypt: CMS_encrypt auto-selects KEMRI for the KEM recipient.
     * AES-256-CBC content cipher -> EnvelopedData (the CEK is key-wrapped under
     * the KEM-derived KEK; OpenSSL defaults the KDF to HKDF-SHA256 + AES-wrap). */
    certs = sk_X509_new_null();
    in = BIO_new_mem_buf(content, sizeof(content) - 1);
    if (certs == NULL || in == NULL || !sk_X509_push(certs, cert))
        goto fail;
    cms = CMS_encrypt_ex(certs, in, EVP_aes_256_cbc(), CMS_BINARY, ctx, NULL);
    if (cms == NULL || !cms_to_der(cms, &der, &derlen))
        goto fail;

    /* Decrypt with the recipient key -> must recover the exact plaintext. */
    if (!cms_decrypt_der(ctx, der, derlen, kem, cert, &recovered, &reclen)
            || reclen != (long)(sizeof(content) - 1)
            || memcmp(recovered, content, reclen) != 0)
        goto fail;

    /* Negative: a different key of the same type, same cert identity. The
     * recipient matches by issuer/serial, decapsulation yields a different KEK,
     * and the AES key-unwrap integrity check rejects it -> decrypt must fail. */
    if ((kem_wrong = gen_kem(ctx, name)) == NULL)
        goto fail;
    if (cms_decrypt_der(ctx, der, derlen, kem_wrong, cert, NULL, NULL)) {
        printf("FAIL (decrypt succeeded with wrong key)\n");
        failed++;
        goto done;
    }

    printf("PASS\n");
    passed++;
    goto done;
fail:
    printf("FAIL\n");
    ERR_print_errors_fp(stdout);
    failed++;
done:
    OPENSSL_free(der);
    OPENSSL_free(recovered);
    BIO_free(in);
    sk_X509_free(certs);
    CMS_ContentInfo_free(cms);
    EVP_PKEY_free(kem);
    EVP_PKEY_free(kem_wrong);
    X509_free(cert);
}

int main(void)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    const char *mods = getenv("OPENSSL_MODULES");
    int kemri_supported;
    size_t i;

    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if (OSSL_PROVIDER_load(ctx, "default") == NULL
            || OSSL_PROVIDER_load(ctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers\n");
        OSSL_LIB_CTX_free(ctx);
        return 1;
    }
    /* Optional: both experimental tiers below take their PQ half (Frodo/BIKE/HQC)
     * from oqsprovider — the composite experimental combos and the experimental
     * hybrid-family rows alike; absent it, those rows self-skip. */
    (void)OSSL_PROVIDER_load(ctx, "oqsprovider");
    ERR_clear_error();

    kemri_supported = cms_kemri_supported(ctx);

    printf("composite KEM in CMS EnvelopedData (KEMRI, RFC 9629)\n");
    printf("====================================================\n");
    printf("  CMS KEMRI driveable by this OpenSSL (needs 3.6.0+): %s\n",
           kemri_supported ? "yes" : "no");
    /* Both tiers: standardized ML-KEM combos (draft-18 OIDs .55..66, PQ from the
     * default provider on 3.5+) and experimental Frodo/BIKE/HQC combos (private
     * OID arc, PQ from oqsprovider) — the same SPKI+KEMRI path over different PQ. */
    for (i = 0; i < COMPOSITE_KEM_ALG_COUNT; i++)
        check(ctx, composite_kem_table[i].name,
              composite_kem_table[i].pq_alg, kemri_supported);

    /* Experiment: a *hybrid*-family KEM (concatenation, NOT a LAMPS composite)
     * can equally be a CMS KEMRI recipient — the limit was never the KEM, only a
     * cert-representable key. Exercise every hybrid row that carries an X.509 key
     * OID but no TLS group (oid != NULL && tls_codepoint == 0): the experimental
     * private-arc rows meant as standalone-key hybrids. These self-skip unless the
     * build enabled HYBRID_KEM_ENCODERS (else X509_set_pubkey has no SPKI encoder
     * -> keygen/cert step fails -> SKIP) and oqsprovider supplies the PQ half.
     *
     * The recipient cert is file-based: make_kem_cert() round-trips it through DER
     * so the recipient pubkey is rebuilt from its SubjectPublicKeyInfo via the
     * generic OID-driven decode — the same path `openssl cms -encrypt -recip
     * <hybrid-cert-file>` uses. That resolves the hybrid keytype from the SPKI OID
     * because the provider registers the hybrid KEM OID<->name mapping
     * (hybrid_prov.c); the standalone SPKI/PKCS8 decode itself is covered directly
     * by hybrid_kem_encode_test's hybrid->hybrid self round-trip. */
    printf("  -- experimental hybrid-family KEMs (HYBRID_KEM_ENCODERS) --\n");
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++)
        if (hybrid_kem_table[i].oid != NULL
                && hybrid_kem_table[i].tls_codepoint == 0)
            check(ctx, hybrid_kem_table[i].hybrid_name,
                  hybrid_kem_table[i].alg2_name, kemri_supported);

    printf("\nResults: %d/%d passed, %d failed, %d skipped\n",
           passed, tests, failed, skipped);
    OSSL_LIB_CTX_free(ctx);
    return failed == 0 ? 0 : 1;
}
