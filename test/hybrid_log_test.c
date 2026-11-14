/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * hybrid_log() diagnostics test (issue #45).
 *
 * The provider drops a hybrid it cannot operate — a TLS group/sigalg whose
 * components are not both fetchable in the current libctx — and, when
 * HYBRID_LOG is set, logs one line per drop to stderr. This test loads the
 * hybrid provider into a default-only context (no oqsprovider), so every
 * Frodo/BIKE/HQC group is inoperable and must be dropped, then enumerates the
 * TLS-GROUP capabilities while capturing stderr:
 *   - with HYBRID_LOG=1, the drop for an oqsprovider-only group is logged;
 *   - with HYBRID_LOG unset, nothing is logged.
 * Cede-to-default is off here (set by CMake), so inoperability is the only
 * reason a non-zero-code-point group is dropped.
 *
 * It also covers the "ops" category: one line per keygen / encapsulate /
 * decapsulate / sign / verify naming the provider that actually served each
 * component, and no such line when another provider serves the algorithm.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "../hybrid_prov.h"

#define CAP_FILE "hybrid_log_test.captured"
#define DROP_MARKER "not advertising TLS group"
#define FRODO_GROUP "p256_frodo640aes"

static int noop_cb(const OSSL_PARAM params[], void *arg)
{
    (void)params;
    (void)arg;
    return 1;   /* we only care about the side-channel log, not the params */
}

/*
 * Enumerate the hybrid provider's TLS-GROUP capabilities in a default-only
 * libctx while capturing everything written to stderr into `out` (size cap).
 * Returns the number of captured bytes, or -1 on setup failure.
 */
static long enumerate_capturing_stderr(const char *mods, char *out, size_t outsz)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dflt = NULL, *hyb = NULL;
    int saved = -1, tmpfd = -1;
    long n = -1;

    if (ctx == NULL)
        goto done;
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if ((dflt = OSSL_PROVIDER_load(ctx, "default")) == NULL
            || (hyb = OSSL_PROVIDER_load(ctx, "hybrid")) == NULL)
        goto done;

    /* Redirect the underlying stderr fd to a temp file, leaving the stderr
     * FILE* (which hybrid_log writes through) untouched, then restore it. */
    fflush(stderr);
    saved = dup(fileno(stderr));
    tmpfd = open(CAP_FILE, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (saved < 0 || tmpfd < 0)
        goto done;
    dup2(tmpfd, fileno(stderr));

    OSSL_PROVIDER_get_capabilities(hyb, "TLS-GROUP", noop_cb, NULL);

    fflush(stderr);
    lseek(tmpfd, 0, SEEK_SET);
    n = (long)read(tmpfd, out, outsz - 1);
    if (n < 0)
        n = 0;
    out[n] = '\0';

done:
    if (saved >= 0) {
        dup2(saved, fileno(stderr));
        close(saved);
    }
    if (tmpfd >= 0)
        close(tmpfd);
    ERR_clear_error();
    OSSL_PROVIDER_unload(hyb);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(ctx);
    return n;
}

/* Run fn(ctx) with stderr captured into out (NUL-terminated). Returns the
 * number of captured bytes, or -1 on setup failure. */
static long capture(int (*fn)(OSSL_LIB_CTX *, const char *), OSSL_LIB_CTX *ctx,
                    const char *alg, char *out, size_t outsz)
{
    int saved, tmpfd;
    long n;

    fflush(stderr);
    saved = dup(fileno(stderr));
    tmpfd = open(CAP_FILE, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (saved < 0 || tmpfd < 0) {
        if (saved >= 0)
            close(saved);
        if (tmpfd >= 0)
            close(tmpfd);
        return -1;
    }
    dup2(tmpfd, fileno(stderr));
    (void)fn(ctx, alg);
    fflush(stderr);
    lseek(tmpfd, 0, SEEK_SET);
    n = (long)read(tmpfd, out, outsz - 1);
    if (n < 0)
        n = 0;
    out[n] = '\0';
    dup2(saved, fileno(stderr));
    close(saved);
    close(tmpfd);
    ERR_clear_error();
    return n;
}

/* keygen + encapsulate + decapsulate of KEM `alg`, fetched as `propq`. */
static int kem_roundtrip(OSSL_LIB_CTX *ctx, const char *alg, const char *propq)
{
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_from_name(ctx, alg, propq), *ec = NULL;
    EVP_PKEY *pk = NULL;
    unsigned char ct[16384], ss[256], ss2[256];
    size_t ctl = sizeof(ct), ssl = sizeof(ss), ssl2 = sizeof(ss2);
    int ok = 0;

    if (kc == NULL || EVP_PKEY_keygen_init(kc) <= 0
            || EVP_PKEY_keygen(kc, &pk) <= 0)
        goto end;
    if ((ec = EVP_PKEY_CTX_new_from_pkey(ctx, pk, NULL)) == NULL
            || EVP_PKEY_encapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_encapsulate(ec, ct, &ctl, ss, &ssl) <= 0
            || EVP_PKEY_decapsulate_init(ec, NULL) <= 0
            || EVP_PKEY_decapsulate(ec, ss2, &ssl2, ct, ctl) <= 0)
        goto end;
    ok = (ssl == ssl2 && memcmp(ss, ss2, ssl) == 0);
end:
    OPENSSL_cleanse(ss, sizeof(ss));
    OPENSSL_cleanse(ss2, sizeof(ss2));
    EVP_PKEY_CTX_free(ec);
    EVP_PKEY_CTX_free(kc);
    EVP_PKEY_free(pk);
    return ok;
}

static int kem_hybrid(OSSL_LIB_CTX *c, const char *a)
{
    return kem_roundtrip(c, a, "provider=hybrid");
}

static int kem_default(OSSL_LIB_CTX *c, const char *a)
{
    return kem_roundtrip(c, a, "provider=default");
}

/* keygen + sign + verify of signature `alg` from the hybrid provider. */
static int sig_hybrid(OSSL_LIB_CTX *ctx, const char *alg)
{
    static const unsigned char msg[] = "hybrid_log_test";
    EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_from_name(ctx, alg, "provider=hybrid");
    EVP_PKEY *pk = NULL;
    EVP_MD_CTX *mc = EVP_MD_CTX_new();
    unsigned char sig[65536];
    size_t sl = sizeof(sig);
    int ok = 0;

    if (kc == NULL || mc == NULL || EVP_PKEY_keygen_init(kc) <= 0
            || EVP_PKEY_keygen(kc, &pk) <= 0
            || EVP_DigestSignInit_ex(mc, NULL, NULL, ctx, NULL, pk, NULL) <= 0
            || EVP_DigestSign(mc, sig, &sl, msg, sizeof(msg)) <= 0)
        goto end;
    EVP_MD_CTX_free(mc);
    if ((mc = EVP_MD_CTX_new()) == NULL
            || EVP_DigestVerifyInit_ex(mc, NULL, NULL, ctx, NULL, pk, NULL) <= 0
            || EVP_DigestVerify(mc, sig, sl, msg, sizeof(msg)) <= 0)
        goto end;
    ok = 1;
end:
    EVP_MD_CTX_free(mc);
    EVP_PKEY_CTX_free(kc);
    EVP_PKEY_free(pk);
    return ok;
}

/* Expected "hybrid: <op> <alg>: <comp>[:<group>]@<prov> ..." for a table row
 * whose components all come from `prov` (format owned by hybrid_log_op). */
static void expect_line(char *out, size_t outsz, const char *op, const char *alg,
                        const char *const names[], const char *const groups[],
                        unsigned n, const char *prov)
{
    size_t off = (size_t)snprintf(out, outsz, "hybrid: %s %s: ", op, alg);
    unsigned i;

    for (i = 0; i < n && off < outsz; i++)
        off += (size_t)snprintf(out + off, outsz - off, "%s%s%s%s@%s",
                                i > 0 ? " " : "", names[i],
                                groups[i] != NULL ? ":" : "",
                                groups[i] != NULL ? groups[i] : "", prov);
}

static int report(int *tests, int *passed, int *failed, const char *what, int ok)
{
    (*tests)++;
    printf("  %s ... %s\n", what, ok ? "PASS" : "FAIL");
    if (ok)
        (*passed)++;
    else
        (*failed)++;
    return ok;
}

/* The per-operation ("ops") category, in a default + hybrid context. */
static void ops_tests(const char *mods, int *tests, int *passed, int *failed)
{
    OSSL_LIB_CTX *ctx = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *dflt = NULL, *hyb = NULL;
    char buf[65536], want[512];
    const char *kem = NULL, *native = NULL, *sig = NULL,
               *names[HYBRID_MAX_COMP], *groups[HYBRID_MAX_COMP];
    const HYBRID_KEM_INFO *ki = NULL;
    const HYBRID_SIG_INFO *si = NULL;
    size_t i;
    unsigned c;

    if (ctx == NULL)
        return;
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(ctx, mods);
    if ((dflt = OSSL_PROVIDER_load(ctx, "default")) == NULL
            || (hyb = OSSL_PROVIDER_load(ctx, "hybrid")) == NULL)
        goto end;

    /* Pick rows from the tables, so this adapts to the OpenSSL version:
     *   kem     operable here from default components, and NOT also served
     *           natively by the default provider. A name both providers serve
     *           may have its key generated by one and its encapsulation run
     *           by the other (OpenSSL exports the key to whichever KEM it
     *           fetches), so only a hybrid-only name has all three lines.
     *   native  served natively by the default provider, for the negative. */
    unsetenv(HYBRID_ENV_LOG);
    for (i = 0; i < HYBRID_KEM_ALG_COUNT; i++) {
        const char *n = hybrid_kem_table[i].hybrid_name;

        if (kem_default(ctx, n)) {
            if (native == NULL)
                native = n;
        } else if (kem == NULL && kem_hybrid(ctx, n)) {
            ki = &hybrid_kem_table[i];
            kem = n;
        }
    }
    for (i = 0; i < HYBRID_SIG_ALG_COUNT && sig == NULL; i++)
        if (sig_hybrid(ctx, hybrid_sig_table[i].hybrid_name)) {
            si = &hybrid_sig_table[i];
            sig = si->hybrid_name;
        }
    ERR_clear_error();

    if (kem == NULL) {
        printf("  ops: no hybrid KEM operable from default here ... SKIP\n");
    } else {
        static const char *const kops[] = { "keygen", "encapsulate", "decapsulate" };

        for (c = 0; c < ki->n_comp; c++) {
            names[c] = ki->component[c].name;
            groups[c] = ki->component[c].group;
        }
        setenv(HYBRID_ENV_LOG, "ops", 1);
        capture(kem_hybrid, ctx, kem, buf, sizeof(buf));
        for (i = 0; i < sizeof(kops) / sizeof(kops[0]); i++) {
            char what[160];

            expect_line(want, sizeof(want), kops[i], kem, names, groups,
                        ki->n_comp, "default");
            snprintf(what, sizeof(what), "HYBRID_LOG=ops: %s %s line names each "
                     "component's provider", kops[i], kem);
            if (!report(tests, passed, failed, what, strstr(buf, want) != NULL))
                printf("    want \"%s\"\n    got  \"%s\"\n", want, buf);
        }

        /* Provenance: a KEM run entirely by the default provider leaves no
         * hybrid line, even though the hybrid provider is loaded. */
        if (native != NULL) {
            char what[160];

            capture(kem_default, ctx, native, buf, sizeof(buf));
            snprintf(what, sizeof(what), "HYBRID_LOG=ops: no hybrid line when "
                     "default serves %s", native);
            report(tests, passed, failed, what, strstr(buf, "hybrid: ") == NULL);
        }

        setenv(HYBRID_ENV_LOG, "caps", 1);
        capture(kem_hybrid, ctx, kem, buf, sizeof(buf));
        report(tests, passed, failed, "HYBRID_LOG=caps: no operation lines",
               strstr(buf, "hybrid: keygen") == NULL);

        setenv(HYBRID_ENV_LOG, "0", 1);
        capture(kem_hybrid, ctx, kem, buf, sizeof(buf));
        report(tests, passed, failed, "HYBRID_LOG=0: silent", buf[0] == '\0');
    }

    if (sig == NULL) {
        printf("  ops: no hybrid signature operable from default here ... SKIP\n");
    } else {
        static const char *const sops[] = { "keygen", "sign", "verify" };

        names[0] = si->alg1_name;  groups[0] = si->alg1_group;
        names[1] = si->alg2_name;  groups[1] = si->alg2_group;
        setenv(HYBRID_ENV_LOG, "ops", 1);
        capture(sig_hybrid, ctx, sig, buf, sizeof(buf));
        for (i = 0; i < sizeof(sops) / sizeof(sops[0]); i++) {
            char what[160];

            expect_line(want, sizeof(want), sops[i], sig, names, groups, 2,
                        "default");
            snprintf(what, sizeof(what), "HYBRID_LOG=ops: %s %s line names each "
                     "component's provider", sops[i], sig);
            if (!report(tests, passed, failed, what, strstr(buf, want) != NULL))
                printf("    want \"%s\"\n    got  \"%s\"\n", want, buf);
        }
    }
end:
    unsetenv(HYBRID_ENV_LOG);
    ERR_clear_error();
    OSSL_PROVIDER_unload(hyb);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(ctx);
}

int main(void)
{
    const char *mods = getenv("OPENSSL_MODULES");
    char buf[65536];
    int tests = 0, passed = 0, failed = 0;
    long n;

    printf("hybrid_log() diagnostics (issue #45)\n");
    printf("====================================\n");

    /* 1. With HYBRID_LOG=1: the Frodo group drop must be logged. */
    setenv("HYBRID_LOG", "1", 1);
    n = enumerate_capturing_stderr(mods, buf, sizeof(buf));
    if (n < 0) {
        fprintf(stderr, "setup failed (cannot load providers / capture stderr)\n");
        return 1;
    }
    tests++;
    if (strstr(buf, DROP_MARKER) != NULL && strstr(buf, FRODO_GROUP) != NULL) {
        printf("  HYBRID_LOG=1 logs the inoperable-group drop ... PASS\n");
        passed++;
    } else {
        printf("  HYBRID_LOG=1 logs the inoperable-group drop ... FAIL\n");
        printf("    (captured %ld bytes, marker/group not found)\n", n);
        failed++;
    }

    /* 2. With HYBRID_LOG unset: nothing is logged. */
    unsetenv("HYBRID_LOG");
    n = enumerate_capturing_stderr(mods, buf, sizeof(buf));
    tests++;
    if (n >= 0 && strstr(buf, DROP_MARKER) == NULL) {
        printf("  HYBRID_LOG unset is silent ... PASS\n");
        passed++;
    } else {
        printf("  HYBRID_LOG unset is silent ... FAIL\n");
        failed++;
    }

    ops_tests(mods, &tests, &passed, &failed);

    remove(CAP_FILE);
    printf("\nResults: %d/%d passed", passed, tests);
    if (failed > 0)
        printf(" (%d FAILED)", failed);
    printf("\n");
    return failed == 0 ? 0 : 1;
}
