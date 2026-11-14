/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests the provider's config-driven component property queries
 * (alg1-propquery / alg2-propquery): they must independently steer which
 * provider supplies the PQ and classic sub-algorithms. Also tests that a
 * component-providers entry that cannot load fails the hybrid provider's init
 * cleanly (no crash, no use-after-free under ASan) and names the culprit.
 *
 * The probe relies on the fact that the hybrid provider itself implements
 * neither ML-KEM nor X25519: forcing a component to "provider=hybrid" via
 * config must make exactly that component's keygen fail, while the other
 * component is unaffected.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>

static int test_count, pass_count, fail_count;

#define TEST_START(n) do { test_count++; \
    printf("  TEST %d: %s ... ", test_count, n); fflush(stdout); } while (0)
#define TEST_PASS()  do { pass_count++; printf("PASS\n"); } while (0)
#define TEST_FAIL(m) do { fail_count++; printf("FAIL: %s\n", m); } while (0)

static const char *module_dir;

/* No provider module by this name exists anywhere on the search path. */
#define BOGUS_PROVIDER "no-such-component-provider"

/* Directory for temporary files: $TMPDIR if set, else the platform default
 * (POSIX P_tmpdir). */
static const char *tmp_dir(void)
{
    const char *d = getenv("TMPDIR");

    if (d != NULL && *d != '\0')
        return d;
#ifdef P_tmpdir
    return P_tmpdir;
#else
    return "/tmp";
#endif
}

/*
 * Create a unique temporary openssl.cnf loading default + hybrid, with optional
 * extra hybrid-section lines (e.g. the propquery keys). With activate == 0 the
 * hybrid section is only registered, for a later explicit OSSL_PROVIDER_load().
 * Its path goes to path[pathsz]; the caller removes the file. Returns 1 on
 * success (no file is left behind on failure).
 */
static int make_cnf(char *path, size_t pathsz, const char *hybrid_extra,
                    int activate)
{
    int n = snprintf(path, pathsz, "%s/hybrid_cfg_test.XXXXXX", tmp_dir());
    int fd;
    FILE *f;

    if (n < 0 || (size_t)n >= pathsz || (fd = mkstemp(path)) < 0)
        return 0;
    if ((f = fdopen(fd, "w")) == NULL) {
        close(fd);
        remove(path);
        return 0;
    }
    fprintf(f,
            "openssl_conf = c\n"
            "[c]\nproviders = p\n"
            "[p]\ndefault = d\nhybrid = h\n"
            "[d]\nactivate = 1\n"
            "[h]\nmodule = %s/hybrid.so\n%s%s",
            module_dir, activate ? "activate = 1\n" : "",
            hybrid_extra ? hybrid_extra : "");
    if (fclose(f) != 0) {
        remove(path);
        return 0;
    }
    return 1;
}

/*
 * Register the hybrid provider from a cnf without activating it, then load it
 * explicitly. (A cnf "activate = 1" failure is dropped by OpenSSL without an
 * error, even with config_diagnostics; an explicit load reports init errors.)
 * Returns 1 if the load failed AND an error's data contains `needle`.
 */
static int load_fails_naming(const char *hybrid_extra, const char *needle)
{
    char cnf[4096];
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *prov = NULL;
    const char *data;
    int flags, named = 0;

    if (!make_cnf(cnf, sizeof(cnf), hybrid_extra, 0))
        return 0;
    if ((libctx = OSSL_LIB_CTX_new()) != NULL
            && OSSL_LIB_CTX_load_config(libctx, cnf)) {
        prov = OSSL_PROVIDER_load(libctx, "hybrid");
        while (ERR_get_error_all(NULL, NULL, NULL, &data, &flags) != 0)
            if ((flags & ERR_TXT_STRING) != 0 && strstr(data, needle) != NULL)
                named = 1;
    }
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    remove(cnf);
    return prov == NULL && named;
}

/* Load cnf into a fresh libctx; return 1 if the hybrid provider activated.
 * (A keygen probe cannot tell: "?provider=hybrid" falls back to default.) */
static int hybrid_active(const char *hybrid_extra)
{
    char cnf[4096];
    OSSL_LIB_CTX *libctx = NULL;
    int ok = 0;

    if (!make_cnf(cnf, sizeof(cnf), hybrid_extra, 1))
        return -1;
    if ((libctx = OSSL_LIB_CTX_new()) != NULL
            && OSSL_LIB_CTX_load_config(libctx, cnf))
        ok = OSSL_PROVIDER_available(libctx, "hybrid");
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    remove(cnf);
    return ok;
}

/* Load cnf into a fresh libctx and try to keygen the hybrid; return 1 if ok. */
static int keygen_ok(const char *hybrid_extra)
{
    char cnf[4096];
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    if (!make_cnf(cnf, sizeof(cnf), hybrid_extra, 1))
        return -1;
    if ((libctx = OSSL_LIB_CTX_new()) == NULL
            || !OSSL_LIB_CTX_load_config(libctx, cnf))
        goto end;
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "X25519MLKEM768",
                                     "?provider=hybrid");
    if (ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0)
        ok = (EVP_PKEY_keygen(ctx, &pkey) > 0);
end:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_LIB_CTX_free(libctx);
    ERR_clear_error();
    remove(cnf);
    return ok;
}

int main(void)
{
    module_dir = getenv("OPENSSL_MODULES");
    if (module_dir == NULL)
        module_dir = ".";

    printf("hybrid-provider config-driven component selection tests\n");
    printf("=======================================================\n");

    /* Baseline: no config keys -> components fall back to default. */
    TEST_START("no propquery keys -> keygen succeeds");
    if (keygen_ok("") == 1) TEST_PASS();
    else TEST_FAIL("baseline keygen should succeed");

    /* Both components explicitly from default via config. */
    TEST_START("pq+classic = provider=default -> keygen succeeds");
    if (keygen_ok("alg2-propquery = provider=default\n"
                  "alg1-propquery = provider=default\n") == 1) TEST_PASS();
    else TEST_FAIL("explicit default routing should succeed");

    /* Force only the PQ component to the hybrid provider (which has no
     * ML-KEM): keygen must fail -- proves alg2-propquery is applied. */
    TEST_START("pq = provider=hybrid (no ML-KEM there) -> keygen fails");
    if (keygen_ok("alg2-propquery = provider=hybrid\n") == 0) TEST_PASS();
    else TEST_FAIL("alg2-propquery was not applied to the PQ component");

    /* Force only the classic component to hybrid (no X25519 there): keygen
     * must fail independently -- proves alg1-propquery is applied. */
    TEST_START("classic = provider=hybrid (no X25519 there) -> keygen fails");
    if (keygen_ok("alg1-propquery = provider=hybrid\n") == 0) TEST_PASS();
    else TEST_FAIL("alg1-propquery was not applied to the classic component");

    /* Private component context loads and activates. (Not a lone "default":
     * OpenSSL's provider-config parser treats a value naming a section as a
     * section reference, and "default" is the cnf's implicit top section.) */
    TEST_START("component-providers = default, -> hybrid active");
    if (hybrid_active("component-providers = default,\n") == 1)
        TEST_PASS();
    else TEST_FAIL("private component context with default should activate");

    /* An unloadable component provider AFTER one that loaded: init must fail
     * cleanly. Regression: the error path freed the private context but kept
     * the loaded handle, which teardown then unloaded again after the context
     * was gone (segfault at exit in the field; leak report under ASan, where
     * the explicit-load test below then fails). */
    TEST_START("component-providers = default <bogus> -> hybrid unavailable");
    if (hybrid_active("component-providers = default " BOGUS_PROVIDER "\n") == 0)
        TEST_PASS();
    else TEST_FAIL("hybrid must not activate with an unloadable component");

    TEST_START("component-providers = <bogus> (first) -> hybrid unavailable");
    if (hybrid_active("component-providers = " BOGUS_PROVIDER " default\n") == 0)
        TEST_PASS();
    else TEST_FAIL("hybrid must not activate with an unloadable component");

    /* The failure must be diagnosable: the error names the provider. */
    TEST_START("unloadable component provider is named in the error");
    if (load_fails_naming("component-providers = default " BOGUS_PROVIDER "\n",
                          BOGUS_PROVIDER))
        TEST_PASS();
    else TEST_FAIL("explicit load should fail with an error naming the provider");

    printf("\n=======================================================\n");
    printf("Results: %d/%d passed", pass_count, test_count);
    if (fail_count) printf(" (%d FAILED)", fail_count);
    printf("\n");
    return fail_count == 0 ? 0 : 1;
}
