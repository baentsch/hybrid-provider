/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Tests the provider's config-driven component property queries
 * (pq-propquery / classic-propquery): they must independently steer which
 * provider supplies the PQ and classic sub-algorithms.
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

static int test_count, pass_count, fail_count;

#define TEST_START(n) do { test_count++; \
    printf("  TEST %d: %s ... ", test_count, n); fflush(stdout); } while (0)
#define TEST_PASS()  do { pass_count++; printf("PASS\n"); } while (0)
#define TEST_FAIL(m) do { fail_count++; printf("FAIL: %s\n", m); } while (0)

static const char *module_dir;

/* Write an openssl.cnf loading default + hybrid, with optional extra hybrid
 * section lines (e.g. the propquery keys). Returns 1 on success. */
static int write_cnf(const char *path, const char *hybrid_extra)
{
    FILE *f = fopen(path, "w");

    if (f == NULL)
        return 0;
    fprintf(f,
            "openssl_conf = c\n"
            "[c]\nproviders = p\n"
            "[p]\ndefault = d\nhybrid = h\n"
            "[d]\nactivate = 1\n"
            "[h]\nmodule = %s/hybrid.so\nactivate = 1\n%s",
            module_dir, hybrid_extra ? hybrid_extra : "");
    fclose(f);
    return 1;
}

/* Load cnf into a fresh libctx and try to keygen the hybrid; return 1 if ok. */
static int keygen_ok(const char *hybrid_extra)
{
    char cnf[] = "/tmp/hybrid_cfg_test.XXXXXX";
    int fd = mkstemp(cnf);
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    if (fd < 0)
        return -1;
    close(fd);
    if (!write_cnf(cnf, hybrid_extra))
        goto end;
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
    if (keygen_ok("pq-propquery = provider=default\n"
                  "classic-propquery = provider=default\n") == 1) TEST_PASS();
    else TEST_FAIL("explicit default routing should succeed");

    /* Force only the PQ component to the hybrid provider (which has no
     * ML-KEM): keygen must fail -- proves pq-propquery is applied. */
    TEST_START("pq = provider=hybrid (no ML-KEM there) -> keygen fails");
    if (keygen_ok("pq-propquery = provider=hybrid\n") == 0) TEST_PASS();
    else TEST_FAIL("pq-propquery was not applied to the PQ component");

    /* Force only the classic component to hybrid (no X25519 there): keygen
     * must fail independently -- proves classic-propquery is applied. */
    TEST_START("classic = provider=hybrid (no X25519 there) -> keygen fails");
    if (keygen_ok("classic-propquery = provider=hybrid\n") == 0) TEST_PASS();
    else TEST_FAIL("classic-propquery was not applied to the classic component");

    printf("\n=======================================================\n");
    printf("Results: %d/%d passed", pass_count, test_count);
    if (fail_count) printf(" (%d FAILED)", fail_count);
    printf("\n");
    return fail_count == 0 ? 0 : 1;
}
