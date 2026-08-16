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

    remove(CAP_FILE);
    printf("\nResults: %d/%d passed", passed, tests);
    if (failed > 0)
        printf(" (%d FAILED)", failed);
    printf("\n");
    return failed == 0 ? 0 : 1;
}
