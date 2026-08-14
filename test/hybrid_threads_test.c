/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Concurrency, fork and teardown stress test (issue #43).
 *
 * The provider is designed to keep no shared mutable runtime state: the
 * cede-to-default tables are per-instance and immutable after init, and
 * component sizes are compile-time constants. This test is the regression guard
 * for that — under TSan it must stay race-free:
 *
 *   1. independent   — N threads each run keygen+encaps+decaps and
 *                      keygen+sign+verify with their OWN keys on ONE shared
 *                      libctx, stressing the shared component-fetch/query paths.
 *   2. shared key    — many threads run operations concurrently against the SAME
 *                      key object, stressing concurrent reads of one key.
 *   3. load/unload   — N threads each load the provider into their OWN libctx,
 *                      operate, and unload, stressing concurrent init/teardown
 *                      of the per-instance cede state.
 *   4. fork+operate  — fork() with the provider loaded, then operate in the
 *                      child, proving post-fork state is usable.
 *
 * Meant to be run under AddressSanitizer (the sanitize CI leg) and
 * ThreadSanitizer (the tsan CI leg). Uses only the public EVP/provider API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/err.h>

/* Algorithms exercised. Both resolve entirely from the default provider on
 * OpenSSL >= 3.5 (native ML-KEM/ML-DSA), which is where this test runs. */
#define KEM_ALG "X25519MLKEM768"
#define SIG_ALG "p256_mldsa44"

#define N_THREADS 8
#define N_ITERS   24

static const char *module_path;   /* OPENSSL_MODULES, for per-thread libctxs */

static int sig_sign_verify(OSSL_LIB_CTX *libctx, EVP_PKEY *key,
                           const unsigned char *msg, size_t msglen);
static int kem_encap_decap(OSSL_LIB_CTX *libctx, EVP_PKEY *key);

/* keygen -> encaps -> decaps on `alg`; shared secrets must match. */
static int do_kem(OSSL_LIB_CTX *libctx, const char *alg)
{
    EVP_PKEY_CTX *gctx = NULL, *ectx = NULL, *dctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ctlen = 0, ss1len = 0, ss2len = 0;
    int ret = 0;

    if ((gctx = EVP_PKEY_CTX_new_from_name(libctx, alg, "provider=hybrid")) == NULL
            || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &key) <= 0)
        goto err;

    if ((ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid")) == NULL
            || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0
            || EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &ss1len) <= 0)
        goto err;
    if ((ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss1 = OPENSSL_malloc(ss1len)) == NULL
            || EVP_PKEY_encapsulate(ectx, ct, &ctlen, ss1, &ss1len) <= 0)
        goto err;

    if ((dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid")) == NULL
            || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0
            || EVP_PKEY_decapsulate(dctx, NULL, &ss2len, ct, ctlen) <= 0)
        goto err;
    if ((ss2 = OPENSSL_malloc(ss2len)) == NULL
            || EVP_PKEY_decapsulate(dctx, ss2, &ss2len, ct, ctlen) <= 0)
        goto err;

    ret = (ss1len == ss2len && memcmp(ss1, ss2, ss1len) == 0);

err:
    OPENSSL_free(ct);
    OPENSSL_free(ss1);
    OPENSSL_free(ss2);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gctx);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/* Encapsulate to a pre-existing public key, then decapsulate with it. */
static int kem_encap_decap(OSSL_LIB_CTX *libctx, EVP_PKEY *key)
{
    EVP_PKEY_CTX *ectx = NULL, *dctx = NULL;
    unsigned char *ct = NULL, *ss1 = NULL, *ss2 = NULL;
    size_t ctlen = 0, ss1len = 0, ss2len = 0;
    int ret = 0;

    if ((ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid")) == NULL
            || EVP_PKEY_encapsulate_init(ectx, NULL) <= 0
            || EVP_PKEY_encapsulate(ectx, NULL, &ctlen, NULL, &ss1len) <= 0)
        goto err;
    if ((ct = OPENSSL_malloc(ctlen)) == NULL
            || (ss1 = OPENSSL_malloc(ss1len)) == NULL
            || EVP_PKEY_encapsulate(ectx, ct, &ctlen, ss1, &ss1len) <= 0)
        goto err;
    if ((dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid")) == NULL
            || EVP_PKEY_decapsulate_init(dctx, NULL) <= 0
            || (ss2 = OPENSSL_malloc(ss1len)) == NULL
            || (ss2len = ss1len,
                EVP_PKEY_decapsulate(dctx, ss2, &ss2len, ct, ctlen) <= 0))
        goto err;
    ret = (ss1len == ss2len && memcmp(ss1, ss2, ss1len) == 0);

err:
    OPENSSL_free(ct);
    OPENSSL_free(ss1);
    OPENSSL_free(ss2);
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_CTX_free(dctx);
    return ret;
}

/* keygen -> sign -> verify on `alg`. */
static int do_sig(OSSL_LIB_CTX *libctx, const char *alg)
{
    static const unsigned char msg[] = "hybrid-provider concurrency test";
    EVP_PKEY_CTX *gctx = NULL;
    EVP_PKEY *key = NULL;
    int ret = 0;

    if ((gctx = EVP_PKEY_CTX_new_from_name(libctx, alg, "provider=hybrid")) == NULL
            || EVP_PKEY_keygen_init(gctx) <= 0
            || EVP_PKEY_keygen(gctx, &key) <= 0)
        goto err;
    ret = sig_sign_verify(libctx, key, msg, sizeof(msg) - 1);

err:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(gctx);
    return ret;
}

/* Sign then verify `msg` with an existing key. */
static int sig_sign_verify(OSSL_LIB_CTX *libctx, EVP_PKEY *key,
                           const unsigned char *msg, size_t msglen)
{
    EVP_MD_CTX *sctx = NULL, *vctx = NULL;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    int ret = 0;

    if ((sctx = EVP_MD_CTX_new()) == NULL
            || EVP_DigestSignInit_ex(sctx, NULL, NULL, libctx, NULL, key,
                                     NULL) <= 0
            || EVP_DigestSign(sctx, NULL, &siglen, msg, msglen) <= 0
            || (sig = OPENSSL_malloc(siglen)) == NULL
            || EVP_DigestSign(sctx, sig, &siglen, msg, msglen) <= 0)
        goto err;

    if ((vctx = EVP_MD_CTX_new()) == NULL
            || EVP_DigestVerifyInit_ex(vctx, NULL, NULL, libctx, NULL, key,
                                       NULL) <= 0
            || EVP_DigestVerify(vctx, sig, siglen, msg, msglen) <= 0)
        goto err;
    ret = 1;

err:
    OPENSSL_free(sig);
    EVP_MD_CTX_free(sctx);
    EVP_MD_CTX_free(vctx);
    return ret;
}

/* ---------------------------------------------------------------- test 1 --- */

struct shared_arg {
    OSSL_LIB_CTX *libctx;
    int failures;
};

static void *independent_worker(void *v)
{
    struct shared_arg *a = v;
    int i;

    for (i = 0; i < N_ITERS; i++) {
        if (!do_kem(a->libctx, KEM_ALG) || !do_sig(a->libctx, SIG_ALG)) {
            __atomic_fetch_add(&a->failures, 1, __ATOMIC_RELAXED);
            return NULL;
        }
    }
    return NULL;
}

static int test_independent(OSSL_LIB_CTX *libctx)
{
    pthread_t t[N_THREADS];
    struct shared_arg a = { libctx, 0 };
    int i, ok = 1;

    for (i = 0; i < N_THREADS; i++)
        if (pthread_create(&t[i], NULL, independent_worker, &a) != 0)
            ok = 0;
    for (i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);
    return ok && a.failures == 0;
}

/* ---------------------------------------------------------------- test 2 --- */

struct sharedkey_arg {
    OSSL_LIB_CTX *libctx;
    EVP_PKEY *kem_key;      /* one object, used by every thread */
    EVP_PKEY *sig_key;
    const unsigned char *msg;
    size_t msglen;
    int failures;
};

static void *sharedkey_worker(void *v)
{
    struct sharedkey_arg *a = v;
    int i;

    /* All threads hit the same key objects concurrently, reading the same
     * immutable component EVP_PKEYs and constant sizes. */
    for (i = 0; i < N_ITERS; i++) {
        if (!kem_encap_decap(a->libctx, a->kem_key)
                || !sig_sign_verify(a->libctx, a->sig_key, a->msg, a->msglen)) {
            __atomic_fetch_add(&a->failures, 1, __ATOMIC_RELAXED);
            return NULL;
        }
    }
    return NULL;
}

static int test_shared_key(OSSL_LIB_CTX *libctx)
{
    static const unsigned char msg[] = "shared-key concurrency";
    pthread_t t[N_THREADS];
    struct sharedkey_arg a;
    EVP_PKEY_CTX *gk = NULL, *gs = NULL;
    int i, ok = 0;

    memset(&a, 0, sizeof(a));
    a.libctx = libctx;
    a.msg = msg;
    a.msglen = sizeof(msg) - 1;

    /* Generate the shared keys, then hand the same objects to every thread. */
    if ((gk = EVP_PKEY_CTX_new_from_name(libctx, KEM_ALG, "provider=hybrid")) == NULL
            || EVP_PKEY_keygen_init(gk) <= 0
            || EVP_PKEY_keygen(gk, &a.kem_key) <= 0)
        goto err;
    if ((gs = EVP_PKEY_CTX_new_from_name(libctx, SIG_ALG, "provider=hybrid")) == NULL
            || EVP_PKEY_keygen_init(gs) <= 0
            || EVP_PKEY_keygen(gs, &a.sig_key) <= 0)
        goto err;

    ok = 1;
    for (i = 0; i < N_THREADS; i++)
        if (pthread_create(&t[i], NULL, sharedkey_worker, &a) != 0)
            ok = 0;
    for (i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);
    ok = ok && a.failures == 0;

err:
    EVP_PKEY_free(a.kem_key);
    EVP_PKEY_free(a.sig_key);
    EVP_PKEY_CTX_free(gk);
    EVP_PKEY_CTX_free(gs);
    return ok;
}

/* ---------------------------------------------------------------- test 3 --- */

static void *loadunload_worker(void *v)
{
    int *failures = v;
    int i;

    for (i = 0; i < 6; i++) {
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        OSSL_PROVIDER *deflt = NULL, *hyb = NULL;
        int ok = 0;

        if (libctx == NULL)
            goto next;
        if (module_path != NULL)
            OSSL_PROVIDER_set_default_search_path(libctx, module_path);
        deflt = OSSL_PROVIDER_load(libctx, "default");
        hyb = OSSL_PROVIDER_load(libctx, "hybrid");
        if (deflt != NULL && hyb != NULL)
            ok = do_kem(libctx, KEM_ALG);
next:
        OSSL_PROVIDER_unload(hyb);
        OSSL_PROVIDER_unload(deflt);
        OSSL_LIB_CTX_free(libctx);
        if (!ok)
            __atomic_fetch_add(failures, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}

static int test_load_unload(void)
{
    pthread_t t[N_THREADS];
    int failures = 0, i, ok = 1;

    for (i = 0; i < N_THREADS; i++)
        if (pthread_create(&t[i], NULL, loadunload_worker, &failures) != 0)
            ok = 0;
    for (i = 0; i < N_THREADS; i++)
        pthread_join(t[i], NULL);
    return ok && failures == 0;
}

/* ---------------------------------------------------------------- test 4 --- */

/* Fork with the provider loaded, then operate in the child. Proves the shared
 * state inherited across fork() is usable (no lock left held, no stale cache).
 * The child uses its OWN libctx to avoid touching the parent's providers. */
static int test_fork(void)
{
    pid_t pid = fork();

    if (pid < 0)
        return 0;                       /* fork failed: cannot run this leg */

    if (pid == 0) {
        /* Child: independent libctx, do real work, exit 0 on success. */
        OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
        int ok = 0;

        if (libctx != NULL) {
            if (module_path != NULL)
                OSSL_PROVIDER_set_default_search_path(libctx, module_path);
            if (OSSL_PROVIDER_load(libctx, "default") != NULL
                    && OSSL_PROVIDER_load(libctx, "hybrid") != NULL)
                ok = do_kem(libctx, KEM_ALG) && do_sig(libctx, SIG_ALG);
            OSSL_LIB_CTX_free(libctx);
        }
        _exit(ok ? 0 : 1);
    }

    {   /* Parent: reap and report the child's verdict. */
        int status = 0;

        if (waitpid(pid, &status, 0) != pid)
            return 0;
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
}

/* --------------------------------------------------------------- harness --- */

static int run(const char *name, int result, int *fails)
{
    printf("  %-28s ... %s\n", name, result ? "PASS" : "FAIL");
    if (!result) {
        (*fails)++;
        ERR_print_errors_fp(stderr);
    }
    return result;
}

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *deflt = NULL, *hyb = NULL;
    int fails = 0;

    module_path = getenv("OPENSSL_MODULES");

    printf("hybrid-provider thread/fork/teardown stress test\n");
    printf("================================================\n");

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        goto done;
    if (module_path != NULL)
        OSSL_PROVIDER_set_default_search_path(libctx, module_path);
    deflt = OSSL_PROVIDER_load(libctx, "default");
    hyb = OSSL_PROVIDER_load(libctx, "hybrid");
    if (deflt == NULL || hyb == NULL) {
        fprintf(stderr, "provider load failed\n");
        ERR_print_errors_fp(stderr);
        fails = 1;
        goto done;
    }

    run("independent threads", test_independent(libctx), &fails);
    run("shared-key threads", test_shared_key(libctx), &fails);
    run("concurrent load/unload", test_load_unload(), &fails);
    run("fork then operate", test_fork(), &fails);

done:
    OSSL_PROVIDER_unload(hyb);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);

    printf("================================================\n");
    printf("%s\n", fails == 0 ? "ALL PASS" : "FAILURES");
    return fails == 0 ? 0 : 1;
}
