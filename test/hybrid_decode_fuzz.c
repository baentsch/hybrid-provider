/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Decoder fuzz harness for the hybrid provider.
 *
 * Feeds attacker-controlled bytes through OpenSSL's OSSL_DECODER machinery with
 * the hybrid provider loaded, exercising the untrusted-key-material decode paths
 * hybrid_decode() (SubjectPublicKeyInfo) and hybrid_decode_p8() (PKCS#8
 * PrivateKeyInfo) in hybrid_decoder.c, plus the component sub-key loading they
 * drive (hybrid_key_load_pub_components / hybrid_key_load_prv_components).
 *
 * This is the key-import attack surface: any application that decodes an
 * untrusted public key or PKCS#8 private key (PKI enrollment, key upload, CMS
 * key import, CLI on an untrusted file) reaches exactly this code. Build with
 * -fsanitize=address to catch out-of-bounds writes/reads of the classic
 * key-parsing kind — e.g. a serialization call that writes into a fixed-size
 * buffer before its produced length is checked, or a length taken from the DER
 * and used without bounding it against the destination.
 *
 * Two build modes, selected by CMake:
 *   - libFuzzer (HYBRID_FUZZ_LIBFUZZER defined): coverage-guided fuzzing, entry
 *     point LLVMFuzzerTestOneInput(); libFuzzer supplies main().
 *   - standalone (default): a plain main() that runs each file named on argv
 *     (or a directory of them) through the same entry point once. Lets CI and
 *     manual reproduction exercise the harness over a seed corpus without a
 *     fuzzing-capable compiler.
 */

#include <dirent.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/decoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

/*
 * One-time provider setup, shared across all fuzz iterations. libFuzzer calls
 * the entry point in a tight loop, so loading providers per call would dominate
 * the run; do it once and leak it deliberately (the process is short-lived and
 * the allocation is a fixed one-off, so there is nothing for a leak checker to
 * flag as growth).
 */
static OSSL_LIB_CTX *g_libctx = NULL;

static void ensure_init(void)
{
    const char *mods;

    if (g_libctx != NULL)
        return;

    g_libctx = OSSL_LIB_CTX_new();
    if (g_libctx == NULL) {
        fprintf(stderr, "OSSL_LIB_CTX_new failed\n");
        exit(1);
    }
    /* Same module-discovery convention as the CTest suite (add_test sets
     * OPENSSL_MODULES=${CMAKE_BINARY_DIR}); the fuzzer inherits it. */
    mods = getenv("OPENSSL_MODULES");
    if (mods != NULL)
        OSSL_PROVIDER_set_default_search_path(g_libctx, mods);

    if (OSSL_PROVIDER_load(g_libctx, "default") == NULL
            || OSSL_PROVIDER_load(g_libctx, "hybrid") == NULL) {
        fprintf(stderr, "failed to load default/hybrid providers "
                        "(set OPENSSL_MODULES to the build dir)\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    /* Optional experimental tier; absence is not fatal to the harness. */
    OSSL_PROVIDER_load(g_libctx, "oqsprovider");
    ERR_clear_error();
}

/*
 * Drive one decode attempt: hand the raw bytes to OSSL_DECODER as DER with no
 * keytype/structure constraint, so the framework offers them to every
 * registered decoder — including the hybrid provider's SPKI and PKCS#8
 * decoders. selection 0 means "public or private", so both hybrid_decode() and
 * hybrid_decode_p8() are reachable from a single input.
 */
static void decode_once(const uint8_t *data, size_t size)
{
    OSSL_DECODER_CTX *dctx;
    EVP_PKEY *pkey = NULL;
    const unsigned char *p = data;
    size_t plen = size;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", NULL, NULL, 0,
                                         g_libctx, NULL);
    if (dctx != NULL) {
        (void)OSSL_DECODER_from_data(dctx, &p, &plen);
        OSSL_DECODER_CTX_free(dctx);
    }
    EVP_PKEY_free(pkey);
    /* Decoders legitimately raise errors on inputs that carry one of our OIDs
     * but malformed contents; drop them so the error stack does not grow
     * unboundedly across iterations. */
    ERR_clear_error();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* An oversized input only makes each iteration slower without reaching new
     * decoder logic; the interesting structure lives in the first few KB. */
    if (size > 65536)
        return 0;

    ensure_init();
    decode_once(data, size);
    return 0;
}

#ifndef HYBRID_FUZZ_LIBFUZZER
/*
 * Standalone driver (no libFuzzer): run the entry point once per input file
 * named on the command line. A directory argument is expanded to its regular
 * file entries, so `hybrid_decode_fuzz corpus/` replays a whole seed corpus.
 * Exit status is 0 as long as the process survives every input — an ASAN abort
 * is the failure signal, which is exactly what CI checks for.
 */
static int run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    long n;
    unsigned char *buf;

    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return 0; /* skip unreadable entries rather than fail the run */
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0) {
        fclose(f);
        return 0;
    }
    rewind(f);
    buf = OPENSSL_malloc((size_t)n + 1);
    if (buf == NULL) {
        fclose(f);
        return 0;
    }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        OPENSSL_free(buf);
        fclose(f);
        return 0;
    }
    fclose(f);
    LLVMFuzzerTestOneInput(buf, (size_t)n);
    OPENSSL_free(buf);
    return 1;
}

static void run_path(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *ent;
    char child[4096];

    if (d == NULL) {          /* not a directory: treat as a single file */
        run_file(path);
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.')
            continue;
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        run_file(child);
    }
    closedir(d);
}

int main(int argc, char **argv)
{
    int i;

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <file-or-dir> [more...]\n"
                "  runs each input through the hybrid decoder once under ASAN.\n"
                "  set OPENSSL_MODULES to the directory holding hybrid.so\n",
                argv[0]);
        /* An empty invocation still verifies provider load wiring. */
        ensure_init();
        printf("providers loaded OK; no inputs given\n");
        return 0;
    }
    for (i = 1; i < argc; i++)
        run_path(argv[i]);
    printf("survived all inputs\n");
    return 0;
}
#endif /* HYBRID_FUZZ_LIBFUZZER */
