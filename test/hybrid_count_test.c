/*
 * Copyright 2026 hybrid-provider contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Headline algorithm-count guard.
 *
 * The README advertises a headline count of how many algorithms this provider
 * serves. That number must never silently drift as rows are added to the
 * source-of-truth tables (HYBRID_KEM_LIST / HYBRID_SIG_LIST / COMPOSITE_SIG_LIST
 * / COMPOSITE_KEM_LIST). This test recomputes the counts from those tables at
 * compile time and asserts the README's "Algorithms served:" line agrees, so a
 * new algorithm forces the headline to be updated (or CI fails).
 *
 * The README line has a fixed, parseable shape carrying exactly seven integers
 * in order:
 *
 *   **Algorithms served:** <kem> hybrid KEMs + <sig> hybrid signatures =
 *   <core> hybrid algorithms; with `-DHYBRID_COMPOSITE`, <csig> composite
 *   signatures + <ckem> composite KEMs = <comp> more, for <total> total.
 *
 * Built inside the HYBRID_COMPOSITE block so all four counts are visible.
 *
 * argv[1] = path to README.md (passed by CMake from ${CMAKE_SOURCE_DIR}).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../hybrid_prov.h"
#include "../composite_prov.h"
#include "../composite_kem_prov.h"

#define ANCHOR "**Algorithms served:**"

/* Pull the first n non-negative integers appearing at/after p into out[]. */
static int scan_ints(const char *p, long *out, int n)
{
    int got = 0;

    while (*p != '\0' && got < n) {
        if (isdigit((unsigned char)*p)) {
            char *end;
            out[got++] = strtol(p, &end, 10);
            p = end;
        } else {
            p++;
        }
    }
    return got;
}

int main(int argc, char **argv)
{
    const long kem   = HYBRID_KEM_ALG_COUNT;
    const long sig   = HYBRID_SIG_ALG_COUNT;
    const long csig  = COMPOSITE_SIG_ALG_COUNT;
    const long ckem  = COMPOSITE_KEM_ALG_COUNT;
    const long core  = kem + sig;
    const long comp  = csig + ckem;
    const long total = core + comp;
    long v[7];
    char *buf, *anchor;
    long flen;
    FILE *f;
    int fail = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-README.md>\n", argv[0]);
        return 2;
    }
    if ((f = fopen(argv[1], "rb")) == NULL) {
        fprintf(stderr, "cannot open %s\n", argv[1]);
        return 2;
    }
    fseek(f, 0, SEEK_END);
    flen = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (flen < 0 || (buf = malloc((size_t)flen + 1)) == NULL) {
        fclose(f);
        return 2;
    }
    if (fread(buf, 1, (size_t)flen, f) != (size_t)flen) {
        fclose(f);
        free(buf);
        return 2;
    }
    fclose(f);
    buf[flen] = '\0';

    printf("computed from tables: kem=%ld sig=%ld core=%ld "
           "csig=%ld ckem=%ld comp=%ld total=%ld\n",
           kem, sig, core, csig, ckem, comp, total);

    if ((anchor = strstr(buf, ANCHOR)) == NULL) {
        fprintf(stderr, "FAIL: README missing \"%s\" headline\n", ANCHOR);
        free(buf);
        return 1;
    }
    if (scan_ints(anchor + strlen(ANCHOR), v, 7) != 7) {
        fprintf(stderr, "FAIL: README headline does not carry 7 integers\n");
        free(buf);
        return 1;
    }

    printf("README headline says: kem=%ld sig=%ld core=%ld "
           "csig=%ld ckem=%ld comp=%ld total=%ld\n",
           v[0], v[1], v[2], v[3], v[4], v[5], v[6]);

#define CHECK(label, got, want)                                               \
    do {                                                                      \
        if ((got) != (want)) {                                               \
            fprintf(stderr, "FAIL: %s: README says %ld, tables say %ld\n",    \
                    (label), (long)(got), (long)(want));                      \
            fail = 1;                                                         \
        }                                                                     \
    } while (0)

    CHECK("hybrid KEMs",         v[0], kem);
    CHECK("hybrid signatures",   v[1], sig);
    CHECK("hybrid total",        v[2], core);
    CHECK("composite signatures", v[3], csig);
    CHECK("composite KEMs",      v[4], ckem);
    CHECK("composite total",     v[5], comp);
    CHECK("grand total",         v[6], total);
#undef CHECK

    free(buf);
    if (fail) {
        fprintf(stderr,
                "\nUpdate the \"Algorithms served:\" line in README.md to match "
                "the algorithm tables.\n");
        return 1;
    }
    printf("PASS: README headline matches the algorithm tables\n");
    return 0;
}
