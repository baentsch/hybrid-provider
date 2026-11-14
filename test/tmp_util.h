/*
 * Copyright 2026 The hybrid-provider Authors
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef HYBRID_TEST_TMP_UTIL_H
#define HYBRID_TEST_TMP_UTIL_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Size for a temporary-file path buffer. */
#ifdef PATH_MAX
# define HYBRID_TEST_PATH_MAX PATH_MAX
#else
# define HYBRID_TEST_PATH_MAX 4096
#endif

/*
 * Directory for the tests' temporary files: $TMPDIR if set, else the platform
 * default (POSIX P_tmpdir). The single place that decides it; no test
 * hardcodes a temporary directory.
 */
static inline const char *hybrid_test_tmp_dir(void)
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
 * Create a unique temporary file "<tmp dir>/<prefix>.XXXXXX" and return it open
 * for writing. Its path goes to path[pathsz] (HYBRID_TEST_PATH_MAX suffices);
 * the caller closes the stream and removes the file. The file is written
 * through the mkstemp descriptor, never reopened by name. Returns NULL on
 * failure, leaving no file behind.
 */
static inline FILE *hybrid_test_tmpfile(char *path, size_t pathsz,
                                        const char *prefix)
{
    int n = snprintf(path, pathsz, "%s/%s.XXXXXX", hybrid_test_tmp_dir(), prefix);
    int fd;
    FILE *f;

    if (n < 0 || (size_t)n >= pathsz || (fd = mkstemp(path)) < 0)
        return NULL;
    if ((f = fdopen(fd, "w")) == NULL) {
        close(fd);
        remove(path);
        return NULL;
    }
    return f;
}

#endif /* HYBRID_TEST_TMP_UTIL_H */
