#!/bin/sh
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# Regenerate the valid seeds in test/corpus/decode/ for the decoder fuzz harness
# (test/hybrid_decode_fuzz.c). Emits a PKCS#8 private key (DER) and its SPKI
# public key (DER) for a few hybrid signature algorithms, exercising the decode
# success path. Malformed/truncated seeds in the same directory are derived from
# these and kept under version control by hand.
#
# Usage:
#   OPENSSL=/path/to/openssl-3.5+/bin/openssl \
#   OPENSSL_MODULES=/path/to/build \
#   LD_LIBRARY_PATH=/path/to/openssl-3.5+/lib64 \
#   test/corpus/gen_decode_corpus.sh
#
# If the provider module was built with ASAN (the fuzz build does this), preload
# libasan so the non-ASAN openssl CLI can dlopen it:
#   LD_PRELOAD=$(gcc -print-file-name=libasan.so) ...
set -eu

OPENSSL=${OPENSSL:-openssl}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT="$HERE/decode"
mkdir -p "$OUT"

: "${OPENSSL_MODULES:?set OPENSSL_MODULES to the directory holding hybrid.so}"
export HYBRID_CEDE_TO_DEFAULT=0
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0}

# One EC-hybrid and one RSA-hybrid signature alg give distinct classical-key
# shapes through the same decode path. Extend as component availability allows.
for alg in p256_mldsa44 rsa3072_mldsa44 p256_falcon512; do
    if "$OPENSSL" genpkey -algorithm "$alg" \
            -provider hybrid -provider default \
            -outform DER -out "$OUT/${alg}_p8.der" 2>/dev/null \
        && "$OPENSSL" pkey -provider hybrid -provider default \
            -inform DER -in "$OUT/${alg}_p8.der" \
            -pubout -outform DER -out "$OUT/${alg}_spki.der" 2>/dev/null; then
        echo "generated $alg"
    else
        echo "skipped $alg (component unavailable)"
        rm -f "$OUT/${alg}_p8.der" "$OUT/${alg}_spki.der"
    fi
done
