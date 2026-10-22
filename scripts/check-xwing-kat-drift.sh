#!/usr/bin/env bash
#
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# Detect drift between the upstream X-Wing reference test vectors and this repo's
# vendored copy (test/xwing_kat.txt, the oracle for xwing_kat_test). Two kinds:
#
#   (a) coherence — the vendored file must still match what test/regen_xwing_kat.py
#       produces from the pinned draft tag. Catches a hand-edit of the vectors, a
#       corrupted copy, or a TAG bump landed without regenerating the file.
#   (b) staleness — a newer draft-connolly-cfrg-xwing-kem-NN tag exists upstream
#       than the one we pin. The X-Wing combiner/label and ML-KEM-768 finalisation
#       shifted across early revisions, so the vectors only compare at a matched
#       version: we pin deliberately and bump deliberately. This is the signal to
#       evaluate the bump — not to chase it automatically.
#
# WHY buildless (no provider, no toolchain): like check-oqs-hybrid-drift.sh, this
# runs fast on a weekly schedule and files an actionable issue the moment upstream
# moves, rather than waiting for a vector mismatch to surface as a red test build.
# It needs only python3, git and the network.
#
# Exit status: 0 = in sync, 1 = drift detected (report on stdout), 2 = error.
#
# Env:
#   XWING_UPSTREAM   git URL to check (default: the CFRG draft repo)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGEN="$REPO_ROOT/test/regen_xwing_kat.py"
VENDORED="$REPO_ROOT/test/xwing_kat.txt"

# The upstream identity has a single home: the constants in regen_xwing_kat.py.
# Read REPO and TAG back from there and derive everything else, so this script
# hardcodes no repo URL, tag or tag-prefix of its own.
read_const() { sed -n "s/^$1 = \"\([^\"]*\)\".*/\1/p" "$REGEN"; }
REPO="$(read_const REPO)"
TAG="$(read_const TAG)"
if [ -z "$REPO" ] || [ -z "$TAG" ]; then
    echo "error: could not read REPO/TAG from $REGEN" >&2
    exit 2
fi
UPSTREAM="${XWING_UPSTREAM:-https://github.com/$REPO}"  # git URL for tag listing
TAG_PREFIX="${TAG%-*}"                                  # tag minus the -NN suffix
PINNED_NUM=$((10#${TAG##*-}))

report=""
drift=0

# (a) coherence: regenerate from the pinned tag and diff against the vendored copy.
fresh="$(mktemp)"
trap 'rm -f "$fresh"' EXIT
if ! python3 "$REGEN" > "$fresh" 2>/dev/null; then
    echo "error: could not fetch/distill pinned vectors ($TAG) from upstream" >&2
    exit 2
fi
if ! diff_out="$(diff -u "$VENDORED" "$fresh")"; then
    drift=1
    report+="Vendored test/xwing_kat.txt no longer matches regen at ${TAG}:"$'\n'
    report+="$diff_out"$'\n\n'
    report+="Fix: python3 test/regen_xwing_kat.py > test/xwing_kat.txt"$'\n\n'
fi

# (b) staleness: find the highest draft number published upstream.
latest="$(git ls-remote --tags "$UPSTREAM" "${TAG_PREFIX}-*" 2>/dev/null \
            | sed -E "s#.*/${TAG_PREFIX}-0*([0-9]+)\^?\{?.*#\1#" \
            | grep -E '^[0-9]+$' | sort -n | tail -1)" || latest=""
if [ -z "$latest" ]; then
    echo "error: could not list upstream tags at $UPSTREAM" >&2
    exit 2
fi
if [ "$latest" -gt "$PINNED_NUM" ]; then
    drift=1
    report+="Newer X-Wing draft upstream: ${TAG_PREFIX}-${latest} (we pin -${PINNED_NUM})."$'\n'
    report+="The vectors are version-sensitive. Evaluate bumping TAG in"$'\n'
    report+="test/regen_xwing_kat.py, regenerate test/xwing_kat.txt, and re-run"$'\n'
    report+="xwing_kat_test (adjust the combiner only if the draft changed it)."$'\n'
fi

printf '%s' "$report"
exit "$drift"
