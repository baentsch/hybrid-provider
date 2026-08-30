#!/usr/bin/env bash
#
# setup_oqs_interop.sh — (re)build the oqsprovider interop peer from source.
#
# The hybrid-provider's goal is format-identical interop with
# oqsprovider (see design.md). Interop MUST be tested against a from-source
# oqsprovider, never a distro/local install. This script reproduces that peer,
# so a machine wipe / reboot only costs one command:
#
#     ./test/setup_oqs_interop.sh
#
# It clones liboqs + oqs-provider into .interop/ (gitignored) at LIBOQS_REF /
# OQSPROV_REF (default: main for both), builds them against the OpenSSL install
# at OPENSSL_PREFIX, and symlinks the resulting oqsprovider.so into $BUILD_DIR so
# the test harness finds it via OPENSSL_MODULES.
#
#   OPENSSL_PREFIX  OpenSSL to build against (default: the repo's .local/, which
#                   you build yourself first; 3.5+ recommended so the default
#                   provider also offers the MLX hybrids — otherwise those tests
#                   self-skip). No system OpenSSL is assumed.
#   LIBOQS_PREFIX   Where liboqs is installed/detected (default: OPENSSL_PREFIX,
#                   i.e. everything in one prefix — the local-dev default). CI
#                   sets this to a separate dir so the pinned liboqs is cached
#                   independently of the OpenSSL patch level. liboqs links
#                   libcrypto (for AES/SHA), but only via the soname-stable
#                   public EVP API — its imports are all @OPENSSL_3.0.0, and it
#                   carries no RUNPATH — so one build resolves libcrypto.so.3 at
#                   runtime against whichever OpenSSL 3.x is staged beside it and
#                   need not be rebuilt per OpenSSL patch.
#   ONLY_LIBOQS     If "1", build/install liboqs into LIBOQS_PREFIX and stop
#                   (no oqs-provider, no OpenSSL required). Used by CI to populate
#                   the standalone liboqs cache before OpenSSL is staged.
#   BUILD_DIR       hybrid-provider build dir to drop oqsprovider.so into.
#
# Everything lives under the repo (.interop/, .local/, build/) — nothing in /tmp.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$REPO/.local}"
LIBOQS_PREFIX="${LIBOQS_PREFIX:-$OPENSSL_PREFIX}"
ONLY_LIBOQS="${ONLY_LIBOQS:-0}"
INTEROP="$REPO/.interop"
BUILD_DIR="${BUILD_DIR:-$REPO/build}"

LIBOQS_SRC="$INTEROP/liboqs"
OQSPROV_SRC="$INTEROP/oqs-provider"
OQSPROV_BUILD="$OQSPROV_SRC/_build"

# Which liboqs / oqs-provider to build (branch, tag or commit). Default is main
# for both (always mutually compatible). CI pins release/known-good refs for the
# regular jobs and uses main for the weekly bleeding-edge job.
LIBOQS_REF="${LIBOQS_REF:-main}"
OQSPROV_REF="${OQSPROV_REF:-main}"

# In-repo OQS_CEDE_HYBRIDS lever, applied to oqs-provider until it lands upstream.
CEDE_PATCH="$REPO/test/patches/oqsprovider-cede-hybrids.patch"

# Check out the requested ref (works for branch/tag/commit); clone if absent.
checkout_ref() {  # <dir> <ref>
    # A prior run may have applied our cede patch; undo ONLY that so the checkout
    # below is clean. Never discard other local work: revert solely when the tree's
    # single change is exactly our patch — otherwise leave everything intact and warn.
    if [ -n "$(git -C "$1" status --porcelain --untracked-files=no)" ]; then
        if git -C "$1" apply --reverse --check "$CEDE_PATCH" 2>/dev/null \
           && [ -z "$(git -C "$1" status --porcelain --untracked-files=no \
                      -- ':!oqsprov/oqsprov.c')" ]; then
            git -C "$1" apply --reverse "$CEDE_PATCH"   # our patch only
        else
            echo "!! $1 has uncommitted changes; leaving them intact" >&2
            echo "!! (commit or stash them for a clean re-checkout)" >&2
        fi
    fi
    git -C "$1" fetch --tags --force origin
    git -C "$1" checkout --quiet "$2"
    git -C "$1" pull --ff-only --quiet 2>/dev/null || true   # no-op on tag/commit
}

# Apply the in-repo OQS_CEDE_HYBRIDS patch unless oqsprovider already carries it.
# The lever puts oqsprovider in PQ-only mode so hybrid-provider serves every hybrid
# name (used by hybrid_replace_test). checkout_ref has already reverted any prior
# application of this same patch, so re-runs pick up patch edits cleanly. A no-op
# once it lands upstream; remove the patch file and this call at that point.
apply_cede_patch() {  # <oqs-provider src dir>
    [ -f "$CEDE_PATCH" ] || return 0
    if grep -q OQS_CEDE_HYBRIDS "$1/oqsprov/oqsprov.c" 2>/dev/null; then
        echo ">> OQS_CEDE_HYBRIDS already present in oqsprovider (skipping patch)"
    elif git -C "$1" apply --check "$CEDE_PATCH" 2>/dev/null; then
        git -C "$1" apply "$CEDE_PATCH"
        echo ">> applied cede-hybrids patch (OQS_CEDE_HYBRIDS lever)"
    else
        echo "!! cede-hybrids patch does not apply to $OQSPROV_REF (oqsprov.c may have" >&2
        echo "!! drifted); hybrid_replace_test will FAIL until the patch or pin is fixed." >&2
    fi
}

echo ">> repo:           $REPO"
echo ">> openssl prefix: $OPENSSL_PREFIX"
echo ">> liboqs prefix:  $LIBOQS_PREFIX"
echo ">> interop dir:    $INTEROP"

# OpenSSL is needed to build oqs-provider, but NOT to build liboqs — so the
# ONLY_LIBOQS pre-build (which runs before OpenSSL is staged) skips this check.
if [ "$ONLY_LIBOQS" != "1" ] && [ ! -d "$OPENSSL_PREFIX/include/openssl" ]; then
    echo "!! No OpenSSL found at $OPENSSL_PREFIX (need 3.5+). Set OPENSSL_PREFIX." >&2
    exit 1
fi

mkdir -p "$INTEROP"

# --- liboqs ------------------------------------------------------------------
# Rebuild liboqs into LIBOQS_PREFIX unless already installed there (a cache hit;
# the CI cache key includes LIBOQS_REF, so "installed" implies the right ref).
# liboqs links libcrypto only through the soname-stable @OPENSSL_3.0.0 EVP API
# (see the LIBOQS_PREFIX note above), so its prefix caches independently of the
# OpenSSL patch level.
echo ">> liboqs ref:      $LIBOQS_REF"
echo ">> oqs-provider ref: $OQSPROV_REF"
if [ -f "$LIBOQS_PREFIX/include/oqs/oqs.h" ]; then
    echo ">> liboqs already installed in $LIBOQS_PREFIX (skipping rebuild)"
else
    if [ ! -d "$LIBOQS_SRC/.git" ]; then
        git clone https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC"
    fi
    checkout_ref "$LIBOQS_SRC" "$LIBOQS_REF"
    cmake -S "$LIBOQS_SRC" -B "$LIBOQS_SRC/_build" -GNinja \
        -DCMAKE_INSTALL_PREFIX="$LIBOQS_PREFIX" \
        -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release
    cmake --build "$LIBOQS_SRC/_build"
    cmake --install "$LIBOQS_SRC/_build"
fi

# ONLY_LIBOQS: populate the standalone liboqs cache and stop (no OpenSSL yet).
if [ "$ONLY_LIBOQS" = "1" ]; then
    echo ">> ONLY_LIBOQS=1 — liboqs ready in $LIBOQS_PREFIX; skipping oqs-provider"
    exit 0
fi

# --- oqs-provider ------------------------------------------------------------
if [ ! -d "$OQSPROV_SRC/.git" ]; then
    git clone https://github.com/open-quantum-safe/oqs-provider.git "$OQSPROV_SRC"
fi
checkout_ref "$OQSPROV_SRC" "$OQSPROV_REF"
apply_cede_patch "$OQSPROV_SRC"
# CMAKE_PREFIX_PATH carries both prefixes so oqs-provider finds liboqs even when
# it lives in a prefix separate from OpenSSL (identical when the two coincide).
cmake -S "$OQSPROV_SRC" -B "$OQSPROV_BUILD" -GNinja \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX;$LIBOQS_PREFIX" \
    -DOQS_KEM_ENCODERS=ON \
    -DCMAKE_BUILD_TYPE=Release
cmake --build "$OQSPROV_BUILD"

OQSPROV_SO="$OQSPROV_BUILD/lib/oqsprovider.so"
[ -f "$OQSPROV_SO" ] || { echo "!! build produced no oqsprovider.so" >&2; exit 1; }

# --- expose to the test harness ---------------------------------------------
if [ -d "$BUILD_DIR" ]; then
    ln -sf "$OQSPROV_SO" "$BUILD_DIR/oqsprovider.so"
    echo ">> symlinked oqsprovider.so into $BUILD_DIR"
fi

echo ">> done. oqsprovider (main) built at: $OQSPROV_SO"
echo ">> commit: $(git -C "$OQSPROV_SRC" rev-parse --short HEAD)"
