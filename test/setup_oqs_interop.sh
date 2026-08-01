#!/usr/bin/env bash
#
# setup_oqs_interop.sh — (re)build the oqsprovider interop peer from GitHub main.
#
# The hybrid-provider's Phase-1 goal is format-identical interop with
# oqsprovider (see redesign.md). Interop MUST be tested against oqsprovider
# *main*, never a distro/local install. This script reproduces that peer from
# scratch, so a machine wipe / reboot only costs one command:
#
#     ./test/setup_oqs_interop.sh
#
# It clones liboqs + oqs-provider main into .interop/ (gitignored), builds them
# against the repo's local OpenSSL 3.5+ in .local/, and symlinks the resulting
# oqsprovider.so into build/ so the test harness finds it via OPENSSL_MODULES.
#
# Everything lives under the repo (.interop/, .local/, build/) — nothing in /tmp.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_PREFIX="${OPENSSL_PREFIX:-$REPO/.local}"
INTEROP="$REPO/.interop"
BUILD_DIR="${BUILD_DIR:-$REPO/build}"

LIBOQS_SRC="$INTEROP/liboqs"
OQSPROV_SRC="$INTEROP/oqs-provider"
OQSPROV_BUILD="$OQSPROV_SRC/_build"

echo ">> repo:           $REPO"
echo ">> openssl prefix: $OPENSSL_PREFIX"
echo ">> interop dir:    $INTEROP"

if [ ! -d "$OPENSSL_PREFIX/include/openssl" ]; then
    echo "!! No OpenSSL found at $OPENSSL_PREFIX (need 3.5+). Set OPENSSL_PREFIX." >&2
    exit 1
fi

mkdir -p "$INTEROP"

# --- liboqs (main) -----------------------------------------------------------
# oqs-provider main tracks liboqs main. Rebuild liboqs into the OpenSSL prefix
# unless a recent one (HQC level-naming: hqc_5) is already installed there.
if grep -q "OQS_KEM_alg_hqc_5" "$OPENSSL_PREFIX/include/oqs/kem.h" 2>/dev/null; then
    echo ">> liboqs already current in $OPENSSL_PREFIX (skipping rebuild)"
else
    if [ ! -d "$LIBOQS_SRC/.git" ]; then
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "$LIBOQS_SRC"
    else
        git -C "$LIBOQS_SRC" pull --ff-only
    fi
    cmake -S "$LIBOQS_SRC" -B "$LIBOQS_SRC/_build" -GNinja \
        -DCMAKE_INSTALL_PREFIX="$OPENSSL_PREFIX" \
        -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_BUILD_TYPE=Release
    cmake --build "$LIBOQS_SRC/_build"
    cmake --install "$LIBOQS_SRC/_build"
fi

# --- oqs-provider (main) -----------------------------------------------------
if [ ! -d "$OQSPROV_SRC/.git" ]; then
    git clone --depth 1 https://github.com/open-quantum-safe/oqs-provider.git "$OQSPROV_SRC"
else
    git -C "$OQSPROV_SRC" pull --ff-only
fi
cmake -S "$OQSPROV_SRC" -B "$OQSPROV_BUILD" -GNinja \
    -DOPENSSL_ROOT_DIR="$OPENSSL_PREFIX" \
    -DCMAKE_PREFIX_PATH="$OPENSSL_PREFIX" \
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
