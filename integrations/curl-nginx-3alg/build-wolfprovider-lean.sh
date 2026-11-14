#!/bin/bash
# =============================================================================
# Lean wolfProvider build for the 3-alg demo (add-on; not part of the oqs-demos
# baseline). Unlike wolfProvider's own scripts/build-wolfprovider.sh — which is
# a CI harness that clones and compiles a SECOND, pinned OpenSSL — this builds
# wolfSSL + wolfProvider against the ONE shared OpenSSL already installed in
# ${INSTALLDIR}. One libcrypto for everything.
#
# wolfSSL's exact configure flags (opts + CFLAGS) are owned by wolfProvider
# upstream (scripts/utils-wolfssl.sh). We PIN them here for auditability, and then
# assert at build time that our pins still equal upstream's — any drift fails the
# build loudly instead of silently building a differently-configured wolfSSL. (The
# wolfSSL *version* is pinned by us for reproducibility; upstream floats it — see
# PIN_TAG below.)
#
# Env in:  INSTALLDIR  MODULES  WOLFPROVIDER_TAG
# =============================================================================
set -euo pipefail

INSTALLDIR="${INSTALLDIR:?}"
MODULES="${MODULES:?}"
WOLFPROVIDER_TAG="${WOLFPROVIDER_TAG:-master}"

# --- PINNED, kept in sync with wolfProvider scripts/utils-wolfssl.sh ---------
# (${OPENSSL_INSTALL_DIR} is kept as a literal token so the drift check matches
# the upstream source verbatim; it is substituted with ${INSTALLDIR} for the
# actual build. Note the trailing space in PIN_CFLAGS — it is in the source.)
# wolfSSL tag: wolfProvider's script does NOT pin this — it auto-resolves the
# latest wolfSSL release at build time (v5.9.1-stable is only its API-unreachable
# fallback). We pin our own reproducible, ML-KEM-capable release instead (must be
# >= v5.9.2-stable for ML-KEM with wolfProvider master). The tag is therefore NOT
# part of the drift check below — only the configure flags are.
PIN_TAG='v5.9.4-stable'
PIN_OPTS='--enable-all-crypto --with-eccminsz=192 --with-max-ecc-bits=1024 --enable-opensslcoexist --enable-sha'
PIN_CFLAGS='-I${OPENSSL_INSTALL_DIR}/include -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP -DHAVE_PUBLIC_FFDHE -DHAVE_FFDHE_6144 -DHAVE_FFDHE_8192 -DWOLFSSL_PSS_LONG_SALT -DWOLFSSL_PSS_SALT_LEN_DISCOVER -DRSA_MIN_SIZE=1024 -DWOLFSSL_OLD_OID_SUM '
PIN_MLKEM='--enable-mlkem'

apk --no-cache add patchelf pkgconf >/dev/null

git clone --depth 1 --branch "${WOLFPROVIDER_TAG}" https://github.com/wolfSSL/wolfProvider.git /opt/wolfProvider

# --- drift guard: our pins vs wolfProvider's utils-wolfssl.sh -----------------
UTIL=/opt/wolfProvider/scripts/utils-wolfssl.sh
[ -f "$UTIL" ] || { echo "DRIFT: $UTIL not found — upstream layout changed"; exit 1; }

# Anchor on the LHS variable name: the file also defines WOLFSSL_FIPS_CONFIG_OPTS/
# _CFLAGS whose ${...:-} bodies contain the same substring, so an unanchored match
# would grab the FIPS variant.
up_opts=$(grep -m1 '^WOLFSSL_CONFIG_OPTS='  "$UTIL" | sed "s/.*:-'//; s/'.*//")
up_cflags=$(grep -m1 '^WOLFSSL_CONFIG_CFLAGS=' "$UTIL" | sed 's/.*:-"//; s/".*//')

fail=0
chk() { # name pinned upstream
    if [ "$2" != "$3" ]; then
        echo "DRIFT in $1:"; echo "  pinned:   [$2]"; echo "  upstream: [$3]"; fail=1
    fi
}
chk "WOLFSSL_CONFIG_OPTS"   "$PIN_OPTS"   "$up_opts"
chk "WOLFSSL_CONFIG_CFLAGS" "$PIN_CFLAGS" "$up_cflags"
if ! grep -q 'WOLFPROV_MLKEM' "$UTIL" || ! grep -q -- "$PIN_MLKEM" "$UTIL"; then
    echo "DRIFT: WOLFPROV_MLKEM/${PIN_MLKEM} mapping no longer in $UTIL"; fail=1
fi
if [ "$fail" != 0 ]; then
    echo "wolfSSL build flags drifted from wolfProvider upstream; update the PIN_* in $0." >&2
    exit 1
fi
echo "wolfSSL pin drift-check OK (opts + cflags + mlkem match upstream; tag pinned locally to ${PIN_TAG})"

# --- build wolfSSL once, against the shared OpenSSL ---------------------------
real_cflags=$(printf '%s' "$PIN_CFLAGS" | sed "s|\${OPENSSL_INSTALL_DIR}|${INSTALLDIR}|g")
git clone --depth 1 --branch "${PIN_TAG}" https://github.com/wolfSSL/wolfssl.git /opt/wolfssl
cd /opt/wolfssl
./autogen.sh
# shellcheck disable=SC2086
./configure --prefix="${INSTALLDIR}" ${PIN_OPTS} ${PIN_MLKEM} CFLAGS="${real_cflags}"
make -j"$(nproc)"
make install

# --- build wolfProvider against the shared OpenSSL + that wolfSSL -------------
cd /opt/wolfProvider
./autogen.sh
./configure --with-openssl="${INSTALLDIR}" --with-wolfssl="${INSTALLDIR}" ${PIN_MLKEM}
make -j"$(nproc)"

# --- install the module (registers as "wolfprov"; loader wants wolfprov.so) ---
cp .libs/libwolfprov.so "${MODULES}/"
# The module is built without a DT_NEEDED on libwolfssl; add it + rpath so its
# wc_* symbols resolve when OpenSSL dlopens it into the hybrid's private ctx.
patchelf --add-needed libwolfssl.so --set-rpath "${INSTALLDIR}/lib64" "${MODULES}/libwolfprov.so"
ln -sf libwolfprov.so "${MODULES}/wolfprov.so"
echo "wolfProvider (lean) built: ${MODULES}/wolfprov.so"
