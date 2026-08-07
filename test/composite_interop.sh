#!/usr/bin/env bash
#
# composite_interop.sh — cross-provider interop for the one thing hybrid-provider
# and CompositeCrypto/composite-provider actually overlap on: LAMPS composite
# ML-DSA *signatures*.
#
# The two providers implement the same draft-ietf-lamps-pq-composite-sigs
# algorithms but under DIFFERENT provider-local names (ours e.g.
# "mldsa44_ecdsa_p256"; theirs e.g. "ML-DSA-44-ECDSA-P256"). The only stable
# cross-provider identifier is the composite OID arc 1.3.6.1.5.5.7.6.NN, so the
# check works through serialized artifacts matched by OID rather than by name:
#
#   1. Enumerate each provider's signature algorithms and, for each, generate a
#      self-signed certificate. The cert's SubjectPublicKeyInfo / signature both
#      carry the composite OID; algorithms whose cert has no 1.3.6.1.5.5.7.6.*
#      OID (i.e. the concat hybrids, not composites) drop out automatically.
#   2. For every OID present on BOTH sides, cross-verify: hybrid-produced cert
#      verified under composite-provider, and vice versa. Byte-compatible wire
#      formats verify; a mismatch fails.
#
# OIDs only one side produces are reported SKIP (no counterpart), not FAIL — the
# providers implement different subsets of the draft matrix. The classical /
# ML-DSA components come from the default provider (OpenSSL 3.5+); on older
# OpenSSL, or when either provider or a component is unavailable, the affected
# algorithm self-skips.
#
# composite-provider (github.com/CompositeCrypto/composite-provider) is an
# external, early-stage peer, so this is NOT wired into ctest; run it by hand
# after placing composite.$SOEXT on the module path (or pass --build to fetch
# and build it into .interop/). It self-skips (exit 0) when the peer is absent.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-$REPO/build}"
COMPOSITE_REPO="${COMPOSITE_REPO:-https://github.com/CompositeCrypto/composite-provider.git}"
COMPOSITE_REF="${COMPOSITE_REF:-main}"
BUILD=0
KEEP=0

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SOEXT="${SOEXT:-dll}";;
    Darwin)               SOEXT="${SOEXT:-dylib}";;
    *)                    SOEXT="${SOEXT:-so}";;
esac

usage() {
    sed -n '3,33p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [options]

Options:
  --openssl PATH      openssl binary            (default: $OPENSSL_BIN)
  --libpath PATH      LD_LIBRARY_PATH for libs  (default: none)
  --module-dir DIR    OPENSSL_MODULES dir with hybrid.$SOEXT / composite.$SOEXT
                      (default: $MODULE_DIR)
  --build             Clone + build composite-provider into .interop/ and
                      symlink composite.$SOEXT into the module dir first.
                      Honors OPENSSL_PREFIX (default: derived from --openssl).
  --keep              Keep the temp work dir (for debugging).
  -h, --help          This help.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --openssl)    OPENSSL_BIN="$2"; shift 2;;
        --libpath)    OPENSSL_LIBPATH="$2"; shift 2;;
        --module-dir) MODULE_DIR="$2"; shift 2;;
        --build)      BUILD=1; shift;;
        --keep)       KEEP=1; shift;;
        -h|--help)    usage; exit 0;;
        *)            echo "unknown option: $1" >&2; usage; exit 2;;
    esac
done

[ -n "$OPENSSL_LIBPATH" ] && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_MODULES="$MODULE_DIR"

if [ -t 1 ]; then C_OK=$'\033[32m'; C_NO=$'\033[31m'; C_SK=$'\033[33m'; C_Z=$'\033[0m'
else C_OK=""; C_NO=""; C_SK=""; C_Z=""; fi
pass=0; fail=0; skip=0
ok()   { echo "  ${C_OK}PASS${C_Z}  $*"; pass=$((pass+1)); }
no()   { echo "  ${C_NO}FAIL${C_Z}  $*"; fail=$((fail+1)); }
note() { echo "  ${C_SK}SKIP${C_Z}  $*"; skip=$((skip+1)); }
hdr()  { echo; echo "== $* =="; }

# --- optionally build the composite-provider peer from source ----------------
build_peer() {
    local prefix src build so
    prefix="${OPENSSL_PREFIX:-}"
    if [ -z "$prefix" ]; then   # derive from the openssl binary's install prefix
        prefix="$(cd "$(dirname "$(command -v "$OPENSSL_BIN")")/.." && pwd)"
    fi
    src="$REPO/.interop/composite-provider"
    build="$src/_build"
    echo ">> building composite-provider ($COMPOSITE_REF) against $prefix"
    mkdir -p "$REPO/.interop"
    [ -d "$src/.git" ] || git clone "$COMPOSITE_REPO" "$src" || return 1
    git -C "$src" fetch --tags --force origin 2>/dev/null || true
    git -C "$src" checkout --quiet "$COMPOSITE_REF" || return 1
    cmake -S "$src" -B "$build" -DOPENSSL_ROOT_DIR="$prefix" \
        -DCMAKE_BUILD_TYPE=Release >/dev/null || return 1
    cmake --build "$build" >/dev/null || return 1
    so="$(find "$build" -name "composite.$SOEXT" -print -quit)"
    [ -n "$so" ] || { echo "!! built no composite.$SOEXT" >&2; return 1; }
    mkdir -p "$MODULE_DIR"
    ln -sf "$so" "$MODULE_DIR/composite.$SOEXT"
    echo ">> symlinked $so -> $MODULE_DIR/composite.$SOEXT"
}

[ "$BUILD" -eq 1 ] && { build_peer || { echo "!! composite-provider build failed" >&2; exit 1; }; }

# --- preflight: both provider modules must be present ------------------------
if [ ! -f "$MODULE_DIR/composite.$SOEXT" ]; then
    echo "composite.$SOEXT not found in $MODULE_DIR -- SKIPPING composite interop"
    echo "(build the peer with: $(basename "$0") --build, or point --module-dir at it)"
    exit 0
fi
if [ ! -f "$MODULE_DIR/hybrid.$SOEXT" ]; then
    echo "hybrid.$SOEXT not found in $MODULE_DIR -- build the provider first" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"; }
trap cleanup EXIT

# default-only config: composite OIDs are unregistered here, so asn1parse prints
# them as raw dotted OIDs (a loaded provider would print its registered name).
DCNF="$WORKDIR/default.cnf"
cat > "$DCNF" <<EOF
openssl_conf = c
[c]
providers = p
[p]
default = d
[d]
activate = 1
EOF

mkcnf() {   # $1 = extra provider name, $2 = module path -> echoes cnf path
    local cnf="$WORKDIR/$1.cnf"
    cat > "$cnf" <<EOF
openssl_conf = c
[c]
providers = p
[p]
default = d
$1 = x
[d]
activate = 1
[x]
module = $2
activate = 1
EOF
    echo "$cnf"
}
HCNF="$(mkcnf hybrid    "$MODULE_DIR/hybrid.$SOEXT")"
CCNF="$(mkcnf composite "$MODULE_DIR/composite.$SOEXT")"

# Composite signature-algorithm OID arc (draft-ietf-lamps-pq-composite-sigs).
ARC='1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'

# Extract the composite OID from a certificate (default-only, so unregistered
# arc OIDs print dotted). Empty for a non-composite cert.
oid_of() {
    OPENSSL_CONF="$DCNF" "$OPENSSL_BIN" asn1parse -in "$1" 2>/dev/null \
        | grep -oE "$ARC" | head -1
}

# List a usable fetch handle for each signature algorithm a provider offers.
# `list` prints either the plain form "name @ prov" (hybrid registers one name
# per algorithm) or the multi-alias brace form "{ OID, id-LN, SN } @ prov"
# (composite-provider registers OID:LN:SN). Take the first alias in either case
# — a plain name, or the OID for the brace form (both accepted by genpkey).
list_sigs() {   # $1 = cnf, $2 = provider tag as printed by `list`
    OPENSSL_CONF="$1" "$OPENSSL_BIN" list -signature-algorithms 2>/dev/null \
        | awk -v p="$2" '
            $0 ~ ("@ *" p) {
                sub(/[[:space:]]*@.*/, "");            # drop " @ prov"
                gsub(/[{}]/, "");                       # drop braces
                gsub(/^[[:space:]]+|[[:space:]]+$/, "");
                split($0, a, /[[:space:]]*,[[:space:]]*/);
                print a[1];                             # plain name, or OID
            }'
}

# Generate a self-signed cert for one algorithm; echo the cert path on success.
gen_cert() {   # $1 = cnf, $2 = alg name, $3 = tag (for filenames)
    local cnf="$1" alg="$2" d="$WORKDIR/$3_$2"
    mkdir -p "$d"
    OPENSSL_CONF="$cnf" "$OPENSSL_BIN" genpkey -algorithm "$alg" \
        -out "$d/key.pem" 2>/dev/null || return 1
    OPENSSL_CONF="$cnf" "$OPENSSL_BIN" req -x509 -key "$d/key.pem" \
        -subj "/CN=$alg" -days 1 -out "$d/cert.pem" 2>/dev/null || return 1
    echo "$d/cert.pem"
}

# Build "OID<TAB>certpath" lines for every composite cert a provider can make.
# $1 = cnf, $2 = provider tag, $3 = filename tag.
collect_certs() {
    local cnf="$1" tag="$2" ftag="$3" alg cert oid
    for alg in $(list_sigs "$cnf" "$tag"); do
        cert="$(gen_cert "$cnf" "$alg" "$ftag")" || continue
        oid="$(oid_of "$cert")"
        [ -n "$oid" ] && printf '%s\t%s\t%s\n' "$oid" "$cert" "$alg"
    done
}

hdr "Composite-signature interop: hybrid-provider <-> composite-provider"
echo "  openssl : $("$OPENSSL_BIN" version 2>/dev/null)"
echo "  modules : $MODULE_DIR"

H_MAP="$WORKDIR/h.map"; C_MAP="$WORKDIR/c.map"
collect_certs "$HCNF" hybrid    h > "$H_MAP"
collect_certs "$CCNF" composite c > "$C_MAP"

echo "  hybrid composites: $(wc -l <"$H_MAP")   composite-provider composites: $(wc -l <"$C_MAP")"

if [ ! -s "$H_MAP" ] || [ ! -s "$C_MAP" ]; then
    [ -s "$H_MAP" ] || note "hybrid produced no composite certs (no ML-DSA? needs OpenSSL 3.5+)"
    [ -s "$C_MAP" ] || note "composite-provider produced no composite certs (keygen unimplemented or component base absent)"
    echo; echo "  passed: $pass   failed: $fail   skipped: $skip"
    exit 0
fi

# Union of OIDs, then classify each.
all_oids="$(cut -f1 "$H_MAP" "$C_MAP" | sort -u)"
for oid in $all_oids; do
    hcert="$(awk -F'\t' -v o="$oid" '$1==o{print $2; exit}' "$H_MAP")"
    halg="$(awk  -F'\t' -v o="$oid" '$1==o{print $3; exit}' "$H_MAP")"
    ccert="$(awk -F'\t' -v o="$oid" '$1==o{print $2; exit}' "$C_MAP")"
    calg="$(awk  -F'\t' -v o="$oid" '$1==o{print $3; exit}' "$C_MAP")"

    if [ -z "$hcert" ]; then
        note "$oid  composite-provider-only ($calg) — no hybrid counterpart"; continue
    fi
    if [ -z "$ccert" ]; then
        note "$oid  hybrid-only ($halg) — no composite-provider counterpart"; continue
    fi

    # hybrid-produced cert must verify under composite-provider ...
    if OPENSSL_CONF="$CCNF" "$OPENSSL_BIN" verify -no_check_time \
            -CAfile "$hcert" "$hcert" >/dev/null 2>&1; then
        ok "$oid  hybrid cert ($halg) verified by composite-provider ($calg)"
    else
        no "$oid  hybrid cert ($halg) REJECTED by composite-provider ($calg)"
    fi
    # ... and composite-provider's cert must verify under hybrid-provider.
    if OPENSSL_CONF="$HCNF" "$OPENSSL_BIN" verify -no_check_time \
            -CAfile "$ccert" "$ccert" >/dev/null 2>&1; then
        ok "$oid  composite-provider cert ($calg) verified by hybrid ($halg)"
    else
        no "$oid  composite-provider cert ($calg) REJECTED by hybrid ($halg)"
    fi
done

hdr "Summary"
echo "  passed: $pass   failed: $fail   skipped: $skip"
[ "$fail" -eq 0 ]
