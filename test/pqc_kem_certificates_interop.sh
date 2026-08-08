#!/usr/bin/env bash
#
# pqc_kem_certificates_interop.sh — composite ML-KEM interop against the IETF
# Hackathon PQC certificate artifact repository
# (github.com/IETF-Hackathon/pqc-certificates), the KEM companion to
# pqc_certificates_interop.sh (issue #31, which covers composite ML-DSA sigs).
#
# Our overlap is the LAMPS composite ML-KEM (draft-ietf-lamps-pq-composite-kem),
# whose r5 artifacts use the OID arc 1.3.6.1.5.5.7.6.55..66 — exactly this
# provider's COMPOSITE_KEM_LIST. Unlike a signature, a KEM public key cannot
# self-sign a trust anchor, so the interop is a DECAPSULATION check rather than a
# certificate verify: the reference provider ships, per OID, its serialized
# private key + a ciphertext + the expected shared secret; we decapsulate their
# ciphertext with their key and confirm we recover their secret.
#
# Peers: every provider in the corpus that publishes composite-KEM decaps vectors
# for this spec level (the .55..66 arc). composite-kem-ref-impl is the LAMPS
# conformance oracle and is listed first; the others are independent third-party
# implementations (BouncyCastle et al.). Providers that ship the KEM only as a
# public-key cert (no private key + ciphertext + shared secret) cannot be checked
# by decapsulation and are reported as SKIP. Override the set with --peers.
#
# Modes:
#   verify    (default) Download each peer's artifacts_certs_<round>.zip and, for
#             every composite-KEM OID that ships a decaps vector, load its PKCS#8
#             private key with hybrid-provider, decapsulate its ciphertext, and
#             check the recovered shared secret equals its published one — i.e.
#             "third party generated, we read". Reports a per-peer matrix.
#   generate  Produce THIS provider's composite ML-KEM artifacts (PKCS#8 _priv.der,
#             SPKI _pub.der, plus a self-encapsulated _ciphertext.bin + _ss.bin) in
#             the repo's r5 flat naming, then self-verify by decapsulating. This is
#             the set to submit as providers/hybrid-provider/ so others verify us.
#   all       verify, then generate.
#
# Composite components (ML-KEM + RSA/ECDH/X25519/X448) come from the default
# provider (OpenSSL 3.5+). Everything self-skips (exit 0) when the peer zip cannot
# be fetched or a component is unavailable; a shared OID that fails to decapsulate
# to the reference secret is a real FAIL. Not wired into ctest (needs network + an
# external corpus).
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-$REPO/build}"
ROUND="${ROUND:-r5}"
# composite-kem-ref-impl (LAMPS reference) first, then the third-party providers
# that publish composite-KEM decaps vectors in the r5 round. Override with --peers;
# a peer without decaps vectors self-skips, so widening this list is harmless.
PEERS="${PEERS:-composite-kem-ref-impl bc cht crypto4a cryptonext entrust}"
RAW_BASE="https://raw.githubusercontent.com/IETF-Hackathon/pqc-certificates/master/providers"
OUTDIR=""
KEEP=0
MODE="verify"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SOEXT="${SOEXT:-dll}";;
    Darwin)               SOEXT="${SOEXT:-dylib}";;
    *)                    SOEXT="${SOEXT:-so}";;
esac

usage() { sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; cat <<EOF

Usage: $(basename "$0") [options] [verify|generate|all]

Options:
  --openssl PATH    openssl binary            (default: $OPENSSL_BIN)
  --libpath PATH    LD_LIBRARY_PATH for libs  (default: none)
  --module-dir DIR  OPENSSL_MODULES with hybrid.$SOEXT (default: $MODULE_DIR)
  --peers "a b c"   provider dirs to verify   (default: $PEERS)
  --round R         artifact round            (default: $ROUND)
  --outdir DIR      generate output dir       (default: <module-dir>/pqc-kem-artifacts)
  --keep            keep the temp work dir
  -h, --help        this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --openssl)    OPENSSL_BIN="$2"; shift 2;;
        --libpath)    OPENSSL_LIBPATH="$2"; shift 2;;
        --module-dir) MODULE_DIR="$2"; shift 2;;
        --peers)      PEERS="$2"; shift 2;;
        --round)      ROUND="$2"; shift 2;;
        --outdir)     OUTDIR="$2"; shift 2;;
        --keep)       KEEP=1; shift;;
        -h|--help)    usage; exit 0;;
        verify|generate|all) MODE="$1"; shift;;
        *) echo "unknown argument: $1" >&2; usage; exit 2;;
    esac
done
: "${OUTDIR:=$MODULE_DIR/pqc-kem-artifacts}"

[ -n "$OPENSSL_LIBPATH" ] && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_MODULES="$MODULE_DIR"

if [ -t 1 ]; then C_OK=$'\033[32m'; C_NO=$'\033[31m'; C_SK=$'\033[33m'; C_Z=$'\033[0m'
else C_OK=""; C_NO=""; C_SK=""; C_Z=""; fi
pass=0; fail=0; skip=0
ok()   { echo "  ${C_OK}PASS${C_Z}  $*"; pass=$((pass+1)); }
no()   { echo "  ${C_NO}FAIL${C_Z}  $*"; fail=$((fail+1)); }
note() { echo "  ${C_SK}SKIP${C_Z}  $*"; skip=$((skip+1)); }
hdr()  { echo; echo "== $* =="; }

if [ ! -f "$MODULE_DIR/hybrid.$SOEXT" ]; then
    echo "hybrid.$SOEXT not found in $MODULE_DIR -- build the provider first" >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"; }
trap cleanup EXIT

# default + hybrid: default supplies the ML-KEM / RSA / ECDH / X components,
# hybrid supplies the composite algorithm (which owns the composite-KEM OIDs).
HCNF="$WORKDIR/hybrid.cnf"
cat > "$HCNF" <<EOF
openssl_conf = c
[c]
providers = p
[p]
default = d
hybrid = x
[d]
activate = 1
[x]
module = $MODULE_DIR/hybrid.$SOEXT
activate = 1
EOF

ARC='1\.3\.6\.1\.5\.5\.7\.6\.(5[5-9]|6[0-6])'   # LAMPS composite-KEM OID arc
oss() { OPENSSL_CONF="$HCNF" "$OPENSSL_BIN" "$@"; }

# ---- verify: third-party decaps vectors read + checked by hybrid-provider -----
verify_peer() {   # $1 = provider dir name
    local peer="$1" zip="$WORKDIR/$1.zip" d="$WORKDIR/$1" n=0 p=0
    if ! curl -fsSL "$RAW_BASE/$peer/artifacts_certs_$ROUND.zip" -o "$zip" 2>/dev/null \
            || [ ! -s "$zip" ]; then
        note "$peer: no artifacts_certs_$ROUND.zip (unreachable / absent)"; return
    fi
    mkdir -p "$d"; unzip -qo "$zip" -d "$d" 2>/dev/null
    : > "$WORKDIR/$peer.oids"
    # One shared-secret file per composite-KEM OID; standalone ML-KEM entries
    # (OID arc 2.16.840...) do not match ARC and are ignored.
    while IFS= read -r ss; do
        local base oid priv ct out
        base="${ss%_ss.bin}"
        oid="$(echo "$base" | grep -oE "$ARC" | head -1)"; [ -z "$oid" ] && continue
        n=$((n+1))
        priv="${base}_priv.der"; ct="${base}_ciphertext.bin"
        if [ ! -f "$priv" ] || [ ! -f "$ct" ]; then
            no "$peer: $oid missing _priv.der / _ciphertext.bin"; continue
        fi
        out="$WORKDIR/$(basename "$base").out"
        if oss pkeyutl -decap -inkey "$priv" -keyform DER -in "$ct" \
                -secret "$out" >/dev/null 2>&1 && cmp -s "$out" "$ss"; then
            p=$((p+1)); echo "$oid" >> "$WORKDIR/$peer.oids"
            echo "$oid" >> "$WORKDIR/verified_oids"
        else
            no "$peer: $oid ($(basename "$base")) did not decapsulate to its secret"
        fi
    done < <(find "$d" -type f -name '*_ss.bin' | grep -E "$ARC" | sort)
    if [ "$n" -eq 0 ]; then
        note "$peer: no composite-KEM ($ARC) decaps vectors in $ROUND (certs-only or none)"
    else
        local dist; dist=$(sort -u "$WORKDIR/$peer.oids" | wc -l)
        ok "$peer: $dist/12 composite-KEM OIDs decapsulated to the peer's secret ($p/$n vectors)"
    fi
}

cmd_verify() {
    hdr "Read/verify: pqc-certificates composite ML-KEM decaps vectors checked by hybrid-provider"
    echo "  round: $ROUND   openssl: $("$OPENSSL_BIN" version 2>/dev/null)"
    : > "$WORKDIR/verified_oids"
    local peer
    for peer in $PEERS; do verify_peer "$peer"; done
    if [ -s "$WORKDIR/verified_oids" ]; then
        echo "  distinct composite-KEM OIDs verified from >=1 peer: \
$(sort -u "$WORKDIR/verified_oids" | wc -l)/12"
    fi
}

# ---- generate: our own artifacts in the repo's r5 flat naming ----------------
cmd_generate() {
    hdr "Generate: hybrid-provider composite ML-KEM artifacts (r5 layout) + self-verify"
    mkdir -p "$OUTDIR"
    local alg n=0 p=0
    # Identify composites by the LAMPS OID arc, not a name convention: iterate the
    # KEM algorithms the provider offers, keep those whose public key encodes to a
    # composite-arc OID (the concat MLX/oqs hybrid KEMs have no SPKI OID and drop).
    for alg in $(oss list -kem-algorithms 2>/dev/null \
            | awk '/@ *hybrid/ { gsub(/^ +/,""); sub(/ .*/,""); print }'); do
        local key="$WORKDIR/$alg.key" pub="$WORKDIR/$alg.pub" oid base
        oss genpkey -algorithm "$alg" -out "$key" 2>/dev/null || continue
        oss pkey -in "$key" -pubout -outform DER -out "$pub" 2>/dev/null || continue
        oid="$("$OPENSSL_BIN" asn1parse -inform DER -in "$pub" 2>/dev/null \
               | grep -oE "$ARC" | head -1)"
        [ -z "$oid" ] && continue     # OID outside the composite-KEM arc
        n=$((n+1)); base="$OUTDIR/id-$alg-$oid"
        oss pkey -in "$key" -outform DER -out "${base}_priv.der" 2>/dev/null
        cp "$pub" "${base}_pub.der"
        oss pkeyutl -encap -inkey "$pub" -pubin -keyform DER \
            -out "${base}_ciphertext.bin" -secret "${base}_ss.bin" 2>/dev/null
        # Round-trip: decapsulating our own ciphertext must recover our secret.
        local chk="$WORKDIR/$alg.chk"
        if oss pkeyutl -decap -inkey "${base}_priv.der" -keyform DER \
                -in "${base}_ciphertext.bin" -secret "$chk" 2>/dev/null \
                && cmp -s "$chk" "${base}_ss.bin"; then
            p=$((p+1))
        else
            no "$alg ($oid) self-decapsulation of generated ciphertext"
        fi
    done
    if [ "$n" -eq 0 ]; then
        note "no composite-KEM algorithms available (needs OpenSSL 3.5+ ML-KEM + composite build)"
    else
        ok "generated + self-verified $p/$n composite ML-KEM artifacts -> $OUTDIR"
        echo "       (submit these under providers/hybrid-provider/ so peers can"
        echo "        decapsulate our ciphertexts and check our shared secrets)"
    fi
}

case "$MODE" in
    verify)   cmd_verify;;
    generate) cmd_generate;;
    all)      cmd_verify; cmd_generate;;
esac

hdr "Summary ($MODE)"
echo "  passed: $pass   failed: $fail   skipped: $skip"
[ "$fail" -eq 0 ]
