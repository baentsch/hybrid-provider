#!/usr/bin/env bash
#
# pqc_certificates_interop.sh — interop against the IETF Hackathon PQC
# certificate artifact repository (github.com/IETF-Hackathon/pqc-certificates).
#
# That repo is the canonical multi-vendor X.509 interop corpus: each provider
# uploads self-signed trust-anchor certs (+ keys) per algorithm/OID, and CI
# cross-verifies everyone against everyone. Our overlap is the LAMPS composite
# ML-DSA signatures (draft-ietf-lamps-pq-composite-sigs), whose r5 artifacts use
# the OID arc 1.3.6.1.5.5.7.6.37..54 — exactly this provider's COMPOSITE_SIG_LIST.
#
# Modes:
#   verify    (default) Download each peer's artifacts_certs_<round>.zip and
#             verify every composite trust-anchor cert (matched by OID) with
#             hybrid-provider — i.e. "third party generated, we read". Reports a
#             per-peer pass/fail matrix.
#   generate  Produce THIS provider's composite artifacts (self-signed _ta cert
#             in DER+PEM and a PKCS#8 _priv key) in the repo's r5 flat naming,
#             then self-verify them. This is the set to zip as
#             artifacts_certs_r5.zip for a providers/hybrid-provider/ submission,
#             so the repo's CI (OQS docker + other providers) can verify US —
#             the reverse direction, run there rather than here.
#   all       verify, then generate.
#
# Composite components (ML-DSA + RSA/ECDSA/EdDSA) come from the default provider
# (OpenSSL 3.5+). Everything self-skips (exit 0) when a peer zip cannot be
# fetched or a component is unavailable; a shared OID that fails to verify is a
# real FAIL. Not wired into ctest (needs network + an external corpus).
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-$REPO/build}"
ROUND="${ROUND:-r5}"
PEERS="${PEERS:-composite-sigs-ref-impl bc ossl35 openssl-composite-preliminary-impl composite-crypto}"
RAW_BASE="https://raw.githubusercontent.com/IETF-Hackathon/pqc-certificates/master/providers"
OUTDIR=""
KEEP=0
MODE="verify"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SOEXT="${SOEXT:-dll}";;
    Darwin)               SOEXT="${SOEXT:-dylib}";;
    *)                    SOEXT="${SOEXT:-so}";;
esac

usage() { sed -n '3,38p' "$0" | sed 's/^# \{0,1\}//'; cat <<EOF

Usage: $(basename "$0") [options] [verify|generate|all]

Options:
  --openssl PATH    openssl binary            (default: $OPENSSL_BIN)
  --libpath PATH    LD_LIBRARY_PATH for libs  (default: none)
  --module-dir DIR  OPENSSL_MODULES with hybrid.$SOEXT (default: $MODULE_DIR)
  --peers "a b c"   provider dirs to verify   (default: $PEERS)
  --round R         artifact round            (default: $ROUND)
  --outdir DIR      generate output dir       (default: <module-dir>/pqc-artifacts)
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
: "${OUTDIR:=$MODULE_DIR/pqc-artifacts}"

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

# default + hybrid: default supplies the ML-DSA / RSA / ECDSA / EdDSA components,
# hybrid supplies the composite algorithm (which owns the composite OIDs).
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

ARC='1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'          # LAMPS composite-signature OID arc
oss() { OPENSSL_CONF="$HCNF" "$OPENSSL_BIN" "$@"; }

# ---- verify: third-party artifacts read + verified by hybrid-provider --------
verify_peer() {   # $1 = provider dir name
    local peer="$1" d="$WORKDIR/$1" zip="$WORKDIR/$1.zip" n=0 p=0
    if ! curl -fsSL "$RAW_BASE/$peer/artifacts_certs_$ROUND.zip" -o "$zip" 2>/dev/null \
            || [ ! -s "$zip" ]; then
        note "$peer: no artifacts_certs_$ROUND.zip (unreachable / absent)"; return
    fi
    mkdir -p "$d"; unzip -qo "$zip" -d "$d" 2>/dev/null
    # Composite trust-anchor certs, matched by the arc OID in the filename.
    while IFS= read -r ta; do
        local oid pem
        oid="$(echo "$ta" | grep -oE "$ARC" | head -1)"; [ -z "$oid" ] && continue
        n=$((n+1)); pem="$ta.pem"
        oss x509 -inform DER -in "$ta" -out "$pem" 2>/dev/null || pem="$ta"
        if oss verify -no_check_time -CAfile "$pem" "$pem" >/dev/null 2>&1; then
            p=$((p+1)); echo "$oid" >> "$WORKDIR/verified_oids"
        else
            no "$peer: $oid ($(basename "$ta")) not verified by hybrid-provider"
        fi
    done < <(find "$d" -type f -name '*_ta.der' | grep -E "$ARC" | sort)
    if [ "$n" -eq 0 ]; then
        note "$peer: no composite ($ARC) trust-anchor certs in $ROUND"
    else
        ok "$peer: $p/$n composite trust-anchor certs verified by hybrid-provider"
    fi
}

cmd_verify() {
    hdr "Read/verify: pqc-certificates composite certs verified by hybrid-provider"
    echo "  round: $ROUND   openssl: $("$OPENSSL_BIN" version 2>/dev/null)"
    : > "$WORKDIR/verified_oids"
    local peer
    for peer in $PEERS; do verify_peer "$peer"; done
    if [ -s "$WORKDIR/verified_oids" ]; then
        echo "  distinct composite OIDs verified from >=1 peer: \
$(sort -u "$WORKDIR/verified_oids" | wc -l)/18"
    fi
}

# ---- generate: our own artifacts in the repo's r5 flat naming ----------------
cmd_generate() {
    hdr "Generate: hybrid-provider composite artifacts (r5 layout) + self-verify"
    mkdir -p "$OUTDIR"
    local alg n=0 p=0
    # Identify composites by the official LAMPS OID arc, not by a name convention:
    # iterate every signature algorithm the provider offers, and keep only those
    # whose generated certificate carries a composite-arc OID. Non-composite sigs
    # (concat hybrids, whose OID is outside the arc) and any needing an absent
    # component simply drop out — nothing here assumes how composites are named.
    for alg in $(oss list -signature-algorithms 2>/dev/null \
            | awk '/@ *hybrid/ { gsub(/^ +/,""); print $1 }'); do
        local key="$WORKDIR/$alg.key" crt="$WORKDIR/$alg.crt" oid base
        oss genpkey -algorithm "$alg" -out "$key" 2>/dev/null || continue
        oss req -x509 -key "$key" -subj "/CN=hybrid-provider $alg" -days 3650 \
            -out "$crt" 2>/dev/null || continue
        oid="$(oss x509 -in "$crt" -outform DER 2>/dev/null \
               | "$OPENSSL_BIN" asn1parse -inform DER 2>/dev/null \
               | grep -oE "$ARC" | head -1)"
        [ -z "$oid" ] && continue     # OID outside the composite arc -> not composite
        n=$((n+1)); base="$OUTDIR/id-$alg-$oid"
        oss x509 -in "$crt" -outform DER -out "${base}_ta.der" 2>/dev/null
        cp "$crt" "${base}_ta.pem"
        oss pkey -in "$key" -outform DER -out "${base}_priv.der" 2>/dev/null
        # Round-trip: our own trust anchor must verify under hybrid-provider.
        if oss verify -no_check_time -CAfile "${base}_ta.pem" "${base}_ta.pem" \
                >/dev/null 2>&1; then
            p=$((p+1))
        else
            no "$alg ($oid) self-verify of generated trust anchor"
        fi
    done
    if [ "$n" -eq 0 ]; then
        note "no composite algorithms available (needs OpenSSL 3.5+ ML-DSA + composite build)"
    else
        ok "generated + self-verified $p/$n composite artifacts -> $OUTDIR"
        echo "       (zip these as artifacts_certs_$ROUND.zip for a"
        echo "        providers/hybrid-provider/ submission to have others verify us)"
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
