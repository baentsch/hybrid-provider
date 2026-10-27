#!/usr/bin/env bash
#
# pqc_kem_cms_certificates_interop.sh — composite ML-KEM CMS (KEMRI) interop
# against the IETF Hackathon PQC certificate artifact repository
# (github.com/IETF-Hackathon/pqc-certificates). This is the CMS companion to:
#   - pqc_kem_certificates_interop.sh  (raw composite-KEM DECAPS vectors), and
#   - pqc_kem_cms_interop.sh           (BOTH-WAY CMS interop vs carl-wallace's
#                                       kemri_toy, a single live peer).
#
# Here the peer is the corpus itself: each provider ships, per composite-KEM OID,
# a CMS EnvelopedData whose single recipient is a KEMRecipientInfo (RFC 9629),
# plus the recipient's PKCS#8 private key and the expected plaintext. We decrypt
# their EnvelopedData with hybrid-provider and confirm we recover that plaintext —
# "third party generated, we read", across a real implementation boundary and the
# full standardized combo matrix (the .55..66 arc, incl. brainpool .61/.64, which
# kemri_toy cannot generate).
#
# Our overlap is the LAMPS composite ML-KEM (draft-ietf-lamps-pq-composite-kem),
# whose cms_v3 artifacts use the OID arc 1.3.6.1.5.5.7.6.55..66 — exactly this
# provider's COMPOSITE_KEM_LIST. Corpus files are named
# <label>-<oid>_kemri_id-alg-hkdf-with-sha256.der (the EnvelopedData, HKDF-SHA256
# key-derivation — the draft-18 default), <label>-<oid>_priv.der (the recipient
# key) and a shared expected_plaintext.txt. The authenticated (_kemri_auth*) and
# user-keying-material (_ukm) variants are out of scope for this one-way read.
#
# Peers: providers that publish draft-18 composite-KEM KEMRI artifacts on the
# .55..66 arc. composite-crypto and bc are two independent, conformant impls (each
# a full 12/12). Others can be added with --peers; note carl-redhound tracks an
# older composite-kem draft (the kemri_toy skew — see pqc_kem_cms_interop.sh), so
# some of its combos will not interop with our -18 combiner and it is not a default.
#
# Floors / behaviour (opt-in harness; NOT wired into ctest — needs network + the
# external corpus + a KEMRI-capable OpenSSL):
#   - OpenSSL 3.6.0+ : CMS KEM-recipient auto-selection (the encapsulate_init probe
#     in ossl_cms_pkey_get_ri_type) landed in 3.6.0 with KEMRI (commit d0899abb,
#     PR 27681); 3.5 defaults a KEM key to key transport. Below 3.6 we self-skip.
#   - Composite components (ML-KEM + RSA/ECDH/X25519/X448) come from the default
#     provider (3.5+); the composite OIDs come from hybrid-provider.
# Everything self-skips (exit 0) when a peer zip cannot be fetched or a component
# is unavailable; a shared OID whose EnvelopedData does NOT decrypt to the peer's
# expected plaintext is a real FAIL.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-$REPO/build}"
VER="${VER:-v3}"
# Two independent draft-18 impls that ship the full .55..66 KEMRI matrix. Override
# with --peers; a peer without composite-arc KEMRI artifacts self-skips, so
# widening the list is harmless (but an older-draft peer may FAIL on skew).
PEERS="${PEERS:-composite-crypto bc}"
RAW_BASE="https://raw.githubusercontent.com/IETF-Hackathon/pqc-certificates/master/providers"
KEEP=0

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SOEXT="${SOEXT:-dll}";;
    Darwin)               SOEXT="${SOEXT:-dylib}";;
    *)                    SOEXT="${SOEXT:-so}";;
esac

usage() { sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'; cat <<EOF

Usage: $(basename "$0") [options]

Options:
  --openssl PATH    openssl binary (must be 3.6.0+)   (default: $OPENSSL_BIN)
  --libpath PATH    LD_LIBRARY_PATH for its libs      (default: none)
  --module-dir DIR  OPENSSL_MODULES with hybrid.$SOEXT (default: $MODULE_DIR)
  --peers "a b c"   provider dirs to verify           (default: $PEERS)
  --version V       cms corpus version (artifacts_cms_<V>.zip) (default: $VER)
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
        --version)    VER="$2"; shift 2;;
        --keep)       KEEP=1; shift;;
        -h|--help)    usage; exit 0;;
        *) echo "unknown argument: $1" >&2; usage; exit 2;;
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
skip_all() { echo "SKIP: $*"; exit 0; }

# ---- prerequisites (clean self-skip) -----------------------------------------
"$OPENSSL_BIN" version >/dev/null 2>&1 || skip_all "openssl ($OPENSSL_BIN) not runnable"
ver="$("$OPENSSL_BIN" version 2>/dev/null)"
major="$(printf '%s' "$ver" | sed -nE 's/^OpenSSL ([0-9]+)\..*/\1/p')"
minor="$(printf '%s' "$ver" | sed -nE 's/^OpenSSL [0-9]+\.([0-9]+)\..*/\1/p')"
# CMS KEMRI (RFC 9629) first shipped in 3.6.0; accept >= 3.6.
[ -n "$major" ] && { [ "$major" -ge 4 ] 2>/dev/null \
    || { [ "$major" -eq 3 ] && [ "${minor:-0}" -ge 6 ]; } 2>/dev/null; } \
    || skip_all "need OpenSSL 3.6.0+ for CMS KEMRI (have: ${ver:-unknown})"
[ -f "$MODULE_DIR/hybrid.$SOEXT" ] || skip_all "hybrid.$SOEXT not found in $MODULE_DIR"

WORKDIR="$(mktemp -d)"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"; }
trap cleanup EXIT

# default + hybrid: default supplies ML-KEM / RSA / ECDH / X components, hybrid
# supplies the composite algorithm (which owns the composite-KEM OIDs).
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

# ---- verify: third-party EnvelopedData decrypted by hybrid-provider ----------
verify_peer() {   # $1 = provider dir name
    local peer="$1" zip="$WORKDIR/$1.zip" d="$WORKDIR/$1" n=0 p=0 exp blob
    if ! curl -fsSL "$RAW_BASE/$peer/artifacts_cms_$VER.zip" -o "$zip" 2>/dev/null \
            || [ ! -s "$zip" ]; then
        note "$peer: no artifacts_cms_$VER.zip (unreachable / absent)"; return
    fi
    mkdir -p "$d"; unzip -qo "$zip" -d "$d" 2>/dev/null
    exp="$(find "$d" -type f -name expected_plaintext.txt | head -1)"
    if [ -z "$exp" ]; then
        note "$peer: no expected_plaintext.txt in cms_$VER (cannot assert content)"; return
    fi
    : > "$WORKDIR/$peer.oids"
    # One EnvelopedData per composite-KEM OID (HKDF-SHA256 KEMRI; exclude the
    # authenticated and user-keying-material variants). Standalone ML-KEM entries
    # (OID arc 2.16.840... / BC vendor arc) do not match ARC and are ignored.
    while IFS= read -r blob; do
        local base oid priv out
        base="${blob%_kemri_id-alg-hkdf-with-sha256.der}"
        oid="$(echo "$base" | grep -oE "$ARC" | head -1)"; [ -z "$oid" ] && continue
        n=$((n+1))
        priv="${base}_priv.der"
        if [ ! -f "$priv" ]; then
            no "$peer: $oid missing _priv.der"; continue
        fi
        out="$WORKDIR/$(basename "$base").out"
        if oss cms -decrypt -inform DER -in "$blob" -inkey "$priv" -keyform DER \
                -out "$out" >/dev/null 2>&1 && cmp -s "$out" "$exp"; then
            p=$((p+1)); echo "$oid" >> "$WORKDIR/$peer.oids"
            echo "$oid" >> "$WORKDIR/verified_oids"
        else
            no "$peer: $oid ($(basename "$base")) did not decrypt to expected plaintext"
        fi
    done < <(find "$d" -type f -name '*_kemri_id-alg-hkdf-with-sha256.der' \
                | grep -v '_kemri_auth' | grep -E "$ARC" | sort)
    if [ "$n" -eq 0 ]; then
        note "$peer: no composite-KEM ($ARC) KEMRI artifacts in cms_$VER"
    else
        local dist; dist=$(sort -u "$WORKDIR/$peer.oids" | wc -l)
        ok "$peer: $dist/12 composite-KEM OIDs decrypted to the peer's plaintext ($p/$n blobs)"
    fi
}

hdr "Read/verify: pqc-certificates composite ML-KEM CMS (KEMRI) decrypted by hybrid-provider"
echo "  corpus: cms_$VER   openssl: $ver"
: > "$WORKDIR/verified_oids"
for peer in $PEERS; do verify_peer "$peer"; done
if [ -s "$WORKDIR/verified_oids" ]; then
    echo "  distinct composite-KEM OIDs decrypted from >=1 peer: \
$(sort -u "$WORKDIR/verified_oids" | wc -l)/12"
fi

hdr "Summary"
echo "  passed: $pass   failed: $fail   skipped: $skip"
[ "$fail" -eq 0 ]
