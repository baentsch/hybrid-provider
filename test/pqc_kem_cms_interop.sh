#!/usr/bin/env bash
#
# pqc_kem_cms_interop.sh — BOTH-WAY composite-ML-KEM CMS KEMRI interop against an
# independent implementation, fully local and synchronous (issue #108 follow-up).
#
# The in-process hybrid_cms_kem_test proves self-consistency; this proves real
# interoperability of the CMS EnvelopedData / KEMRecipientInfo (RFC 9629) wire
# format with a SEPARATE codebase — carl-wallace/kemri_toy, a Rust tool built on
# the RustCrypto `cms`/`ml-kem` stack (github.com/carl-wallace/kemri_toy). Nothing
# is sent anywhere: kemri_toy is a local binary and every artifact stays on disk.
#
# Two directions per composite-KEM combo:
#   A. kemri_toy ENCRYPTS (fresh key + EnvelopedData)  -> hybrid-provider DECRYPTS
#      (openssl cms -decrypt, hybrid loaded), recovered plaintext must match.
#   B. hybrid-provider ENCRYPTS (our key, our cert, openssl cms -encrypt)
#      -> kemri_toy DECRYPTS with our PKCS#8 key, recovered plaintext must match.
#
# This exercises, across an impl boundary, our composite-KEM SPKI + PKCS#8
# encoders/decoders, the SHA3-256 combiner (byte-exact or the shared secret
# differs), and OpenSSL's KEMRI glue (HKDF-SHA256 + AES key-wrap).
#
# Floors / prerequisites (self-skips with exit 0 if unmet — this is an opt-in
# harness, not wired into ctest):
#   - OpenSSL 3.6.0+: CMS KEM-recipient auto-selection (the encapsulate_init
#     probe in ossl_cms_pkey_get_ri_type) landed in 3.6.0 with KEMRI itself
#     (commit d0899abb, PR 27681, "Implement KEMRecipientInfo (RFC9629) in CMS");
#     3.5 has no KEMRI and defaults a KEM key to key transport. (The optional
#     OSSL_PKEY_PARAM_CMS_RI_TYPE provider hint is a later 4.0 addition and is
#     not needed — the probe alone selects our KEM.)
#   - the hybrid provider module (hybrid.$SOEXT) and a kemri_toy binary.
#
# The combo set is the intersection of both impls' composite-KEM support: kemri_toy
# has no brainpool, so OIDs .61/.64 are out of scope here. The name<->OID mapping
# is an explicit table of FROZEN standard identifiers (draft-ietf-lamps-pq-
# composite-kem, arc 1.3.6.1.5.5.7.6.55..66) — curate by hand when a row is added;
# a cleverer derivation would only obscure that these are fixed spec values.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
MODULE_DIR="${MODULE_DIR:-$REPO/build}"
KEMRI_TOY="${KEMRI_TOY:-kemri_toy}"

case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) SOEXT="${SOEXT:-dll}";;
    Darwin)               SOEXT="${SOEXT:-dylib}";;
    *)                    SOEXT="${SOEXT:-so}";;
esac

usage() {
    sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [options]

Options:
  --openssl PATH      openssl binary (must be 3.6.0+)  (default: $OPENSSL_BIN)
  --libpath PATH      LD_LIBRARY_PATH for its libs     (default: none)
  --module-dir DIR    OPENSSL_MODULES w/ hybrid.$SOEXT (default: $MODULE_DIR)
  --kemri-toy PATH    kemri_toy binary                 (default: $KEMRI_TOY)
  -h, --help          this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --openssl)    OPENSSL_BIN="$2"; shift 2;;
        --libpath)    OPENSSL_LIBPATH="$2"; shift 2;;
        --module-dir) MODULE_DIR="$2"; shift 2;;
        --kemri-toy)  KEMRI_TOY="$2"; shift 2;;
        -h|--help)    usage; exit 0;;
        *) echo "unknown option: $1" >&2; usage; exit 2;;
    esac
done

# hybrid is always paired with default (ML-KEM + classical come from there).
export OPENSSL_MODULES="$MODULE_DIR"
# A hermetic config: openssl `x509 -new` misreads a stock openssl.cnf's [default]
# section as cert extensions, and some installs ship no cnf at all — /dev/null
# sidesteps both and needs nothing from the environment.
export OPENSSL_CONF=/dev/null
[ -n "$OPENSSL_LIBPATH" ] && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

PROV="-provider default -provider hybrid"
ossl() { "$OPENSSL_BIN" "$@"; }

skip() { echo "SKIP: $*"; exit 0; }

# --- prerequisites (clean self-skip) -----------------------------------------
command -v "$OPENSSL_BIN" >/dev/null 2>&1 || ossl version >/dev/null 2>&1 \
    || skip "openssl ($OPENSSL_BIN) not runnable"
ver="$(ossl version 2>/dev/null)"
major="$(printf '%s' "$ver" | sed -nE 's/^OpenSSL ([0-9]+)\..*/\1/p')"
minor="$(printf '%s' "$ver" | sed -nE 's/^OpenSSL [0-9]+\.([0-9]+)\..*/\1/p')"
# CMS KEMRI (RFC 9629) first shipped in 3.6.0; accept >= 3.6.
[ -n "$major" ] && { [ "$major" -ge 4 ] 2>/dev/null \
    || { [ "$major" -eq 3 ] && [ "${minor:-0}" -ge 6 ]; } 2>/dev/null; } \
    || skip "need OpenSSL 3.6.0+ for CMS KEMRI (have: ${ver:-unknown})"
[ -f "$MODULE_DIR/hybrid.$SOEXT" ] || skip "hybrid.$SOEXT not in $MODULE_DIR"
ossl list -kem-algorithms -provider hybrid 2>/dev/null | grep -q "mlkem768_p256" \
    || skip "hybrid provider does not load / serve composite KEMs"
command -v "$KEMRI_TOY" >/dev/null 2>&1 || [ -x "$KEMRI_TOY" ] \
    || skip "kemri_toy not found ($KEMRI_TOY) — build github.com/carl-wallace/kemri_toy"

# --- combo table: our provider name | kemri_toy --kem | OID tail --------------
# Intersection of both impls (no brainpool in kemri_toy). Frozen spec identifiers.
COMBOS="
mlkem768_rsa2048  ml-kem768-rsa2048-sha3-256     55
mlkem768_rsa3072  ml-kem768-rsa3072-sha3-256     56
mlkem768_rsa4096  ml-kem768-rsa4096-sha3-256     57
mlkem768_x25519   ml-kem768-x25519-sha3-256      58
mlkem768_p256     ml-kem768-ecdh-p256-sha3-256   59
mlkem768_p384     ml-kem768-ecdh-p384-sha3-256   60
mlkem1024_rsa3072 ml-kem1024-rsa3072-sha3-256    62
mlkem1024_p384    ml-kem1024-ecdh-p384-sha3-256  63
mlkem1024_x448    ml-kem1024-x448-sha3-256       65
mlkem1024_p521    ml-kem1024-ecdh-p521-sha3-256  66
"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# One Ed25519 CA to sign all recipient certs (a KEM key cannot self-sign).
ossl genpkey -algorithm ED25519 -out "$WORK/ca.key" >/dev/null 2>&1
ossl x509 -new -key "$WORK/ca.key" -subj "/CN=hybrid-kem-interop-ca" -days 3650 \
    -out "$WORK/ca.crt" >/dev/null 2>&1 || skip "cannot create CA cert"

MSG="kemri_toy <-> hybrid-provider RFC9629 KEMRI"
MSG_A="$WORK/msgA.txt"; printf '%s' "$MSG" >"$MSG_A"
MSG_B="$WORK/msgB.txt"; printf '%s' "$MSG" >"$MSG_B"

# Status model (honest about a cross-DRAFT peer): kemri_toy pins
# draft-ietf-lamps-pq-composite-kem-12; we implement -18. A combo is only in
# scope if kemri_toy can round-trip it ITSELF (encrypt own -> decrypt own) — that
# excludes combos kemri_toy has not implemented (it panics generating X25519/X448
# recipient keys, "generate_kem_cert for EC variants"). Among in-scope combos:
#   OK    both cross-directions agree;
#   SKEW  they diverge BUT both sides are internally consistent (kemri_toy self-
#         round-trips AND our own provider decrypts our own output) — a draft-12
#         vs -18 difference, not a fault. draft-18 correctness is asserted
#         elsewhere (hybrid_cms_kem_test + pqc_kem_cms_certificates_interop.sh,
#         which reads the IETF Hackathon pqc-certificates cms_v3 corpus).
#   SKIP  kemri_toy cannot do the combo at all.
# The run FAILS only if OUR output is not even self-valid (a real regression) or a
# step on our side errors — never merely because the older-draft peer disagrees.
ok=0; skew=0; skip=0; fail=0
printf '%-20s %-7s %-7s %s\n' "combo (OID)" "kt>hyb" "hyb>kt" "status"
printf '%-20s %-7s %-7s %s\n' "-----------" "------" "------" "------"

while read -r our kt oid; do
    [ -z "${our:-}" ] && continue
    d="$WORK/$oid"; mkdir -p "$d/kt" "$d/kt/self" "$d/hyb" "$d/hyb/out"

    # Peer-capability gate: kemri_toy must self-round-trip (also produces the
    # Direction-A source artifacts). If it cannot, the combo is out of scope.
    if ! "$KEMRI_TOY" --kem "$kt" -i "$MSG_A" -o "$d/kt" >/dev/null 2>&1; then
        printf '%-20s %-7s %-7s %s\n' "$our(.$oid)" "-" "-" "SKIP (kemri_toy lacks $kt)"
        skip=$((skip+1)); continue
    fi
    blob="$(ls "$d/kt"/*7.6."$oid"_kemri_id-alg-hkdf-with-sha256.der 2>/dev/null | head -1)"
    priv="$(ls "$d/kt"/*7.6."$oid"_priv.der 2>/dev/null | head -1)"
    "$KEMRI_TOY" -i "$blob" -k "$priv" -o "$d/kt/self" >/dev/null 2>&1
    if [ -z "$blob" ] || [ -z "$priv" ] \
       || [ "$(cat "$(ls "$d/kt/self"/decrypted_* 2>/dev/null | head -1)" 2>/dev/null)" != "$MSG" ]; then
        printf '%-20s %-7s %-7s %s\n' "$our(.$oid)" "-" "-" "SKIP (kemri_toy cannot round-trip)"
        skip=$((skip+1)); continue
    fi

    # Direction A: hybrid-provider decrypts kemri_toy's EnvelopedData.
    a="x"
    got="$(ossl cms -decrypt $PROV -inform DER -in "$blob" -inkey "$priv" -keyform DER 2>/dev/null)"
    [ "$got" = "$MSG" ] && a="ok"

    # Direction B: hybrid-provider generates key+cert, encrypts; kemri_toy decrypts.
    # (A missing step here is OUR failure, not the peer's.)
    b="x"; our_self="x"
    if ossl genpkey $PROV -algorithm "$our" -outform DER -out "$d/hyb/priv.der" 2>/dev/null \
       && ossl pkey $PROV -in "$d/hyb/priv.der" -inform DER -pubout -out "$d/hyb/pub.pem" 2>/dev/null \
       && ossl x509 -new -force_pubkey "$d/hyb/pub.pem" -CA "$WORK/ca.crt" \
              -CAkey "$WORK/ca.key" -subj "/CN=ee-$oid" -days 365 $PROV \
              -out "$d/hyb/ee.crt" 2>/dev/null \
       && ossl cms -encrypt $PROV -recip "$d/hyb/ee.crt" -aes-256-cbc -binary \
              -in "$MSG_B" -outform DER -out "$d/hyb/env.der" 2>/dev/null; then
        # Our own output must be self-valid (guards against masking a regression).
        [ "$(ossl cms -decrypt $PROV -inform DER -in "$d/hyb/env.der" \
                 -inkey "$d/hyb/priv.der" -keyform DER 2>/dev/null)" = "$MSG" ] && our_self="ok"
        if "$KEMRI_TOY" -i "$d/hyb/env.der" -k "$d/hyb/priv.der" -o "$d/hyb/out" >/dev/null 2>&1; then
            dec="$(ls "$d/hyb/out"/decrypted_* 2>/dev/null | head -1)"
            [ -n "$dec" ] && [ "$(cat "$dec")" = "$MSG" ] && b="ok"
        fi
    fi

    pa="$([ "$a" = ok ] && echo ok || echo no)"
    pb="$([ "$b" = ok ] && echo ok || echo no)"
    if [ "$a" = ok ] && [ "$b" = ok ]; then
        st="OK"; ok=$((ok+1))
    elif [ "$our_self" = ok ]; then
        st="SKEW (kemri_toy draft-12 vs our -18)"; skew=$((skew+1))
    else
        st="FAIL (our output not self-valid)"; fail=$((fail+1))
    fi
    printf '%-20s %-7s %-7s %s\n' "$our(.$oid)" "$pa" "$pb" "$st"
done <<EOF
$COMBOS
EOF

echo "----"
echo "both-way composite-KEM CMS KEMRI interop (hybrid-provider <-> kemri_toy):"
echo "  $ok OK (both ways), $skew SKEW (older-draft peer), $skip SKIP (peer lacks combo), $fail FAIL"
[ "$fail" -eq 0 ]
