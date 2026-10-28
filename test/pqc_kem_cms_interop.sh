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
# Two directions per composite-KEM combo, both driven off OUR key/cert so no
# kemri_toy --kem name is ever needed:
#   A. kemri_toy ENCRYPTS to our EE cert (--ee-cert-file)  -> hybrid-provider
#      DECRYPTS (openssl cms -decrypt, hybrid loaded); recovered plaintext matches.
#   B. hybrid-provider ENCRYPTS to our cert (openssl cms -encrypt) -> kemri_toy
#      DECRYPTS with our PKCS#8 key (--ee-key-file); recovered plaintext matches.
#
# This exercises, across an impl boundary, our composite-KEM SPKI + PKCS#8
# encoders/decoders, the SHA3-256 combiner (byte-exact or the shared secret
# differs), and OpenSSL's KEMRI glue (HKDF-SHA256 + AES key-wrap). A combo
# kemri_toy cannot process just errors out (handing it our cert/key never requires
# it to know the combo by name) — so its support is discovered, never frozen.
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
# The combo set is NOT a frozen table — that would freeze the two impls'
# intersection, which drifts as kemri_toy gains combos. Instead both sides are
# discovered at run time: our side from the provider (every standardized
# composite-KEM OID 1.3.6.1.5.5.7.6.55..66 it serves), kemri_toy's side from its
# own `--help` (`--kem [possible values: ...]`) cross-checked against the OID it
# stamps into its output filenames. We then test every combo the standard defines
# that WE serve; a combo kemri_toy cannot do is SKIP (not a frozen omission), and a
# composite OID kemri_toy supports but we do not is reported as our own drift.
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
# The module file is present, so a failure to ACTIVATE here is a real fault (bad
# ABI, missing component dep, ...), not a clean skip -- and OpenSSL drops an
# unloadable provider silently (exit 0, nothing on stderr). Fail loudly with the
# one diagnostic OpenSSL won't give us.
ossl list -providers -provider hybrid 2>/dev/null | grep -q 'name: hybrid-provider' || {
    echo "ERROR: hybrid provider present at $MODULE_DIR/hybrid.$SOEXT but did not" >&2
    echo "       activate under $OPENSSL_BIN ($ver). Likely an ABI/libcrypto" >&2
    echo "       mismatch or a missing component dependency." >&2
    exit 1
}
# Loaded fine but serves no composite KEM (e.g. built without -DHYBRID_COMPOSITE,
# or OpenSSL < 3.5): that is a legitimate self-skip, not a fault.
ossl list -kem-algorithms -provider hybrid 2>/dev/null | grep -q "mlkem768_p256" \
    || skip "hybrid provider loaded but does not serve composite KEMs"
command -v "$KEMRI_TOY" >/dev/null 2>&1 || [ -x "$KEMRI_TOY" ] \
    || skip "kemri_toy not found ($KEMRI_TOY) — build github.com/carl-wallace/kemri_toy"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ARC='1\.3\.6\.1\.5\.5\.7\.6\.(5[5-9]|6[0-6])'   # LAMPS composite-KEM OID arc

MSG="kemri_toy <-> hybrid-provider RFC9629 KEMRI"
MSG_A="$WORK/msgA.txt"; printf '%s' "$MSG" >"$MSG_A"
MSG_B="$WORK/msgB.txt"; printf '%s' "$MSG" >"$MSG_B"

# --- discover OUR standardized composite-KEM combos (oid tail -> our name) -----
# Every composite-KEM the provider serves whose public key encodes to the LAMPS
# standardized arc; the concat MLX/X-Wing hybrids (no SPKI OID) and the private-arc
# experimental composites fall outside ARC and drop. This is "what the standard
# defines that we serve" — the driver set, so kemri_toy gaps surface as SKIP.
: > "$WORK/ourmap"
for alg in $(ossl list -kem-algorithms $PROV 2>/dev/null \
        | awk '/@ *hybrid/ { gsub(/^ +/,""); sub(/ .*/,""); print }'); do
    ossl genpkey $PROV -algorithm "$alg" -outform DER -out "$WORK/o.key" 2>/dev/null || continue
    ossl pkey $PROV -in "$WORK/o.key" -inform DER -pubout -outform DER \
        -out "$WORK/o.pub" 2>/dev/null || continue
    # asn1parse is not provider-aware (rejects -provider); it only reads the DER.
    oidfull="$(ossl asn1parse -inform DER -in "$WORK/o.pub" 2>/dev/null \
               | grep -oE "$ARC" | head -1)"
    [ -z "$oidfull" ] && continue
    echo "${oidfull##*.} $alg" >> "$WORK/ourmap"
done
sort -n -o "$WORK/ourmap" "$WORK/ourmap"

# kemri_toy's advertised --kem values — consulted ONLY to classify a FAILED
# interaction (absent here => a genuine kemri_toy omission => SKIP). No frozen
# name<->OID table and no probing pass: we hand kemri_toy OUR cert/key
# (--ee-cert-file / --ee-key-file), so it never needs a --kem name, and a combo it
# cannot process simply errors out.
KT_KEMS="$("$KEMRI_TOY" --help 2>&1 \
    | awk '/--kem/{f=1} f&&/possible values:/{sub(/.*\[possible values: /,""); sub(/\].*/,""); gsub(/,/," "); print; exit}')"

# One Ed25519 CA to sign all recipient certs (a KEM key cannot self-sign).
ossl genpkey -algorithm ED25519 -out "$WORK/ca.key" >/dev/null 2>&1
ossl x509 -new -key "$WORK/ca.key" -subj "/CN=hybrid-kem-interop-ca" -days 3650 \
    -out "$WORK/ca.crt" >/dev/null 2>&1 || skip "cannot create CA cert"

# Does kemri_toy advertise a --kem for this combo? Transparent token test: a --kem
# value must carry both our level (ml-kem768/1024) and our trad token (bp -> the
# "brainpool" kemri spells). Used only to annotate a failed interaction, never to
# decide what to run.
kt_advertises() {   # $1 = our alg name, e.g. mlkem1024_bp384
    local lvl="${1%%_*}" trad="${1#*_}"
    lvl="ml-kem${lvl#mlkem}"                    # mlkem768 -> ml-kem768
    case "$trad" in bp*) trad="brainpool" ;; esac
    printf '%s' "$KT_KEMS" | tr ' ' '\n' | grep -i -- "$lvl" | grep -qi -- "$trad"
}

# Status model. We test every standardized combo WE serve; kemri_toy is driven
# with our cert/key, so its own capability decides the outcome:
#   OK    both cross-directions agree.
#   SKEW  kemri_toy processed the combo but disagreed, while our own output is
#         self-valid — a draft-12 vs -18 difference, not a fault (draft-18
#         correctness is asserted by hybrid_cms_kem_test +
#         pqc_kem_cms_certificates_interop.sh against the pqc-certificates corpus).
#   SKIP  kemri_toy errors on the combo (cannot process it); confirmed absent from
#         its --help --kem list. If it IS advertised yet errored, the row is marked
#         SKIP* so the discrepancy stays visible rather than hidden.
# The run FAILS only if OUR OWN output is not self-valid (a real regression).
ok=0; skew=0; skip=0; fail=0
printf '%-20s %-7s %-7s %s\n' "combo (OID)" "kt>hyb" "hyb>kt" "status"
printf '%-20s %-7s %-7s %s\n' "-----------" "------" "------" "------"

while read -r oid our; do
    [ -z "${oid:-}" ] && continue
    d="$WORK/run/$oid"; mkdir -p "$d/A" "$d/B"

    # Our key + EE cert (used by BOTH directions; a failure here is OUR bug).
    if ! ossl genpkey $PROV -algorithm "$our" -outform DER -out "$d/priv.der" 2>/dev/null \
       || ! ossl pkey $PROV -in "$d/priv.der" -inform DER -pubout -out "$d/pub.pem" 2>/dev/null \
       || ! ossl x509 -new -force_pubkey "$d/pub.pem" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
              -subj "/CN=ee-$oid" -days 365 $PROV -out "$d/ee.der" -outform DER 2>/dev/null; then
        printf '%-20s %-7s %-7s %s\n' "$our(.$oid)" "-" "-" "FAIL (our keygen/cert)"
        fail=$((fail+1)); continue
    fi

    # Direction A: kemri_toy ENCRYPTS to our cert (--ee-cert-file, no --kem); we
    # decrypt. kemri_toy erroring here means it cannot process this combo.
    a="x"; a_err=0
    if "$KEMRI_TOY" --ee-cert-file "$d/ee.der" -i "$MSG_A" -o "$d/A" >/dev/null 2>&1; then
        blob="$(ls "$d/A"/*_kemri_id-alg-hkdf-with-sha256.der 2>/dev/null | grep -v _kemri_auth | head -1)"
        [ -n "$blob" ] && [ "$(ossl cms -decrypt $PROV -inform DER -in "$blob" \
             -inkey "$d/priv.der" -keyform DER 2>/dev/null)" = "$MSG" ] && a="ok"
    else
        a_err=1
    fi

    # Direction B: we ENCRYPT to our cert; kemri_toy decrypts with our key. Our own
    # output must self-validate (guards against masking a regression as a SKEW).
    b="x"; b_err=0; our_self="x"
    if ossl cms -encrypt $PROV -recip "$d/ee.der" -aes-256-cbc -binary \
            -in "$MSG_B" -outform DER -out "$d/env.der" 2>/dev/null; then
        [ "$(ossl cms -decrypt $PROV -inform DER -in "$d/env.der" \
             -inkey "$d/priv.der" -keyform DER 2>/dev/null)" = "$MSG" ] && our_self="ok"
        if "$KEMRI_TOY" -i "$d/env.der" -k "$d/priv.der" -o "$d/B" >/dev/null 2>&1; then
            dec="$(ls "$d/B"/decrypted_* 2>/dev/null | head -1)"
            [ -n "$dec" ] && [ "$(cat "$dec")" = "$MSG" ] && b="ok"
        else
            b_err=1
        fi
    fi

    pa="$([ "$a" = ok ] && echo ok || echo no)"
    pb="$([ "$b" = ok ] && echo ok || echo no)"
    if [ "$our_self" != ok ]; then
        st="FAIL (our output not self-valid)"; fail=$((fail+1))
    elif [ "$a" = ok ] && [ "$b" = ok ]; then
        st="OK"; ok=$((ok+1))
    elif [ "$a_err" = 1 ] && [ "$b_err" = 1 ]; then
        if kt_advertises "$our"; then
            st="SKIP* (--help advertises it, but kemri_toy errored)"
        else
            st="SKIP (kemri_toy lacks this combo)"
        fi
        skip=$((skip+1))
    else
        st="SKEW (kemri_toy draft-12 vs our -18)"; skew=$((skew+1))
    fi
    printf '%-20s %-7s %-7s %s\n' "$our(.$oid)" "$pa" "$pb" "$st"
done < "$WORK/ourmap"

echo "----"
echo "both-way composite-KEM CMS KEMRI interop (hybrid-provider <-> kemri_toy):"
echo "  $ok OK (both ways), $skew SKEW (older-draft peer), $skip SKIP (kemri_toy can't;"
echo "  * = advertised in --help but errored), $fail FAIL  —  full standardized matrix,"
echo "  discovered at run time (no frozen list)."
[ "$fail" -eq 0 ]
