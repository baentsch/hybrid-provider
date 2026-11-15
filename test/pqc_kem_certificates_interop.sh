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
# --strict (or STRICT=1) turns the two "nothing to compare" outcomes of a verify
# -- a peer zip that cannot be fetched, and a peer with no artifacts on our arc --
# from SKIP into FAIL. Scheduled drift checks (scripts/check-pqc-certs-drift.sh)
# use it: there a vanished or renamed peer is drift to triage, not a clean skip.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PQC_KIND=certs
PQC_OUTNAME=pqc-kem-artifacts
# composite-kem-ref-impl (LAMPS reference) first, then the third-party providers
# that publish composite-KEM decaps vectors in the r5 round. Override with --peers;
# a peer without decaps vectors self-skips, so widening this list is harmless.
PEERS="${PEERS:-composite-kem-ref-impl bc cht crypto4a cryptonext entrust}"

# shellcheck source=pqc_corpus_common.sh
. "$REPO/test/pqc_corpus_common.sh"
pqc_defaults
pqc_parse_args "$@"
pqc_init_report
pqc_require_module
pqc_setup

# ---- verify: third-party decaps vectors read + checked by hybrid-provider -----
verify_peer() {   # $1 = provider dir name
    local peer="$1" d="$WORKDIR/$1" n=0 p=0
    pqc_fetch_peer "$peer" || return
    # One shared-secret file per composite-KEM OID; standalone ML-KEM entries
    # (OID arc 2.16.840...) do not match ARC and are ignored.
    while IFS= read -r ss; do
        local base oid priv ct out why
        base="${ss%_ss.bin}"
        oid="$(echo "$base" | grep -oE "$ARC" | head -1)"; [ -z "$oid" ] && continue
        n=$((n+1))
        pqc_report_oid kem "$peer" "$oid"
        priv="${base}_priv.der"; ct="${base}_ciphertext.bin"
        if [ ! -f "$priv" ] || [ ! -f "$ct" ]; then
            no "$peer: $oid missing _priv.der / _ciphertext.bin"; continue
        fi
        if ! why="$(pqc_oid_check "$priv" "$oid")"; then
            no "$peer: $why"; continue
        fi
        out="$WORKDIR/$(basename "$base").out"
        if oss pkeyutl -decap -inkey "$priv" -keyform DER -in "$ct" \
                -secret "$out" >/dev/null 2>&1 && cmp -s "$out" "$ss"; then
            p=$((p+1)); pqc_record_ok "$peer" "$oid"
        else
            no "$peer: $oid ($(basename "$base")) did not decapsulate to its secret"
        fi
    done < <(find "$d" -type f -name '*_ss.bin' | grep -E "$ARC" | sort)
    pqc_peer_summary "$peer" "$n" "$p" "decapsulated to the peer's secret" "vectors" \
        "no composite-KEM ($ARC) decaps vectors in $ROUND (certs-only or none)"
}

cmd_verify() {
    pqc_verify_all "Read/verify: pqc-certificates composite ML-KEM decaps vectors checked by hybrid-provider" \
        "decapsulated"
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

pqc_main
