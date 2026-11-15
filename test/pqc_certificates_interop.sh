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
# --strict (or STRICT=1) turns the two "nothing to compare" outcomes of a verify
# -- a peer zip that cannot be fetched, and a peer with no artifacts on our arc --
# from SKIP into FAIL. Scheduled drift checks (scripts/check-pqc-certs-drift.sh)
# use it: there a vanished or renamed peer is drift to triage, not a clean skip.
# --family nist-pq with --providers runs the same checks on plain ML-DSA / SLH-DSA
# / ML-KEM from any component provider, hybrid not involved (see
# test/pqc_corpus_common.sh). An artifact the loaded providers cannot load is a
# SKIP (FAIL under --strict), not a wrong result.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PQC_KIND=certs
PQC_OUTNAME=pqc-artifacts
# Default peers = every provider that publishes draft-19 composite-signature
# artifacts in the r5 round, as listed by the repo's own results matrix
# (docs/pqc_hackathon_results_certs_r5.md — the rows on the 1.3.6.1.5.5.7.6.*
# arc), plus composite-crypto (present in the repo but not that matrix). Override
# with --peers to widen/narrow; non-composite providers self-skip either way.
PEERS="${PEERS:-bc carl-redhound cht composite-crypto composite-sigs-ref-impl \
crypto4a cryptonext entrust entrust-pkihub leancrypto \
openssl-composite-preliminary-impl safelogic}"

# shellcheck source=pqc_corpus_common.sh
. "$REPO/test/pqc_corpus_common.sh"
pqc_defaults
pqc_parse_args "$@"
pqc_init_report
pqc_require_module
pqc_setup

# ---- verify: third-party artifacts read + verified by hybrid-provider --------
verify_peer() {   # $1 = provider dir name
    local peer="$1" d="$WORKDIR/$1" n=0 p=0 u=0 kn=0 kp=0 ku=0
    pqc_fetch_peer "$peer" || return
    # Single-algorithm trust-anchor certs of the family, matched by the OID in
    # the filename. A provider may ship several files for the same OID (duplicate
    # / renamed copies), so certs (files) and distinct OIDs are counted separately.
    while IFS= read -r ta; do
        local oid pem priv privs why bad=0 tapub kpub
        oid="$(pqc_name_oid "$ta")"; [ -z "$oid" ] && continue
        n=$((n+1)); pem="$ta.pem"
        pqc_report_oid sig "$peer" "$oid"
        privs="$(pqc_privs "${ta%_ta.der}")"
        # The OID in the name must be the one inside: the cert and every key form.
        if ! why="$(pqc_oid_check "$ta" "$oid")"; then no "$peer: $why"; continue; fi
        while IFS= read -r priv; do
            [ -n "$priv" ] || continue
            why="$(pqc_oid_check "$priv" "$oid")" || { no "$peer: $why"; bad=1; }
        done <<< "$privs"
        [ "$bad" -eq 1 ] && continue
        oss x509 -inform DER -in "$ta" -out "$pem" 2>/dev/null || pem="$ta"
        if ! pqc_cert_loadable "$pem"; then
            u=$((u+1)); miss "$peer: $oid ($(basename "$ta")) not loadable by: $PQC_PROVIDERS"
            continue
        elif oss verify -no_check_time -CAfile "$pem" "$pem" >/dev/null 2>&1; then
            p=$((p+1)); pqc_record_ok "$peer" "$oid"
        else
            no "$peer: $oid ($(basename "$ta")) not verified by: $PQC_PROVIDERS"
        fi
        # Key forms: each shipped private key (_priv, or ML-DSA's _seed /
        # _expandedkey / _both) must load and yield the trust anchor's public key.
        # This exercises the provider's PKCS#8 decoder, which the cert verify alone
        # never touches. A different key is a FAIL. A key that does not load is a
        # SKIP even under --strict: peers also ship encodings the spec does not
        # define (e.g. an "expanded" composite key; draft-19 composite keys are
        # seed-based only), and rejecting those is correct. The per-peer line
        # counts them, so a decoder that rejects a standard form still shows.
        tapub="$(oss x509 -in "$pem" -noout -pubkey 2>/dev/null)"
        while IFS= read -r priv; do
            [ -n "$priv" ] || continue
            kn=$((kn+1))
            if ! pqc_key_loadable "$priv"; then
                ku=$((ku+1)); note "$peer: $oid ($(basename "$priv")) key form not loadable by: $PQC_PROVIDERS"
                continue
            fi
            kpub="$(oss pkey -in "$priv" -inform DER -pubout 2>/dev/null)"
            if [ -n "$kpub" ] && [ "$kpub" = "$tapub" ]; then
                kp=$((kp+1))
            else
                no "$peer: $oid ($(basename "$priv")) public key differs from its trust anchor's"
            fi
        done <<< "$privs"
    done < <(find "$d" -type f -name '*_ta.der' | grep -E "$ARC" | sort)
    pqc_peer_summary "$peer" "$((n + kn))" "$((p + kp))" "verified" \
        "certs incl. duplicates + key forms; $((kn - ku))/$kn key forms load" \
        "no $PQC_FAMILY ($ARC) trust-anchor certs in $ROUND" "$((u + ku))"
}

cmd_verify() {
    pqc_verify_all "Read/verify: pqc-certificates $PQC_FAMILY signature trust anchors" \
        "verified"
}

# ---- generate: our own artifacts in the repo's r5 flat naming ----------------
cmd_generate() {
    pqc_can_generate || return 0
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

pqc_main
