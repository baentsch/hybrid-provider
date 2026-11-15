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
# These two are CMS framing, not PQ: _kemri_auth wraps the same KEMRI (RFC 9629)
# in AuthEnvelopedData (RFC 5083, AEAD content-encryption) vs our plain
# EnvelopedData (RFC 5652), and _ukm is RFC 9629's UserKeyingMaterial fed to the
# KDF — both KEM-agnostic, so skipping them drops no composite-ML-KEM coverage.
#
# Modes (mirroring pqc_kem_certificates_interop.sh): `verify` (default) reads the
# peers' corpus; `generate` writes THIS provider's composite-KEM KEMRI
# EnvelopedData in the same cms_v3 layout (+ self-verify) for a
# providers/hybrid-provider/ submission so others can decrypt us; `all` does both.
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
# --strict (or STRICT=1) turns the "nothing to compare" outcomes of a verify -- a
# peer zip that cannot be fetched, no expected_plaintext.txt, or no artifacts on
# our arc -- from SKIP into FAIL (used by scripts/check-pqc-certs-drift.sh, where
# a vanished or renamed peer is drift to triage, not a clean skip).
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PQC_KIND=cms
PQC_OUTNAME=pqc-kem-cms-artifacts
PQC_OPENSSL_HINT="must be 3.6.0+"
# Two independent draft-18 impls that ship the full .55..66 KEMRI matrix. Override
# with --peers; a peer without composite-arc KEMRI artifacts self-skips, so
# widening the list is harmless (but an older-draft peer may FAIL on skew).
PEERS="${PEERS:-composite-crypto bc}"
PLAINTEXT="${PLAINTEXT:-Hello, World!}"   # our generated EnvelopedData payload

# shellcheck source=pqc_corpus_common.sh
. "$REPO/test/pqc_corpus_common.sh"
pqc_defaults
pqc_parse_args "$@"
pqc_init_report

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

pqc_setup
# generate needs `x509 -new`, which misreads the provider cnf's [default] section
# as cert extensions; drive those commands with a null cnf + explicit -provider
# flags instead (same workaround as pqc_kem_cms_interop.sh).
ossp() { local sub="$1"; shift
         OPENSSL_CONF=/dev/null "$OPENSSL_BIN" "$sub" -provider default -provider hybrid "$@"; }

# ---- verify: third-party EnvelopedData decrypted by hybrid-provider ----------
verify_peer() {   # $1 = provider dir name
    local peer="$1" d="$WORKDIR/$1" n=0 p=0 exp blob
    pqc_fetch_peer "$peer" || return
    exp="$(find "$d" -type f -name expected_plaintext.txt | head -1)"
    if [ -z "$exp" ]; then
        miss "$peer: no expected_plaintext.txt in cms_$VER (cannot assert content)"; return
    fi
    # One EnvelopedData per composite-KEM OID (HKDF-SHA256 KEMRI; exclude the
    # authenticated and user-keying-material variants). Standalone ML-KEM entries
    # (OID arc 2.16.840... / BC vendor arc) do not match ARC and are ignored.
    while IFS= read -r blob; do
        local base oid priv out why
        base="${blob%_kemri_id-alg-hkdf-with-sha256.der}"
        oid="$(echo "$base" | grep -oE "$ARC" | head -1)"; [ -z "$oid" ] && continue
        n=$((n+1))
        pqc_report_oid cms "$peer" "$oid"
        priv="${base}_priv.der"
        if [ ! -f "$priv" ]; then
            no "$peer: $oid missing _priv.der"; continue
        fi
        # The KEMRI's kem AlgorithmIdentifier and the recipient key must both
        # carry the filename OID.
        if ! why="$(pqc_oid_check "$blob" "$oid")" \
                || ! why="$(pqc_oid_check "$priv" "$oid")"; then
            no "$peer: $why"; continue
        fi
        out="$WORKDIR/$(basename "$base").out"
        if oss cms -decrypt -inform DER -in "$blob" -inkey "$priv" -keyform DER \
                -out "$out" >/dev/null 2>&1 && cmp -s "$out" "$exp"; then
            p=$((p+1)); pqc_record_ok "$peer" "$oid"
        else
            no "$peer: $oid ($(basename "$base")) did not decrypt to expected plaintext"
        fi
    done < <(find "$d" -type f -name '*_kemri_id-alg-hkdf-with-sha256.der' \
                | grep -v '_kemri_auth' | grep -E "$ARC" | sort)
    pqc_peer_summary "$peer" "$n" "$p" "decrypted to the peer's plaintext" "blobs" \
        "no composite-KEM ($ARC) KEMRI artifacts in cms_$VER"
}

cmd_verify() {
    pqc_verify_all "Read/verify: pqc-certificates composite ML-KEM CMS (KEMRI) decrypted by hybrid-provider" \
        "decrypted"
}

# ---- generate: THIS provider's cms_v3 KEMRI artifacts (+ self-verify) --------
# Mirrors the generate mode of pqc_kem_certificates_interop.sh, but emits a CMS
# EnvelopedData per OID instead of a raw decaps vector. Identify composites by the
# LAMPS OID arc (not a name convention): iterate the provider's KEM algorithms and
# keep those whose public key encodes to a composite-arc OID (the concat MLX/oqs
# hybrid KEMs have no SPKI OID and drop; experimental private-arc combos are
# outside the standardized arc and drop too).
cmd_generate() {
    hdr "Generate: hybrid-provider composite ML-KEM CMS KEMRI artifacts (cms_v3 layout) + self-verify"
    mkdir -p "$OUTDIR"
    local ca="$WORKDIR/ca.key" cacrt="$WORKDIR/ca.crt" alg n=0 p=0
    # Ed25519 CA to sign the EE certs (a KEM key cannot self-sign).
    if ! ossp genpkey -algorithm ED25519 -out "$ca" >/dev/null 2>&1 \
            || ! ossp x509 -new -key "$ca" -subj "/CN=hybrid-cms-kem-ca" -days 3650 \
                    -out "$cacrt" >/dev/null 2>&1; then
        note "cannot create Ed25519 CA cert"; return
    fi
    printf '%s' "$PLAINTEXT" > "$OUTDIR/expected_plaintext.txt"
    for alg in $(ossp list -kem-algorithms 2>/dev/null \
            | awk '/@ *hybrid/ { gsub(/^ +/,""); sub(/ .*/,""); print }'); do
        local key="$WORKDIR/$alg.key" pub="$WORKDIR/$alg.pub" oid base
        ossp genpkey -algorithm "$alg" -out "$key" 2>/dev/null || continue
        ossp pkey -in "$key" -pubout -outform DER -out "$pub" 2>/dev/null || continue
        # asn1parse is not provider-aware (rejects -provider); it only needs to
        # read the DER SPKI, so call it plainly with a null cnf.
        oid="$(OPENSSL_CONF=/dev/null "$OPENSSL_BIN" asn1parse -inform DER -in "$pub" \
               2>/dev/null | grep -oE "$ARC" | head -1)"
        [ -z "$oid" ] && continue     # OID outside the composite-KEM arc
        n=$((n+1)); base="$OUTDIR/id-$alg-$oid"
        ossp pkey -in "$key" -outform DER -out "${base}_priv.der" 2>/dev/null
        # EE cert carrying the composite-KEM public key, signed by the Ed25519 CA.
        if ! ossp x509 -new -force_pubkey "$pub" -CA "$cacrt" -CAkey "$ca" \
                -subj "/CN=ee-$oid" -days 365 -out "${base}_ee.der" -outform DER 2>/dev/null \
           || ! ossp cms -encrypt -recip "${base}_ee.der" -aes-256-cbc -binary \
                -in "$OUTDIR/expected_plaintext.txt" -outform DER \
                -out "${base}_kemri_id-alg-hkdf-with-sha256.der" 2>/dev/null; then
            no "$alg ($oid) could not produce EE cert / EnvelopedData"; continue
        fi
        # Self-verify: decrypting our own EnvelopedData must recover the plaintext.
        if [ "$(ossp cms -decrypt -inform DER \
                    -in "${base}_kemri_id-alg-hkdf-with-sha256.der" \
                    -inkey "${base}_priv.der" -keyform DER 2>/dev/null)" = "$PLAINTEXT" ]; then
            p=$((p+1))
        else
            no "$alg ($oid) self-decrypt of generated EnvelopedData"
        fi
    done
    if [ "$n" -eq 0 ]; then
        note "no composite-KEM algorithms available (needs OpenSSL 3.5+ ML-KEM + composite build)"
    else
        ok "generated + self-verified $p/$n composite-KEM CMS artifacts -> $OUTDIR"
        echo "       (submit these under providers/hybrid-provider/ as"
        echo "        artifacts_cms_$VER.zip so peers can decrypt our EnvelopedData)"
    fi
}

pqc_main
