#!/usr/bin/env bash
#
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# Detect drift between oqsprovider's hybrid algorithm set and this provider's
# master tables (HYBRID_KEM_LIST / HYBRID_SIG_LIST in hybrid_prov.h).
#
# WHY a source diff (not the built provider): this runs buildless and fast, so a
# scheduled job can check upstream oqsprovider *main* weekly and file an issue
# the moment a new hybrid family lands there — long before we'd otherwise notice.
# It complements hybrid_coverage_test, which checks a *built* oqsprovider at test
# time (and only what its runtime classification recognises).
#
# HOW hybrids are identified (no fragile name list needed):
#   - KEMs are tagged *structurally* in oqsprovider's generated source by the
#     KEMHYBALG macro — this includes the prefix-less standardised MLX names
#     (X25519MLKEM768, ...), so there is no "standard names" blind spot.
#   - Signatures have no hybrid-specific macro, but a hybrid signature always
#     carries a classical <curve>_/<rsa>_ prefix by construction, so the prefix
#     rule below is complete for them.
#
# Exit status: 0 = in sync, 1 = drift detected (report on stdout), 2 = error.
#
# Env:
#   OQSPROV_REF   oqsprovider git ref to check against (default: main)
#   OQSPROV_SRC   local path to an oqsprov.c to use instead of fetching

set -euo pipefail

OQSPROV_REF="${OQSPROV_REF:-main}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HDR="$REPO_ROOT/hybrid_prov.h"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

src="$tmp/oqsprov.c"
if [ -n "${OQSPROV_SRC:-}" ]; then
    cp "$OQSPROV_SRC" "$src"
    ref_desc="local:$OQSPROV_SRC"
else
    url="https://raw.githubusercontent.com/open-quantum-safe/oqs-provider/${OQSPROV_REF}/oqsprov/oqsprov.c"
    if ! curl -fsSL "$url" -o "$src"; then
        echo "error: failed to fetch $url" >&2
        exit 2
    fi
    ref_desc="oqsprovider@${OQSPROV_REF}"
fi

[ -r "$HDR" ] || { echo "error: cannot read $HDR" >&2; exit 2; }

# Classical prefixes that mark a hybrid signature (see header comment).
classic='^(p256|p384|p521|rsa3072|rsapss3072|x25519|x448|bp256|bp384|bp512)_'

# --- upstream oqsprovider hybrid names ---
grep -oE 'KEMHYBALG\([A-Za-z0-9_]+' "$src" \
    | sed 's/KEMHYBALG(//' | grep -vx 'NAMES' | sort -u > "$tmp/up_kem"
grep -oE 'SIGALG\("[A-Za-z0-9_]+"' "$src" \
    | sed -E 's/SIGALG\("//; s/"//' | grep -E "$classic" | sort -u > "$tmp/up_sig"

# --- our tables (the quoted name is the 2nd arg of each X(...) row) ---
extract_ours() { # $1 = LIST marker suffix (KEM|SIG)
    awk "/define HYBRID_$1_LIST/{on=1} /define HYBRID_$1_ROW/{on=0} on" "$HDR" \
        | grep -oE 'X\([A-Za-z0-9_]+, *"[^"]+"' \
        | sed -E 's/.*"([^"]+)"/\1/' | sort -u
}
extract_ours KEM > "$tmp/our_kem"
extract_ours SIG > "$tmp/our_sig"

missing_kem="$(comm -23 "$tmp/up_kem" "$tmp/our_kem")"
missing_sig="$(comm -23 "$tmp/up_sig" "$tmp/our_sig")"
extra_kem="$(comm -13 "$tmp/up_kem" "$tmp/our_kem")"
extra_sig="$(comm -13 "$tmp/up_sig" "$tmp/our_sig")"

# The standardised MLX KEMs are sourced from the default provider by design, so
# their absence from oqsprovider's KEMHYBALG set is expected, not drift. Drop
# them from the "extra" direction (a genuine rename of an OQS-legacy name still
# shows). They stay in the "missing" direction, so a NEW standardised name that
# oqsprovider serves but we lack would still be flagged.
if [ -n "$extra_kem" ]; then
    extra_kem="$(printf '%s\n' "$extra_kem" | grep -vE \
        '^(X25519MLKEM768|X448MLKEM1024|SecP256r1MLKEM768|SecP384r1MLKEM1024)$' \
        || true)"
fi

drift=0
if [ -n "$missing_kem$missing_sig" ]; then drift=1; fi

echo "oqsprovider hybrid drift check — $ref_desc"
echo "vs hybrid_prov.h ($(wc -l < "$tmp/our_kem") KEM, $(wc -l < "$tmp/our_sig") SIG rows)"
echo "upstream advertises $(wc -l < "$tmp/up_kem") hybrid KEMs, $(wc -l < "$tmp/up_sig") hybrid signatures"
echo

if [ "$drift" -eq 0 ] && [ -z "$extra_kem$extra_sig" ]; then
    echo "IN SYNC — every upstream hybrid is present in our tables."
    exit 0
fi

if [ -n "$missing_kem" ]; then
    echo "## MISSING hybrid KEMs (upstream has, we do NOT serve):"
    echo "$missing_kem" | sed 's/^/  - /'
    echo
fi
if [ -n "$missing_sig" ]; then
    echo "## MISSING hybrid signatures (upstream has, we do NOT serve):"
    echo "$missing_sig" | sed 's/^/  - /'
    echo
fi
if [ -n "$extra_kem$extra_sig" ]; then
    echo "## EXTRA names we list that upstream no longer advertises"
    echo "   (possible rename or removal — review, not necessarily an error):"
    { [ -n "$extra_kem" ] && echo "$extra_kem"; [ -n "$extra_sig" ] && echo "$extra_sig"; :; } \
        | sed 's/^/  - /'
    echo
fi

if [ "$drift" -eq 1 ]; then
    echo "DRIFT DETECTED — add the missing rows to HYBRID_KEM_LIST / HYBRID_SIG_LIST"
    echo "in hybrid_prov.h (see #25 for the eFrodoKEM precedent), then re-run the suite."
    exit 1
fi
echo "No missing hybrids; only informational differences above."
exit 0
