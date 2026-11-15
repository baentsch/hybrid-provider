#!/usr/bin/env bash
#
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# Detect drift between this provider's composite (LAMPS) OIDs and the IETF
# Hackathon PQC certificate corpus (github.com/IETF-Hackathon/pqc-certificates),
# the multi-vendor X.509/CMS interop set. Run weekly by
# .github/workflows/pqc-certs-interop.yml; also runnable locally.
#
# Four checks, each against the corpus's live `master`, plus a coverage report:
#   1. OUR OIDs      -- the composite-arc OIDs our encoder actually emits, taken
#                       from the generate mode of the sig + KEM corpus scripts (a
#                       real SPKI per algorithm, so no OID list is duplicated here
#                       and the provider's tables stay the single source).
#   2. OID TABLE     -- that set vs the corpus's canonical docs/oid_mapping.md, both
#                       ways: an arc OID the table lists that we do not emit, or one
#                       we emit that the table no longer lists (renumbering).
#   3. CORPUS READ   -- the three verify scripts in --strict mode: every default
#                       peer's sig certs, KEM decaps vectors and CMS KEMRI blobs
#                       must be read by us; an unreachable or empty peer FAILs, and
#                       so does an artifact whose embedded OID is not the one in
#                       its filename (test/pqc_corpus_common.sh).
#   4. ROUND         -- a newer artifact round (certs rN / cms vN) than the one the
#                       scripts read is a prompt to evaluate a bump.
#   COVERAGE (informational, never drift) -- per peer and family, how many of our
#                       OIDs it ships and which it does not. A peer that ships an
#                       OID we do not serve already FAILs check 3. The reverse is
#                       the peer's own coverage gap, not drift.
#
# Exit status: 0 = in sync, 1 = drift (report on stdout), 2 = tooling error.
#
# Env (passed through to the test/pqc_*certificates_interop.sh scripts):
#   OPENSSL_BIN, OPENSSL_LIBPATH, MODULE_DIR   as for those scripts
#   ROUND (certs, default r5), VER (cms, default v3)
#   GH_TOKEN   optional; authenticates the one GitHub API call (round listing)
#   OID_MAPPING_SRC  local oid_mapping.md to use instead of fetching (testing)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="IETF-Hackathon/pqc-certificates"
RAW="https://raw.githubusercontent.com/$CORPUS/master"
TREE_API="https://api.github.com/repos/$CORPUS/git/trees/master?recursive=1"
ROUND="${ROUND:-r5}"
VER="${VER:-v3}"
export ROUND VER
# shellcheck source=../test/pqc_corpus_common.sh
. "$REPO_ROOT/test/pqc_corpus_common.sh"   # ARC (composite OID arc), pqc_report_oid
# Check OUR implementations: if the default provider ever serves a composite, the
# cede-to-default lever would otherwise withdraw ours and we would test theirs.
export HYBRID_CEDE_TO_DEFAULT=0
[ -n "${OPENSSL_LIBPATH:-}" ] \
    && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
die() { echo "error: $*" >&2; exit 2; }
drift=0

# ---- 1. OIDs our encoder emits ------------------------------------------------
for fam in sig kem; do
    case "$fam" in
        sig) script=pqc_certificates_interop.sh;;
        kem) script=pqc_kem_certificates_interop.sh;;
    esac
    if ! "$REPO_ROOT/test/$script" generate --outdir "$tmp/gen-$fam" \
            > "$tmp/gen-$fam.log" 2>&1; then
        # Our own artifacts failing self-verify is a regression, not drift --
        # but it makes every later check meaningless, so stop here.
        cat "$tmp/gen-$fam.log" >&2
        die "$script generate failed (provider not built/loadable, or self-verify broke)"
    fi
done
for fam in sig kem; do
    find "$tmp/gen-$fam" -type f 2>/dev/null | grep -oE "$ARC" | sort -u > "$tmp/ours-$fam"
done
cp "$tmp/ours-kem" "$tmp/ours-cms"   # KEMRI blobs carry the composite-KEM OIDs
sort -u "$tmp/ours-sig" "$tmp/ours-kem" > "$tmp/ours"
[ -s "$tmp/ours" ] || die "provider emitted no composite-arc OIDs (built without HYBRID_COMPOSITE, or OpenSSL < 3.5?)"

# ---- 2. vs the corpus OID table ----------------------------------------------
if [ -n "${OID_MAPPING_SRC:-}" ]; then
    cp "$OID_MAPPING_SRC" "$tmp/oid_mapping.md" || die "cannot read $OID_MAPPING_SRC"
else
    curl -fsSL "$RAW/docs/oid_mapping.md" -o "$tmp/oid_mapping.md" \
        || die "cannot fetch $RAW/docs/oid_mapping.md"
fi
# Table rows are "| name | oid | spec |"; take the OID column on our arc.
awk -F'|' -v arc="^${ARC}\$" '{ o=$3; gsub(/ /, "", o); if (o ~ arc) print o }' \
    "$tmp/oid_mapping.md" | sort -u > "$tmp/table"
[ -s "$tmp/table" ] || die "no composite-arc OIDs parsed from oid_mapping.md (format changed?)"
comm -23 "$tmp/table" "$tmp/ours" > "$tmp/missing"
comm -13 "$tmp/table" "$tmp/ours" > "$tmp/unlisted"

# ---- 3. read the corpus, strictly --------------------------------------------
export PQC_OID_REPORT="$tmp/peer-oids"   # "<family> <peer> <oid>" per shipped OID
: > "$PQC_OID_REPORT"
for script in pqc_certificates_interop.sh pqc_kem_certificates_interop.sh \
              pqc_kem_cms_certificates_interop.sh; do
    "$REPO_ROOT/test/$script" --strict verify > "$tmp/$script.log" 2>&1
    echo "$?" > "$tmp/$script.rc"
    cat "$tmp/$script.log" >&2          # full log to the run, not the report
    # A whole-script SKIP is an environment gap (e.g. OpenSSL < 3.6 for CMS).
    grep -q '^SKIP:' "$tmp/$script.log" \
        && die "$script skipped: $(grep '^SKIP:' "$tmp/$script.log")"
done

# ---- 4. newer artifact round -------------------------------------------------
auth=()
[ -n "${GH_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GH_TOKEN")
curl -fsSL "${auth[@]}" "$TREE_API" -o "$tmp/tree.json" \
    || die "cannot list $CORPUS (GitHub API)"
latest() { # $1 = artifact kind (certs|cms), $2 = round prefix (r|v)
    grep -oE "artifacts_$1_$2[0-9]+\.zip" "$tmp/tree.json" \
        | sed -E "s/.*_($2[0-9]+)\.zip/\1/" | sort -uV | tail -1
}
latest_certs="$(latest certs r)"; latest_cms="$(latest cms v)"
newer=""
[ -n "$latest_certs" ] && [ "$(printf '%s\n' "$ROUND" "$latest_certs" | sort -V | tail -1)" != "$ROUND" ] \
    && newer="${newer}  - certs: $latest_certs published (we read $ROUND)"$'\n'
[ -n "$latest_cms" ] && [ "$(printf '%s\n' "$VER" "$latest_cms" | sort -V | tail -1)" != "$VER" ] \
    && newer="${newer}  - cms: $latest_cms published (we read $VER)"$'\n'

# ---- report ------------------------------------------------------------------
echo "pqc-certificates drift check — $CORPUS@master (certs $ROUND, cms $VER)"
echo "openssl: $("${OPENSSL_BIN:-openssl}" version 2>/dev/null)"
echo "we emit $(wc -l < "$tmp/ours") composite-arc OIDs; oid_mapping.md lists $(wc -l < "$tmp/table")"
# Informational: the spec each table row cites (e.g. a draft becoming an RFC).
awk -F'|' -v arc="^${ARC}\$" '{ o=$3; gsub(/ /, "", o); s=$4; gsub(/^ +| +$/, "", s);
        if (o ~ arc) n[s]++ } END { for (s in n) printf "  cited: %s (%d OIDs)\n", s, n[s] }' \
    "$tmp/oid_mapping.md" | sort
echo

if [ -s "$tmp/missing" ]; then
    drift=1
    echo "## OIDs in oid_mapping.md that we do NOT emit (new combo, or renumbered):"
    sed 's/^/  - /' "$tmp/missing"; echo
fi
if [ -s "$tmp/unlisted" ]; then
    drift=1
    echo "## OIDs we emit that oid_mapping.md no longer lists (withdrawn or renumbered):"
    sed 's/^/  - /' "$tmp/unlisted"; echo
fi
for script in pqc_certificates_interop.sh pqc_kem_certificates_interop.sh \
              pqc_kem_cms_certificates_interop.sh; do
    if [ "$(cat "$tmp/$script.rc")" != 0 ]; then
        drift=1
        echo "## test/$script --strict verify FAILED:"
        grep -E '^ *FAIL' "$tmp/$script.log" | sed -E 's/^ *FAIL +/  - /'
        echo
    fi
done
if [ -n "$newer" ]; then
    drift=1
    echo "## Newer artifact round in the corpus:"
    printf '%s' "$newer"; echo
fi

# Informational: each peer's coverage of our OIDs. It does not set drift. A
# shipped OID we do not serve is already a check-3 FAIL above.
echo "## Per-peer coverage of our OIDs (informational):"
for fam in sig kem cms; do
    for peer in $(awk -v f="$fam" '$1 == f { print $2 }' "$tmp/peer-oids" | sort -u); do
        awk -v f="$fam" -v p="$peer" '$1 == f && $2 == p { print $3 }' \
            "$tmp/peer-oids" | sort -u > "$tmp/theirs"
        have=$(comm -12 "$tmp/ours-$fam" "$tmp/theirs" | wc -l)
        gaps="$(comm -23 "$tmp/ours-$fam" "$tmp/theirs" | sed -E 's/.*\./\./' | tr '\n' ' ')"
        printf '  %-3s %-36s %2d/%d%s\n' "$fam" "$peer" "$have" \
            "$(wc -l < "$tmp/ours-$fam")" "${gaps:+   not shipped: ${gaps% }}"
    done
done
echo

if [ "$drift" -eq 0 ]; then
    echo "IN SYNC — OID table matches, every default peer read, no newer round."
    exit 0
fi
echo "DRIFT DETECTED — see design.md \"Triaging a weekly failure (runbook)\"."
exit 1
