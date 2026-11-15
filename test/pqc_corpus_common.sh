# shellcheck shell=bash
#
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# pqc_corpus_common.sh — shared by the IETF Hackathon pqc-certificates corpus
# scripts (test/pqc_*certificates_interop.sh) and scripts/check-pqc-certs-drift.sh.
# Sourced, not executed.
#
# The corpus scripts set these before sourcing, then define verify_peer (and
# cmd_generate) and end with `pqc_main "$@"`:
#   REPO         repo root
#   PQC_KIND     certs | cms   corpus zip kind: artifacts_certs_<ROUND>.zip or
#                              artifacts_cms_<VER>.zip
#   PQC_OUTNAME  generate output dir name under the module dir
#   PEERS        default peer list (env PEERS overrides)
# The drift script only uses ARC and the pqc_* OID helpers; sourcing this file
# has no side effects beyond defining variables and functions.

# The whole LAMPS composite OID arc (sigs .37..54, KEMs .55..66). The KEM scripts
# match all of it, not just the OIDs we serve today: only KEMs ship decaps vectors
# and KEMRI blobs, so the match stays KEM-only, and a NEW composite OID in the
# corpus is tried (and FAILs) instead of being silently ignored.
ARC='1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'

RAW_BASE="https://raw.githubusercontent.com/IETF-Hackathon/pqc-certificates/master/providers"

# ---- OID helpers --------------------------------------------------------------

# The arc OIDs a DER file embeds, one per line, sorted and de-duplicated. A null
# cnf keeps the hybrid provider out of the picture. Plain libcrypto has no names
# for the arc, so asn1parse prints these OIDs numerically.
pqc_embedded_oids() {   # $1 = DER file
    OPENSSL_CONF=/dev/null "${OPENSSL_BIN:-openssl}" asn1parse -inform DER -in "$1" \
            2>/dev/null \
        | grep -oE "OBJECT +:$ARC\$" | grep -oE "$ARC" | sort -u
}

# Filename vs content: the corpus names each artifact after its OID, and the
# verify loops key every result on that name. This checks the file embeds exactly
# that one arc OID, i.e. the key's algorithm (and, for a self-signed trust anchor,
# its signature algorithm too). A mislabelled artifact would otherwise be counted
# under the wrong OID. Returns 0 if coherent; else 1, with the reason on stdout.
# Only for files that carry a single arc OID: PKCS#8 keys, self-signed _ta certs
# and KEMRI EnvelopedData. A KEM _ee cert does not qualify, since its CA may sign
# with a composite signature OID.
pqc_oid_check() {   # $1 = DER file, $2 = OID from its filename
    local emb
    emb="$(pqc_embedded_oids "$1" | tr '\n' ' ')"
    [ "$emb" = "$2 " ] && return 0
    if [ -z "$emb" ]; then
        echo "$(basename "$1"): no arc OID found inside (unparseable DER, or this" \
             "OpenSSL prints the arc OIDs by name), expected $2"
    else
        echo "$(basename "$1") embeds [${emb% }] instead of its filename OID $2"
    fi
    return 1
}

# Record an OID a peer ships (read from the artifact filename). It feeds the
# "of M shipped" totals and, when PQC_OID_REPORT names a file, one
# "<family> <peer> <oid>" line for the per-peer coverage report of
# scripts/check-pqc-certs-drift.sh. Families: sig, kem (decaps vectors), cms.
pqc_report_oid() {   # $1 = family, $2 = peer, $3 = OID
    [ -n "${WORKDIR:-}" ] && echo "$3" >> "$WORKDIR/shipped_oids"
    [ -n "${PQC_OID_REPORT:-}" ] && echo "$1 $2 $3" >> "$PQC_OID_REPORT"
    return 0
}

# Record an OID a peer's artifact passed for (per peer + across peers).
pqc_record_ok() {   # $1 = peer, $2 = OID
    echo "$2" >> "$WORKDIR/$1.oids"
    echo "$2" >> "$WORKDIR/verified_oids"
}

# ---- corpus-script scaffolding ------------------------------------------------
# Everything below is only used by the corpus scripts, via pqc_main.

pqc_round() { if [ "$PQC_KIND" = cms ]; then echo "$VER"; else echo "$ROUND"; fi; }
pqc_zip()   { echo "artifacts_${PQC_KIND}_$(pqc_round).zip"; }

pqc_defaults() {
    OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
    OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-}"
    MODULE_DIR="${MODULE_DIR:-$REPO/build}"
    ROUND="${ROUND:-r5}"
    VER="${VER:-v3}"
    OUTDIR=""
    KEEP=0
    MODE="verify"
    STRICT="${STRICT:-0}"
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) SOEXT="${SOEXT:-dll}";;
        Darwin)               SOEXT="${SOEXT:-dylib}";;
        *)                    SOEXT="${SOEXT:-so}";;
    esac
}

pqc_usage() {
    awk 'NR > 2 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$0"
    local roundopt
    if [ "$PQC_KIND" = cms ]; then
        roundopt="  --version V       cms corpus version ($(pqc_zip))  (default: $VER)"
    else
        roundopt="  --round R         artifact round ($(pqc_zip)) (default: $ROUND)"
    fi
    cat <<EOF

Usage: $(basename "$0") [options] [verify|generate|all]

Options:
  --openssl PATH    openssl binary${PQC_OPENSSL_HINT:+ ($PQC_OPENSSL_HINT)}  (default: $OPENSSL_BIN)
  --libpath PATH    LD_LIBRARY_PATH for its libs  (default: none)
  --module-dir DIR  OPENSSL_MODULES with hybrid.$SOEXT (default: $MODULE_DIR)
  --peers "a b c"   provider dirs to verify   (default: $PEERS)
$roundopt
  --outdir DIR      generate output dir       (default: <module-dir>/$PQC_OUTNAME)
  --keep            keep the temp work dir
  --strict          unreachable / empty peer is FAIL, not SKIP
  -h, --help        this help
EOF
}

pqc_parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --openssl)    OPENSSL_BIN="$2"; shift 2;;
            --libpath)    OPENSSL_LIBPATH="$2"; shift 2;;
            --module-dir) MODULE_DIR="$2"; shift 2;;
            --peers)      PEERS="$2"; shift 2;;
            --round)      [ "$PQC_KIND" = certs ] || pqc_bad_arg "$1"
                          ROUND="$2"; shift 2;;
            --version)    [ "$PQC_KIND" = cms ] || pqc_bad_arg "$1"
                          VER="$2"; shift 2;;
            --outdir)     OUTDIR="$2"; shift 2;;
            --keep)       KEEP=1; shift;;
            --strict)     STRICT=1; shift;;
            -h|--help)    pqc_usage; exit 0;;
            verify|generate|all) MODE="$1"; shift;;
            *)            pqc_bad_arg "$1";;
        esac
    done
    # Absolutize MODULE_DIR: a relative `module =` in the provider cnf is resolved
    # relative to OPENSSL_MODULES, so a relative --module-dir makes OpenSSL look
    # for <dir>/<dir>/hybrid.so and silently skip the provider. Canonicalize first.
    [ -d "$MODULE_DIR" ] && MODULE_DIR="$(cd "$MODULE_DIR" && pwd)"
    : "${OUTDIR:=$MODULE_DIR/$PQC_OUTNAME}"
    [ -n "$OPENSSL_LIBPATH" ] \
        && export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    export OPENSSL_MODULES="$MODULE_DIR"
}
pqc_bad_arg() { echo "unknown argument: $1" >&2; pqc_usage >&2; exit 2; }

pqc_init_report() {
    if [ -t 1 ]; then C_OK=$'\033[32m'; C_NO=$'\033[31m'; C_SK=$'\033[33m'; C_Z=$'\033[0m'
    else C_OK=""; C_NO=""; C_SK=""; C_Z=""; fi
    pass=0; fail=0; skip=0
}
ok()   { echo "  ${C_OK}PASS${C_Z}  $*"; pass=$((pass+1)); }
no()   { echo "  ${C_NO}FAIL${C_Z}  $*"; fail=$((fail+1)); }
note() { echo "  ${C_SK}SKIP${C_Z}  $*"; skip=$((skip+1)); }
hdr()  { echo; echo "== $* =="; }
# A peer with nothing comparable: SKIP by default, FAIL under --strict.
miss() { if [ "$STRICT" -eq 1 ]; then no "$@"; else note "$@"; fi; }
skip_all() { echo "SKIP: $*"; exit 0; }

# The built provider module must exist before anything else is meaningful.
pqc_require_module() {
    if [ ! -f "$MODULE_DIR/hybrid.$SOEXT" ]; then
        echo "hybrid.$SOEXT not found in $MODULE_DIR -- build the provider first" >&2
        exit 1
    fi
}

# Temp work dir, the default + hybrid cnf, and the activation guard. default
# supplies the components (ML-DSA / ML-KEM / RSA / EC / X25519 / X448), hybrid
# supplies the composite algorithms (which own the composite OIDs).
pqc_setup() {
    WORKDIR="$(mktemp -d)"
    trap '[ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"' EXIT
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
    # Guard: OpenSSL silently drops a cnf-referenced provider that fails to load
    # (lazy, non-fatal activation: exit 0, nothing on stderr). Without the hybrid
    # provider active NOTHING owns the composite OIDs and every check just "fails"
    # with no hint why. The module file exists at this point, so a load failure is
    # a real fault (bad ABI, missing component dep, ...): fail loudly with the one
    # diagnostic OpenSSL won't give us.
    if ! oss list -providers 2>/dev/null | grep -q 'name: hybrid-provider'; then
        echo "ERROR: hybrid provider present at $MODULE_DIR/hybrid.$SOEXT but did not" >&2
        echo "       activate under $OPENSSL_BIN ($("$OPENSSL_BIN" version 2>/dev/null))." >&2
        echo "       Likely an ABI/libcrypto mismatch or a missing component dependency." >&2
        exit 1
    fi
}
oss() { OPENSSL_CONF="$HCNF" "$OPENSSL_BIN" "$@"; }

# Fetch + unpack a peer's corpus zip into $WORKDIR/<peer>. On failure reports a
# miss and returns 1.
pqc_fetch_peer() {   # $1 = peer
    local zip="$WORKDIR/$1.zip"
    if ! curl -fsSL "$RAW_BASE/$1/$(pqc_zip)" -o "$zip" 2>/dev/null || [ ! -s "$zip" ]; then
        miss "$1: no $(pqc_zip) (unreachable / absent)"; return 1
    fi
    mkdir -p "$WORKDIR/$1"; unzip -qo "$zip" -d "$WORKDIR/$1" 2>/dev/null
    : > "$WORKDIR/$1.oids"
}

# Per-peer verdict once its loop ran over n artifacts, p of which passed. Each
# failed artifact already raised its own FAIL; the summary line is a PASS only
# when all passed, so a total failure never shows as a green "0/N ... PASS".
pqc_peer_summary() {   # $1 = peer, $2 = n, $3 = p, $4 = what passing means, $5 = unit, $6 = miss text
    local dist msg
    if [ "$2" -eq 0 ]; then miss "$1: $6"; return; fi
    dist=$(sort -u "$WORKDIR/$1.oids" | wc -l)
    msg="$1: $dist distinct OIDs $4 ($3/$2 $5)"
    if [ "$3" -eq "$2" ]; then ok "$msg"; else no "$msg"; fi
}

# The verify mode around the script's verify_peer.
pqc_verify_all() {   # $1 = header, $2 = what passing means (for the total)
    hdr "$1"
    echo "  corpus: $(pqc_zip)   openssl: $("$OPENSSL_BIN" version 2>/dev/null)"
    : > "$WORKDIR/verified_oids"; : > "$WORKDIR/shipped_oids"
    local peer
    for peer in $PEERS; do verify_peer "$peer"; done
    if [ -s "$WORKDIR/shipped_oids" ]; then
        echo "  distinct OIDs $2 from >=1 peer: $(sort -u "$WORKDIR/verified_oids" | wc -l)" \
             "(of $(sort -u "$WORKDIR/shipped_oids" | wc -l) shipped)"
    fi
}

pqc_main() {
    case "$MODE" in
        verify)   cmd_verify;;
        generate) cmd_generate;;
        all)      cmd_verify; cmd_generate;;
    esac
    hdr "Summary ($MODE)"
    echo "  passed: $pass   failed: $fail   skipped: $skip"
    [ "$fail" -eq 0 ]
}
