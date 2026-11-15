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
#
# What is tested is selectable (env or option; the defaults test this provider):
#   PQC_FAMILY    composite (the LAMPS composite arc, served by hybrid) or
#                 nist-pq (plain ML-DSA / SLH-DSA / ML-KEM from a component
#                 provider: "pass-through", hybrid is not involved)
#   PQC_PROVIDERS providers to load, each "name" or "name=/path/module" (default:
#                 "default hybrid"). For nist-pq, drop hybrid to qualify a component
#                 provider alone; keep it to check co-loading hybrid breaks nothing.
#   PQC_PROPQ     optional default property query (e.g. "?provider=oqsprovider")
#                 to pin which loaded provider serves a contested algorithm.
#
# The drift script only uses ARC and the pqc_* OID helpers; sourcing this file
# has no side effects beyond defining variables and functions.

# OID families. ARC is the regex every artifact is keyed on.
#  composite: the whole LAMPS composite arc (sigs .37..54, KEMs .55..66). The KEM
#    scripts match all of it, not just the OIDs we serve today: only KEMs ship
#    decaps vectors and KEMRI blobs, so the match stays KEM-only, and a NEW
#    composite OID in the corpus is tried instead of being silently ignored.
#  nist-pq: the NIST CSOR OIDs of FIPS 203/204/205 (frozen; curated by hand):
#    sigAlgs .3.17-19 ML-DSA, .3.20-31 SLH-DSA, .3.32-34 HashML-DSA,
#    .3.35-46 HashSLH-DSA; kems .4.1-3 ML-KEM.
ARC_COMPOSITE='1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'
ARC_NIST_PQ='2\.16\.840\.1\.101\.3\.4\.(3\.(1[7-9]|[23][0-9]|4[0-6])|4\.[1-3])'
ARC="$ARC_COMPOSITE"

RAW_BASE="https://raw.githubusercontent.com/IETF-Hackathon/pqc-certificates/master/providers"

# ---- OID helpers --------------------------------------------------------------

# The family's OIDs a DER file embeds, one per line, sorted and de-duplicated.
# asn1parse prints an OID by name when libcrypto knows one (3.5+ names ML-DSA-44
# etc.), so each OBJECT is decoded from its own content bytes (X.690 8.19) at the
# offset asn1parse reports, independent of any name table. Null cnf: no providers.
pqc_embedded_oids() {   # $1 = DER file
    local off hl len
    OPENSSL_CONF=/dev/null "${OPENSSL_BIN:-openssl}" asn1parse -inform DER -in "$1" \
            2>/dev/null \
        | sed -nE 's/^ *([0-9]+):d=[0-9]+ +hl= *([0-9]+) +l= *([0-9]+) +prim: +OBJECT.*/\1 \2 \3/p' \
        | while read -r off hl len; do
            od -An -tu1 -v -j $((off + hl)) -N "$len" "$1" | tr -s ' \n' '  ' \
                | awk '{ f = $1; a = (f < 40) ? 0 : (f < 80) ? 1 : 2
                         o = a "." (f - 40 * a); v = 0
                         for (i = 2; i <= NF; i++) {
                             v = v * 128 + $i % 128
                             if ($i < 128) { o = o "." v; v = 0 } }
                         print o }'
        done | grep -xE "$ARC" | sort -u
}

# Filename vs content: the corpus names each artifact after its OID, and the
# verify loops key every result on that name. This checks the file embeds exactly
# that one OID of the family, i.e. the key's algorithm (and, for a self-signed
# trust anchor, its signature algorithm too). A mislabelled artifact would
# otherwise be counted under the wrong OID. Returns 0 if coherent; else 1, with
# the reason on stdout. Only for files that carry a single such OID: PKCS#8 keys,
# self-signed _ta certs and KEMRI EnvelopedData. A KEM _ee cert does not qualify,
# since its CA may sign with an OID of the same family.
pqc_oid_check() {   # $1 = DER file, $2 = OID from its filename
    local emb
    emb="$(pqc_embedded_oids "$1" | tr '\n' ' ')"
    [ "$emb" = "$2 " ] && return 0
    if [ -z "$emb" ]; then
        echo "$(basename "$1"): no OID of the family inside (unparseable DER?)," \
             "expected its filename OID $2"
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

# The filename OID of an artifact, or nothing when the name does not carry
# exactly one OID. Names with two (catalyst_<a>_with_<b>, chameleon_..., an older
# composite form) are multi-algorithm artifacts, not the single algorithm a
# family checks, so they are left out.
pqc_name_oid() {   # $1 = artifact path
    local b; b="$(basename "$1")"
    [ "$(grep -oE '[0-9]+(\.[0-9]+){3,}' <<< "$b" | wc -l)" -eq 1 ] || return 0
    grep -oE "$ARC" <<< "$b" | head -1
}

# Every private key shipped for an artifact base: <base>_priv.der plus the
# per-form variants (_seed_priv.der, _expandedkey_priv.der, _both_priv.der for
# ML-DSA / ML-KEM). One path per line.
pqc_privs() {   # $1 = artifact base (path without its _<suffix>)
    local f
    for f in "$1"_priv.der "$1"_*_priv.der; do [ -f "$f" ] && echo "$f"; done
    return 0
}

# Can the loaded providers decode it at all? An algorithm (or key form) no loaded
# provider serves is a miss (SKIP, FAIL under --strict), not a wrong result.
pqc_cert_loadable() { oss x509 -in "$1" -noout -pubkey >/dev/null 2>&1; }
pqc_key_loadable()  { oss pkey -in "$1" -inform DER -noout >/dev/null 2>&1; }

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
    PQC_FAMILY="${PQC_FAMILY:-composite}"
    PQC_PROVIDERS="${PQC_PROVIDERS:-default hybrid}"
    PQC_PROPQ="${PQC_PROPQ:-}"
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
    cat <<USAGE

Usage: $(basename "$0") [options] [verify|generate|all]

Options:
  --openssl PATH    openssl binary${PQC_OPENSSL_HINT:+ ($PQC_OPENSSL_HINT)}  (default: $OPENSSL_BIN)
  --libpath PATH    LD_LIBRARY_PATH for its libs  (default: none)
  --module-dir DIR  OPENSSL_MODULES with hybrid.$SOEXT (default: $MODULE_DIR)
  --peers "a b c"   provider dirs to verify   (default: $PEERS)
$roundopt
  --family F        composite | nist-pq       (default: $PQC_FAMILY)
  --providers "..." providers to load: "name" or "name=/path/module" each
                    (default: $PQC_PROVIDERS)
  --propquery Q     default property query, e.g. "?provider=oqsprovider"
  --outdir DIR      generate output dir       (default: <module-dir>/$PQC_OUTNAME)
  --keep            keep the temp work dir
  --strict          unreachable / empty peer / unserved algorithm is FAIL, not SKIP
  -h, --help        this help
USAGE
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
            --family)     PQC_FAMILY="$2"; shift 2;;
            --providers)  PQC_PROVIDERS="$2"; shift 2;;
            --propquery)  PQC_PROPQ="$2"; shift 2;;
            --outdir)     OUTDIR="$2"; shift 2;;
            --keep)       KEEP=1; shift;;
            --strict)     STRICT=1; shift;;
            -h|--help)    pqc_usage; exit 0;;
            verify|generate|all) MODE="$1"; shift;;
            *)            pqc_bad_arg "$1";;
        esac
    done
    case "$PQC_FAMILY" in
        composite) ARC="$ARC_COMPOSITE";;
        nist-pq)   ARC="$ARC_NIST_PQ";;
        *)         echo "unknown --family: $PQC_FAMILY (composite | nist-pq)" >&2; exit 2;;
    esac
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
# Nothing comparable (peer, or an algorithm no loaded provider serves): SKIP by
# default, FAIL under --strict.
miss() { if [ "$STRICT" -eq 1 ]; then no "$@"; else note "$@"; fi; }
skip_all() { echo "SKIP: $*"; exit 0; }

# Is NAME one of the providers to load?
pqc_has_provider() {   # $1 = name
    local e; for e in $PQC_PROVIDERS; do [ "${e%%=*}" = "$1" ] && return 0; done
    return 1
}

# The built provider module must exist before anything else is meaningful (when
# hybrid is to be loaded at all).
pqc_require_module() {
    pqc_has_provider hybrid || return 0
    if [ ! -f "$MODULE_DIR/hybrid.$SOEXT" ]; then
        echo "hybrid.$SOEXT not found in $MODULE_DIR -- build the provider first" >&2
        exit 1
    fi
}

# Temp work dir, the provider cnf, and the activation guard. By default, default
# supplies the components (ML-DSA / ML-KEM / RSA / EC / X25519 / X448) and hybrid
# the composite algorithms (which own the composite OIDs). A bare name is a
# built-in or resolved in OPENSSL_MODULES (hybrid: $MODULE_DIR/hybrid.$SOEXT);
# name=/path names the module explicitly.
pqc_setup() {
    local e name mod listed
    WORKDIR="$(mktemp -d)"
    trap '[ "$KEEP" -eq 1 ] || rm -rf "$WORKDIR"' EXIT
    HCNF="$WORKDIR/providers.cnf"
    {
        echo "openssl_conf = c"
        echo "[c]"
        echo "providers = p"
        [ -n "$PQC_PROPQ" ] && echo "alg_section = a"
        echo "[p]"
        for e in $PQC_PROVIDERS; do echo "${e%%=*} = s_${e%%=*}"; done
        for e in $PQC_PROVIDERS; do
            name="${e%%=*}"; mod=""
            [ "$e" != "$name" ] && mod="${e#*=}"
            [ "$name" = hybrid ] && [ -z "$mod" ] && mod="$MODULE_DIR/hybrid.$SOEXT"
            echo "[s_$name]"
            [ -n "$mod" ] && echo "module = $mod"
            echo "activate = 1"
        done
        [ -n "$PQC_PROPQ" ] && printf '[a]\ndefault_properties = %s\n' "$PQC_PROPQ"
    } > "$HCNF"
    # Guard: OpenSSL silently drops a cnf-referenced provider that fails to load
    # (lazy, non-fatal activation: exit 0, nothing on stderr); `list -providers`
    # then just omits it, and every check would "fail" with no hint why. Fail
    # loudly instead, with the one diagnostic OpenSSL won't give us.
    listed="$(oss list -providers 2>/dev/null)"
    for e in $PQC_PROVIDERS; do
        name="${e%%=*}"
        grep -qx "  $name" <<< "$listed" && continue
        echo "ERROR: provider '$name' did not activate under $OPENSSL_BIN" \
             "($("$OPENSSL_BIN" version 2>/dev/null))." >&2
        echo "       Likely a wrong module path, an ABI/libcrypto mismatch or a" \
             "missing component dependency." >&2
        exit 1
    done
}
oss() { OPENSSL_CONF="$HCNF" "$OPENSSL_BIN" "$@"; }

# generate writes THIS provider's composite artifacts for a corpus submission, so
# it needs the composite family with hybrid loaded.
pqc_can_generate() {
    [ "$PQC_FAMILY" = composite ] && pqc_has_provider hybrid && return 0
    note "generate writes hybrid-provider's composite artifacts:" \
         "needs --family composite with hybrid in --providers"
    return 1
}

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

# Per-peer verdict once its loop ran: n artifacts tried, p passed, u not loadable
# by the loaded providers (each already reported). Each failed artifact raised its
# own FAIL; the summary is a PASS only when every loadable one passed, so a total
# failure never shows as a green "0/N ... PASS".
pqc_peer_summary() {   # $1 = peer, $2 = n, $3 = p, $4 = passing means, $5 = unit, $6 = miss text, [$7 = u]
    local dist msg u="${7:-0}" uns=""
    if [ "$2" -eq 0 ]; then miss "$1: $6"; return; fi
    [ "$u" -eq "$2" ] && return     # nothing loadable: the per-artifact misses say it
    [ "$u" -gt 0 ] && uns=", $u not loadable"
    dist=$(sort -u "$WORKDIR/$1.oids" | wc -l)
    msg="$1: $dist distinct OIDs $4 ($3/$(($2 - u)) $5$uns)"
    if [ "$3" -eq $(($2 - u)) ]; then ok "$msg"; else no "$msg"; fi
}

# The verify mode around the script's verify_peer.
pqc_verify_all() {   # $1 = header, $2 = what passing means (for the total)
    hdr "$1"
    echo "  corpus: $(pqc_zip)   openssl: $("$OPENSSL_BIN" version 2>/dev/null)"
    echo "  family: $PQC_FAMILY   providers: $PQC_PROVIDERS${PQC_PROPQ:+   propquery: $PQC_PROPQ}"
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
