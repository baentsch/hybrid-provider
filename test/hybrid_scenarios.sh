#!/usr/bin/env bash
#
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# Configurable harness for exercising the hybrid provider through the OpenSSL
# command-line tool, with selectable PQ and classic crypto providers.
#
# Settings may be given as command-line flags or in a --config file (a simple
# KEY=value file, sourced as shell). Precedence: CLI flag > config file >
# built-in default.
#
# ---------------------------------------------------------------------------
# WHAT THIS SCRIPT CAN AND CANNOT DO (and why)
#
# The hybrid provider implements no encoder/decoder, so a hybrid key cannot be
# written to (or read from) a file. That makes the file-based, multi-process
# KEM/signature round-trips impossible to express with the openssl CLI: every
# `genpkey -out`, `pkeyutl -sign`, etc. fails with "No encoders were found".
# Those scenarios are covered in-process (via raw OSSL_PARAM export/import) by
# the C test `hybrid_test` and cannot be reproduced here.
#
# CONFIGURATION IS CNF-ONLY, NEVER COMMAND LINE
#
# The hybrid provider is configurable ONLY through an openssl.cnf, never through
# `openssl -provider hybrid` on the command line. Two things force this:
#   * Its component-steering keys — pq-propquery, classic-propquery,
#     component-providers, component-path — live in the provider's config
#     section and have no command-line equivalent. component-providers /
#     component-path in particular build the provider's PRIVATE component
#     libctx (used to source Frodo/BIKE/HQC from oqsprovider without its group
#     names colliding in the application context); without them those groups
#     never register and `-groups p256_frodo640aes` fails.
#   * `-provider hybrid` loads the module into the application libctx with none
#     of the above keys set, so it cannot compose anything.
# Every hybrid-side invocation below therefore sets OPENSSL_CONF to a generated
# cnf and passes NO -provider flags. Only the pure-default / pure-oqsprovider
# peers use -provider flags.
#
# NOTE: the component-providers/component-path half of this is only cnf-only
# because oqsprovider currently registers TLS groups under the SAME names as
# this provider (hence the private context to dodge the collision). Once
# oqsprovider drops its hybrid combinations (redesign.md M8) and supplies only
# the base FrodoKEM/BIKE/HQC KEMs, that collision goes away and these groups
# become ordinary command-line-usable groups. The pq-propquery/classic-propquery
# steering keys stay cnf-only, but that is an OpenSSL limitation (single
# -propquery on the TLS path), not oqsprovider's, and only matters when the PQ
# and classic components must come from different providers.
#
# What IS reproducible on the CLI is the TLS 1.3 handshake: there the KEM keys
# live only in memory inside the handshake and are never serialized. This
# script therefore focuses on:
#   * info  — enumerate providers / KEMs / signatures / TLS groups in effect,
#             so you can see which provider supplies each algorithm;
#   * tls   — run real s_server/s_client handshakes (hybrid <-> default, both
#             directions, plus hybrid <-> hybrid) for each selected group;
#   * config— emit the openssl.cnf for the chosen settings.
#
# Provider selection:
#   --hybrid-provider {hybrid|default}
#       Which provider implements the hybrid KEM itself. Selected with the
#       optional property query "?provider=NAME".
#   --pq-provider NAME / --classic-provider NAME
#       PROPERTY name of the provider supplying the ML-KEM/ML-DSA and the
#       X25519/EC components (e.g. "bcrust", "default"). A provider's property
#       name may differ from its module name (bcrust_provider.so advertises
#       "provider=bcrust"); load the module separately with --extra-provider.
#       These are emitted into the generated openssl.cnf as the hybrid
#       provider's pq-propquery / classic-propquery keys, which steer each
#       component independently and also take effect on the TLS path. Use
#       --use-config so the generated cnf (and thus these keys) is in effect.
#   --extra-provider NAME
#       MODULE name of an extra provider to load (== .so basename, the value
#       you'd pass to `openssl -provider`), e.g. "bcrust_provider".
# ---------------------------------------------------------------------------

set -euo pipefail

# --- locate ourselves / sensible defaults --------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

OPENSSL_BIN="${OPENSSL_BIN:-$PROJECT_DIR/.local/bin/openssl}"
OPENSSL_LIBPATH="${OPENSSL_LIBPATH:-$PROJECT_DIR/.local/lib64}"
MODULE_DIR="${MODULE_DIR:-$PROJECT_DIR/build}"
HYBRID_PROVIDER="hybrid"
PQ_PROVIDER="default"
CLASSIC_PROVIDER="default"
EXTRA_PROVIDERS=""          # space-separated, e.g. "bcrust oqsprovider"
GROUP_LIST="X25519MLKEM768 SecP256r1MLKEM768 SecP384r1MLKEM1024"
# Groups whose PQ base comes only from oqsprovider (not in the default provider).
# The hybrid provider must use its private component context so these don't
# collide with oqsprovider's own group names in the application libctx.
COMPCTX_GROUPS="p256_frodo640aes x25519_frodo640aes p384_frodo976aes \
    x448_bikel3 p521_bikel5 \
    p256_hqc1 p384_hqc3 p521_hqc5"
PORT=14433
KEEP=0
USE_CONFIG=0                # drive openssl via generated cnf instead of flags
CONFIG_FILE=""
COMMAND=""
COMPONENT_PROVIDERS=""      # e.g. "default oqsprovider" for component-providers key

pass=0; fail=0; skip=0

# --- pretty output -------------------------------------------------------
if [ -t 1 ]; then C_OK=$'\033[32m'; C_NO=$'\033[31m'; C_SK=$'\033[33m'; C_Z=$'\033[0m'
else C_OK=""; C_NO=""; C_SK=""; C_Z=""; fi
ok()   { echo "  ${C_OK}PASS${C_Z}  $*"; pass=$((pass+1)); }
no()   { echo "  ${C_NO}FAIL${C_Z}  $*"; fail=$((fail+1)); }
note() { echo "  ${C_SK}SKIP${C_Z}  $*"; skip=$((skip+1)); }
hdr()  { echo; echo "== $* =="; }

usage() {
    sed -n '3,75p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [options] <command>

Commands:
  info        List providers, KEM/signature algorithms and TLS groups in effect.
  tls         Run TLS 1.3 handshake interop for each selected group.
  tls-compctx Run TLS 1.3 interop for Frodo/BIKE/HQC groups using the hybrid
              provider's private component context (component-providers key in
              openssl.cnf) so it sources the PQ base from oqsprovider without
              oqsprovider's groups colliding in the application libctx. Tests
              hybrid-vs-oqsprovider both directions. Self-skips when oqsprovider
              is not on the module path. Requires --module-dir to contain both
              hybrid.so and oqsprovider.so.
  config      Print the openssl.cnf for the current settings.
  all         Run info then tls.

Options (override config-file values):
  --openssl PATH            openssl binary           (default: $OPENSSL_BIN)
  --libpath PATH            LD_LIBRARY_PATH for libs  (default: $OPENSSL_LIBPATH)
  --module-dir DIR          OPENSSL_MODULES dir       (default: $MODULE_DIR)
  --hybrid-provider N       hybrid|default            (default: $HYBRID_PROVIDER)
  --pq-provider NAME        ML-KEM/ML-DSA component   (default: $PQ_PROVIDER)
  --classic-provider NAME   X25519/EC component       (default: $CLASSIC_PROVIDER)
  --extra-provider NAME     load an extra provider (repeatable), e.g. bcrust
  --groups "G1 G2 ..."      groups to test            (default: all 3)
  --component-providers "P1 P2"
                            providers loaded into the hybrid provider's own
                            libctx (component-providers config key), e.g.
                            "default oqsprovider". Required for tls-compctx.
  --port N                  base TCP port             (default: $PORT)
  --config FILE             read KEY=value settings from FILE
  --use-config              drive openssl via a generated cnf, not flags
  --keep                    keep the temp working directory
  -h, --help                this help
EOF
}

# --- argument parsing ----------------------------------------------------
# First pass: pick up --config so the file is the base, flags override it.
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
    if [ "${args[$i]}" = "--config" ]; then
        CONFIG_FILE="${args[$((i+1))]}"
    fi
done
if [ -n "$CONFIG_FILE" ]; then
    [ -r "$CONFIG_FILE" ] || { echo "config file not readable: $CONFIG_FILE" >&2; exit 2; }
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --openssl)            OPENSSL_BIN="$2"; shift 2;;
        --libpath)            OPENSSL_LIBPATH="$2"; shift 2;;
        --module-dir)         MODULE_DIR="$2"; shift 2;;
        --hybrid-provider) HYBRID_PROVIDER="$2"; shift 2;;
        --pq-provider)        PQ_PROVIDER="$2"; shift 2;;
        --classic-provider)   CLASSIC_PROVIDER="$2"; shift 2;;
        --extra-provider)     EXTRA_PROVIDERS="$EXTRA_PROVIDERS $2"; shift 2;;
        --component-providers) COMPONENT_PROVIDERS="$2"; shift 2;;
        --groups)             GROUP_LIST="$2"; shift 2;;
        --port)               PORT="$2"; shift 2;;
        --config)             shift 2;;          # already handled
        --use-config)         USE_CONFIG=1; shift;;
        --keep)               KEEP=1; shift;;
        -h|--help)            usage; exit 0;;
        info|tls|tls-compctx|config|all)  COMMAND="$1"; shift;;
        *) echo "unknown argument: $1" >&2; usage; exit 2;;
    esac
done
[ -n "$COMMAND" ] || { usage; exit 2; }

[ -x "$OPENSSL_BIN" ] || { echo "openssl not executable: $OPENSSL_BIN" >&2; exit 2; }
export LD_LIBRARY_PATH="$OPENSSL_LIBPATH${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export OPENSSL_MODULES="$MODULE_DIR"

# Providers to LOAD, identified by their module/-provider name (== the .so
# basename, e.g. "hybrid", "bcrust_provider", "oqsprovider"). This is distinct
# from a provider's PROPERTY name used in queries (e.g. bcrust_provider.so
# advertises "provider=bcrust"); --pq-provider/--classic-provider take the
# property name, --extra-provider takes the module name. To source a component
# from bcrust you therefore pass both:
#     --extra-provider bcrust_provider --pq-provider bcrust
ALL_PROVIDERS="default"
for p in $HYBRID_PROVIDER $EXTRA_PROVIDERS; do
    case " $ALL_PROVIDERS " in *" $p "*) :;; *) ALL_PROVIDERS="$ALL_PROVIDERS $p";; esac
done

# Build "-provider X" flags for a given provider list.
prov_flags() { local f=""; for p in $1; do f="$f -provider $p"; done; echo "$f"; }

# Component property query from the chosen PQ/classic providers.
component_propq() {
    if [ "$PQ_PROVIDER" = "$CLASSIC_PROVIDER" ] && [ "$PQ_PROVIDER" = "default" ]; then
        echo ""                       # plain default, no query needed
    elif [ "$PQ_PROVIDER" = "$CLASSIC_PROVIDER" ]; then
        echo "?provider=$PQ_PROVIDER"
    else
        echo "?provider=$PQ_PROVIDER"  # single query; classic falls back
    fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/hybrid-scenarios.XXXXXX")"
cleanup() { [ "$KEEP" = 1 ] || rm -rf "$WORKDIR"; }
trap cleanup EXIT
[ "$KEEP" = 1 ] && echo "working dir: $WORKDIR (kept)"

# --- generated openssl.cnf ----------------------------------------------
gen_config() {
    local cnf="$WORKDIR/openssl.cnf" p sect
    {
        echo "# generated by hybrid_scenarios.sh"
        echo "openssl_conf = osslcfg"
        echo "[osslcfg]"
        echo "providers = prov_sect"
        echo "alg_section = evp_props"
        echo "[evp_props]"
        echo "default_properties = ?provider=$HYBRID_PROVIDER"
        echo "[prov_sect]"
        for p in $ALL_PROVIDERS; do echo "$p = ${p}_sect"; done
        for p in $ALL_PROVIDERS; do
            sect="${p}_sect"
            echo "[$sect]"
            # default lives in libcrypto; others are loadable modules.
            [ "$p" = "default" ] || echo "module = $MODULE_DIR/${p}.so"
            echo "activate = 1"
            # Steer the hybrid provider's components to the chosen providers.
            if [ "$p" = "hybrid" ]; then
                [ "$PQ_PROVIDER" = "default" ] \
                    || echo "pq-propquery = ?provider=$PQ_PROVIDER"
                [ "$CLASSIC_PROVIDER" = "default" ] \
                    || echo "classic-propquery = ?provider=$CLASSIC_PROVIDER"
                # Private component context: the hybrid provider loads these
                # providers into its OWN libctx so their group registrations
                # don't collide with oqsprovider's in the application context.
                # component-path tells the hybrid provider where to find those
                # component modules (oqsprovider.so) in its private libctx.
                if [ -n "$COMPONENT_PROVIDERS" ]; then
                    echo "component-providers = $COMPONENT_PROVIDERS"
                    echo "component-path = $MODULE_DIR"
                fi
            fi
        done
    } > "$cnf"
    echo "$cnf"
}

# Run openssl either with explicit -provider flags or via generated cnf.
run_ossl() {  # args: openssl subcommand and its args
    if [ "$USE_CONFIG" = 1 ]; then
        OPENSSL_CONF="$(gen_config)" "$OPENSSL_BIN" "$@"
    else
        OPENSSL_CONF=/dev/null "$OPENSSL_BIN" "$@"
    fi
}

# ========================================================================
# info
# ========================================================================
cmd_info() {
    local pf; pf="$(prov_flags "$ALL_PROVIDERS")"
    hdr "Configuration"
    echo "  openssl           : $OPENSSL_BIN ($("$OPENSSL_BIN" version | cut -d' ' -f1-2))"
    echo "  module dir        : $MODULE_DIR"
    echo "  providers loaded  : $ALL_PROVIDERS"
    echo "  hybrid provider: $HYBRID_PROVIDER"
    echo "  pq / classic      : $PQ_PROVIDER / $CLASSIC_PROVIDER"
    echo "  component propq   : '$(component_propq)'"
    echo "  groups            : $GROUP_LIST"
    echo "  driven via        : $([ "$USE_CONFIG" = 1 ] && echo 'openssl.cnf' || echo '-provider flags')"

    hdr "KEM algorithms (alg @ provider)"
    # shellcheck disable=SC2086
    run_ossl list -kem-algorithms $pf 2>/dev/null \
        | grep -iE "MLKEM" | sed 's/^ */  /' || echo "  (none)"

    hdr "Signature algorithms (hybrid)"
    # shellcheck disable=SC2086
    run_ossl list -signature-algorithms $pf 2>/dev/null \
        | grep -iE "mldsa" | sed 's/^ */  /' || echo "  (none)"

    hdr "TLS groups"
    # shellcheck disable=SC2086
    run_ossl list -tls-groups $pf 2>/dev/null \
        | tr ':' '\n' | grep -iE "MLKEM" | sed 's/^/  /' || echo "  (none)"
}

# ========================================================================
# tls — real handshakes over the loopback
# ========================================================================
make_cert() {   # server cert/key via default provider
    run_ossl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$WORKDIR/server.key" -out "$WORKDIR/server.crt" \
        -days 1 -subj "/CN=hybrid-scenarios" -provider default >/dev/null 2>&1
}

wait_listen() {  # $1 = port — TCP-level probe only (a TLS probe would need to
                 # match the server's restricted group, which we don't know here)
    local i
    for i in $(seq 1 50); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# one handshake: $1=group  $2=server-side  $3=client-side  ("hybrid"|"default")
PORT_SEQ=0
handshake() {
    local group="$1" sside="$2" cside="$3"
    # Fresh port each time: a reused port lands in TIME-WAIT and the next
    # s_server fails to bind.
    local port=$((PORT + PORT_SEQ)); PORT_SEQ=$((PORT_SEQ + 1))
    local sprov spropq cprov cpropq srvlog clilog rc=0
    srvlog="$WORKDIR/srv.log"; clilog="$WORKDIR/cli.log"

    if [ "$sside" = "hybrid" ]; then
        sprov="$(prov_flags "$ALL_PROVIDERS")"; spropq="?provider=$HYBRID_PROVIDER"
    else
        sprov="-provider default"; spropq="?provider=default"
    fi
    if [ "$cside" = "hybrid" ]; then
        cprov="$(prov_flags "$ALL_PROVIDERS")"; cpropq="?provider=$HYBRID_PROVIDER"
    else
        cprov="-provider default"; cpropq="?provider=default"
    fi

    # shellcheck disable=SC2086
    OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_server -accept "$port" \
        -cert "$WORKDIR/server.crt" -key "$WORKDIR/server.key" -tls1_3 \
        $sprov -propquery "$spropq" -groups "$group" -www -quiet \
        >"$srvlog" 2>&1 &
    local srvpid=$!

    if ! wait_listen "$port"; then
        kill "$srvpid" 2>/dev/null || true; wait "$srvpid" 2>/dev/null || true
        no "$group  server=$sside client=$cside  (server did not start)"
        sed 's/^/        /' "$srvlog" | head -3
        return
    fi

    # shellcheck disable=SC2086
    echo Q | OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_client \
        -connect "localhost:$port" -tls1_3 $cprov -groups "$group" \
        >"$clilog" 2>&1 || rc=$?
    kill "$srvpid" 2>/dev/null || true; wait "$srvpid" 2>/dev/null || true

    local ng
    ng="$(grep -iE "Negotiated .*group" "$clilog" | head -1 | sed 's/.*: *//')"
    if grep -qiE "Cipher is TLS_" "$clilog" \
       && ! grep -qiE "handshake failure|alert|:error:" "$clilog"; then
        ok "$group  server=$sside client=$cside${ng:+  (group: $ng)}"
    else
        no "$group  server=$sside client=$cside"
        grep -iE "error|alert|fail" "$clilog" | head -2 | sed 's/^/        /'
    fi
}

cmd_tls() {
    if ! make_cert; then
        echo "could not generate server certificate" >&2; exit 1
    fi
    hdr "TLS 1.3 handshake interop (hybrid provider: $HYBRID_PROVIDER)"
    for g in $GROUP_LIST; do
        handshake "$g" hybrid  default
        handshake "$g" default hybrid
        handshake "$g" hybrid  hybrid
    done
}

# ========================================================================
# tls-compctx — Frodo/BIKE/HQC via the hybrid provider's private component
# context (component-providers key).  The hybrid provider sources the PQ base
# from oqsprovider in its OWN libctx, so the application context holds only
# default + hybrid; oqsprovider's group registrations don't collide, and
# these groups resolve unambiguously to the hybrid implementation.
# The peer (the non-hybrid side) uses oqsprovider directly.
# ========================================================================
cmd_tls_compctx() {
    # oqsprovider.so must exist on the module path.
    if [ ! -f "$MODULE_DIR/oqsprovider.so" ]; then
        note "oqsprovider.so not found in $MODULE_DIR — skipping tls-compctx"
        return
    fi

    hdr "TLS 1.3 Frodo/BIKE/HQC — hybrid (compctx) vs oqsprovider"

    # Override settings for this command: the hybrid side uses the private
    # component context; the oqsprovider side uses oqsprovider directly.
    local saved_extra saved_comp saved_pq saved_use
    saved_extra="$EXTRA_PROVIDERS"
    saved_comp="$COMPONENT_PROVIDERS"
    saved_pq="$PQ_PROVIDER"
    saved_use="$USE_CONFIG"

    COMPONENT_PROVIDERS="default oqsprovider"
    EXTRA_PROVIDERS=""        # hybrid's component ctx loads oqsprovider privately;
                              # don't expose it in the application context
    PQ_PROVIDER="default"     # application-context component query (irrelevant —
                              # overridden by the private ctx, but must be set)
    USE_CONFIG=1              # component-providers only works via openssl.cnf

    if ! make_cert; then
        echo "could not generate server certificate" >&2; exit 1
    fi

    local g
    for g in $COMPCTX_GROUPS; do
        # hybrid server, oqsprovider client
        handshake_compctx "$g" hybrid oqs
        # oqsprovider server, hybrid client
        handshake_compctx "$g" oqs hybrid
    done

    EXTRA_PROVIDERS="$saved_extra"
    COMPONENT_PROVIDERS="$saved_comp"
    PQ_PROVIDER="$saved_pq"
    USE_CONFIG="$saved_use"
}

# One handshake for tls-compctx. $1=group  $2=server ("hybrid"|"oqs")
#   $3=client ("hybrid"|"oqs").
# hybrid side: loaded via the generated cnf (has component-providers key).
# oqs side: only default + oqsprovider, no hybrid.
handshake_compctx() {
    local group="$1" sside="$2" cside="$3"
    local port=$((PORT + PORT_SEQ)); PORT_SEQ=$((PORT_SEQ + 1))
    local sprov scnf cprov ccnf srvlog clilog rc=0
    srvlog="$WORKDIR/srv_cc.log"; clilog="$WORKDIR/cli_cc.log"

    local oqs_prov_flags="-provider default -provider oqsprovider"

    # Hybrid side: the provider MUST be configured entirely through a cnf, never
    # via -provider CLI flags. The component-providers / component-path keys that
    # build the hybrid provider's private component libctx only exist in the cnf;
    # there is no command-line equivalent (see the CONFIGURATION note at the top
    # of this file). Point OPENSSL_CONF at a minimal cnf carrying those keys.
    local compctx_cnf="$WORKDIR/compctx.cnf"
    if [ ! -f "$compctx_cnf" ]; then
        cat > "$compctx_cnf" <<CNFEOF
openssl_conf = osslcfg
[osslcfg]
providers = prov_sect
[prov_sect]
default = default_sect
hybrid = hybrid_sect
[default_sect]
activate = 1
[hybrid_sect]
module = $MODULE_DIR/hybrid.so
activate = 1
component-providers = default oqsprovider
component-path = $MODULE_DIR
CNFEOF
    fi
    # Hybrid side: providers activated ENTIRELY via the cnf (no -provider CLI
    # flags). The cnf's [hybrid_sect] carries the component-providers key, which
    # the hybrid provider reads at init to build its private component libctx
    # (default + oqsprovider). The outer/app libctx therefore contains ONLY
    # default + hybrid — no oqsprovider group-name collision — and the Frodo/
    # BIKE/HQC groups resolve unambiguously to the hybrid provider.
    # oqs side: no cnf (OPENSSL_CONF=/dev/null), providers via CLI flags only.
    if [ "$sside" = "hybrid" ]; then
        OPENSSL_CONF="$compctx_cnf" "$OPENSSL_BIN" s_server -accept "$port" \
            -cert "$WORKDIR/server.crt" -key "$WORKDIR/server.key" -tls1_3 \
            -groups "$group" -www -quiet \
            >"$srvlog" 2>&1 &
    else
        OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_server -accept "$port" \
            $oqs_prov_flags -groups "$group" \
            -cert "$WORKDIR/server.crt" -key "$WORKDIR/server.key" -tls1_3 \
            -www -quiet \
            >"$srvlog" 2>&1 &
    fi
    local srvpid=$!

    if ! wait_listen "$port"; then
        kill "$srvpid" 2>/dev/null || true; wait "$srvpid" 2>/dev/null || true
        no "$group  server=$sside client=$cside  (server did not start)"
        sed 's/^/        /' "$srvlog" | head -3
        return
    fi

    if [ "$cside" = "hybrid" ]; then
        echo Q | OPENSSL_CONF="$compctx_cnf" "$OPENSSL_BIN" s_client \
            -connect "localhost:$port" -tls1_3 -groups "$group" \
            >"$clilog" 2>&1 || rc=$?
    else
        echo Q | OPENSSL_CONF=/dev/null "$OPENSSL_BIN" s_client \
            $oqs_prov_flags -groups "$group" \
            -connect "localhost:$port" -tls1_3 \
            >"$clilog" 2>&1 || rc=$?
    fi
    kill "$srvpid" 2>/dev/null || true; wait "$srvpid" 2>/dev/null || true

    local ng
    ng="$(grep -iE "Negotiated .*group" "$clilog" | head -1 | sed 's/.*: *//')"
    if grep -qiE "Cipher is TLS_" "$clilog" \
       && ! grep -qiE "handshake failure|alert|:error:" "$clilog"; then
        ok "$group  server=$sside client=$cside${ng:+  (group: $ng)}"
    else
        no "$group  server=$sside client=$cside"
        grep -iE "error|alert|fail" "$clilog" | head -2 | sed 's/^/        /'
    fi
}

# ========================================================================
case "$COMMAND" in
    info)        cmd_info;;
    tls)         cmd_tls;;
    tls-compctx) cmd_tls_compctx;;
    config)      gen_config >/dev/null; cat "$WORKDIR/openssl.cnf";;
    all)         cmd_info; cmd_tls;;
esac

if [ "$COMMAND" = "tls" ] || [ "$COMMAND" = "tls-compctx" ] || [ "$COMMAND" = "all" ]; then
    hdr "Summary"
    echo "  passed: $pass   failed: $fail   skipped: $skip"
    echo
    echo "  Note: independent PQ/classic component selection is driven by the"
    echo "  generated cnf's pq-propquery/classic-propquery keys (use --use-config)."
    echo "  File-based KEM/signature round-trips remain C-only ('hybrid_test') —"
    echo "  the hybrid provider has no encoder, so its keys cannot be serialized."
    [ "$fail" -eq 0 ] || exit 1
fi
