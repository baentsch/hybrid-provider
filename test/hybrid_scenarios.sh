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
PORT=14433
KEEP=0
USE_CONFIG=0                # drive openssl via generated cnf instead of flags
CONFIG_FILE=""
COMMAND=""

pass=0; fail=0; skip=0

# --- pretty output -------------------------------------------------------
if [ -t 1 ]; then C_OK=$'\033[32m'; C_NO=$'\033[31m'; C_SK=$'\033[33m'; C_Z=$'\033[0m'
else C_OK=""; C_NO=""; C_SK=""; C_Z=""; fi
ok()   { echo "  ${C_OK}PASS${C_Z}  $*"; pass=$((pass+1)); }
no()   { echo "  ${C_NO}FAIL${C_Z}  $*"; fail=$((fail+1)); }
note() { echo "  ${C_SK}SKIP${C_Z}  $*"; skip=$((skip+1)); }
hdr()  { echo; echo "== $* =="; }

usage() {
    sed -n '3,51p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Usage: $(basename "$0") [options] <command>

Commands:
  info        List providers, KEM/signature algorithms and TLS groups in effect.
  tls         Run TLS 1.3 handshake interop for each selected group.
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
        --groups)             GROUP_LIST="$2"; shift 2;;
        --port)               PORT="$2"; shift 2;;
        --config)             shift 2;;          # already handled
        --use-config)         USE_CONFIG=1; shift;;
        --keep)               KEEP=1; shift;;
        -h|--help)            usage; exit 0;;
        info|tls|config|all)  COMMAND="$1"; shift;;
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
case "$COMMAND" in
    info)   cmd_info;;
    tls)    cmd_tls;;
    config) gen_config >/dev/null; cat "$WORKDIR/openssl.cnf";;
    all)    cmd_info; cmd_tls;;
esac

if [ "$COMMAND" = "tls" ] || [ "$COMMAND" = "all" ]; then
    hdr "Summary"
    echo "  passed: $pass   failed: $fail   skipped: $skip"
    echo
    echo "  Note: independent PQ/classic component selection is driven by the"
    echo "  generated cnf's pq-propquery/classic-propquery keys (use --use-config)."
    echo "  File-based KEM/signature round-trips remain C-only ('hybrid_test') —"
    echo "  the hybrid provider has no encoder, so its keys cannot be serialized."
    [ "$fail" -eq 0 ] || exit 1
fi
