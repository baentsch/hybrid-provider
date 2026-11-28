#!/bin/bash
# =============================================================================
# Container entrypoint for the hybrid-provider downstream demo.
#
#   server    (default) start nginx offering EVERY hybrid group the hybrid
#             provider serves in this image, in the foreground, until the
#             container stops. Validate it with connect.sh.
#             Also starts a second nginx on HYP_OQS_PORT (default 4434) under
#             the stock cnf, where oqsprovider serves its OWN hybrids, for
#             interop.sh. HYP_OQS_PORT=0 disables it.
#   selftest  start the server in the background, run connect.sh against it,
#             exit with connect.sh's result (one-shot, for CI).
#   interop   start both servers in the background, run interop.sh (every
#             shared group, every client/server stack pairing), exit with its
#             result (one-shot).
#   <cmd>     run any other command unchanged (noconf.sh, bash, ...).
# =============================================================================
set -u
# Component steering defaults to max (every group; see hyp-env.sh). selftest is
# the three-provider provenance proof, so it defaults to strict instead.
[ "${1:-server}" = selftest ] && export HYP_STEERING="${HYP_STEERING:-strict}"
. "$(dirname "$0")/hyp-env.sh"

hr() { printf '\n========== %s ==========\n' "$1"; }

prepare_server() {
    local groups

    hyp_prepare_cnf || return 1
    export OPENSSL_CONF="$ACTIVE_CNF"

    hr "component steering: HYP_STEERING=${HYP_STEERING} (active openssl.cnf)"
    grep -E '^(component-providers|alg[0-9]+-propquery)' "$ACTIVE_CNF" | sed 's/^/    /'

    hr "config-only change: diff stock vs hybrid openssl.cnf"
    diff -u "$STOCK_CNF" "$HYBRID_CNF" | sed 's/^/    /'

    if [ -n "${HYP_SERVER_GROUPS:-}" ]; then
        groups=$(echo "$HYP_SERVER_GROUPS" | tr ': ' '\n\n' | grep -v '^$')
    else
        groups=$(hyp_hybrid_groups)
    fi
    if [ -z "$groups" ]; then
        echo "FAIL: the hybrid provider serves no TLS groups under $ACTIVE_CNF" >&2
        echo "      (check: openssl list -providers must list hybrid)" >&2
        return 1
    fi
    echo "$groups" >"$GROUPS_FILE"

    # Mark the names the stock cnf (no plugin) also offers, e.g. oqsprovider's
    # own hybrids: here they are served by the hybrid provider instead.
    OPENSSL_CONF="$STOCK_CNF" "$OPENSSL" list -tls-groups 2>/dev/null | tr ':' '\n' \
        >"${HYP_STATE}/stock-groups"
    hr "hybrid groups offered ($(wc -l <"$GROUPS_FILE")); * = name also offered by the stock cnf"
    while read -r g; do
        grep -qxF "$g" "${HYP_STATE}/stock-groups" && echo "    * $g" || echo "      $g"
    done <"$GROUPS_FILE"

    # The template is a valid single-group config; offer the full list here.
    sed -e "s|^\( *ssl_ecdh_curve \).*;|\1$(paste -sd: "$GROUPS_FILE");|" \
        -e "s|^\( *listen \+\)[0-9]\+|\1${HYP_PORT}|" \
        "$NGINX_TEMPLATE" >"$NGINX_CONF"
    "$NGINX" -p "$NGINX_PREFIX" -c "$NGINX_CONF" -t -q || return 1
}

# Second server: same nginx, same certificate, but the STOCK cnf (default +
# oqsprovider, no hybrid provider), offering the groups both stacks serve.
prepare_oqs_server() {
    [ "${HYP_OQS_PORT}" != 0 ] || return 0
    hyp_shared_groups >"$OQS_GROUPS_FILE"
    if [ ! -s "$OQS_GROUPS_FILE" ]; then
        echo "NOTE: no group is served by both stacks; not starting the oqsprovider server" >&2
        HYP_OQS_PORT=0
        return 0
    fi
    hr "interop server: oqsprovider's own hybrids on port ${HYP_OQS_PORT} ($(wc -l <"$OQS_GROUPS_FILE") groups also served by the hybrid provider)"
    sed 's/^/      /' "$OQS_GROUPS_FILE"
    sed -e "s|^\( *ssl_ecdh_curve \).*;|\1$(paste -sd: "$OQS_GROUPS_FILE");|" \
        -e "s|^\( *listen \+\)[0-9]\+|\1${HYP_OQS_PORT}|" \
        -e "s|logs/nginx\.pid|logs/nginx-oqs.pid|" \
        -e "s|${KEM_LOG}|${OQS_KEM_LOG}|" \
        "$NGINX_TEMPLATE" >"$OQS_NGINX_CONF"
    OPENSSL_CONF="$STOCK_CNF" "$NGINX" -p "$NGINX_PREFIX" -c "$OQS_NGINX_CONF" -t -q || return 1
}

start_oqs_server() {   # background; quiet on stdout, stderr to OQS_SERVER_LOG
    [ "${HYP_OQS_PORT}" != 0 ] || return 0
    : >"$OQS_SERVER_LOG"
    OPENSSL_CONF="$STOCK_CNF" "$NGINX" -p "$NGINX_PREFIX" -c "$OQS_NGINX_CONF" \
        >/dev/null 2>>"$OQS_SERVER_LOG" &
}

# The hybrid provider logs, per operation, the provider that actually served
# each component (HYBRID_LOG=ops); connect.sh reads the server's lines from
# SERVER_LOG, a copy of nginx's stderr.
export HYBRID_LOG="${HYBRID_LOG:-ops}"

case "${1:-server}" in
server)
    prepare_server || exit 1
    prepare_oqs_server || exit 1
    start_oqs_server
    hr "serving on port ${HYP_PORT}"
    echo "    validate with:  docker exec <container> connect.sh [GROUP...]"
    [ "${HYP_OQS_PORT}" = 0 ] || \
    echo "    interop with oqsprovider (port ${HYP_OQS_PORT}):  docker exec <container> interop.sh [GROUP...]"
    echo "    per-handshake log (also below): ${KEM_LOG}"
    echo "    hybrid provider operations (HYBRID_LOG=${HYBRID_LOG}): ${SERVER_LOG}"
    : >"$SERVER_LOG"
    exec "$NGINX" -p "$NGINX_PREFIX" -c "$NGINX_CONF" 2> >(tee -a "$SERVER_LOG" >&2)
    ;;
selftest)
    prepare_server || exit 1
    "$NGINX" -p "$NGINX_PREFIX" -c "$NGINX_CONF" >/dev/null 2>"$SERVER_LOG" &
    NGINX_PID=$!
    hyp_wait_port 127.0.0.1 "$HYP_PORT" || { echo "FAIL: nginx did not come up" >&2; exit 1; }
    "$(dirname "$0")/connect.sh"
    RC=$?
    kill "$NGINX_PID" 2>/dev/null
    exit "$RC"
    ;;
interop)
    prepare_server || exit 1
    prepare_oqs_server || exit 1
    [ "${HYP_OQS_PORT}" != 0 ] || { echo "FAIL: interop needs the oqsprovider server (HYP_OQS_PORT)" >&2; exit 1; }
    : >"$SERVER_LOG"
    "$NGINX" -p "$NGINX_PREFIX" -c "$NGINX_CONF" >/dev/null 2>"$SERVER_LOG" &
    NGINX_PID=$!
    start_oqs_server
    OQS_PID=$!
    hyp_wait_port 127.0.0.1 "$HYP_PORT"     || { echo "FAIL: hybrid-provider nginx did not come up" >&2; exit 1; }
    hyp_wait_port 127.0.0.1 "$HYP_OQS_PORT" || { echo "FAIL: oqsprovider nginx did not come up" >&2; exit 1; }
    shift
    "$(dirname "$0")/interop.sh" "$@"
    RC=$?
    kill "$NGINX_PID" "$OQS_PID" 2>/dev/null
    exit "$RC"
    ;;
*)
    exec "$@"
    ;;
esac
