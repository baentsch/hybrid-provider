#!/bin/bash
# =============================================================================
# Client-side validation against the running demo server (entrypoint.sh server).
#
#   connect.sh [GROUP ...]     default: every group the server offers
#
# For each group it connects with curl and with openssl s_client, offering ONLY
# that group, and checks which KEM group was actually negotiated, from
# independent sources:
#   curl      curl's own report ("SSL connection using TLSv1.3 / ... / <group>")
#   s_client  "Negotiated TLS1.3 group: <group>"
#   server    nginx's $ssl_curve, echoed in the response body
#   log       nginx's access log line for this exact request (same container only)
# and which provider served each component, from the hybrid provider's own
# HYBRID_LOG=ops lines, which name the provider that ACTUALLY ran each component:
#   client    curl's key-share keygen and decapsulate lines
#   server    nginx's encapsulate line for this handshake (same container only)
# A missing line means the hybrid provider did not run that side, so the lines
# also prove the hybrid provider served the group itself. Under
# HYP_STEERING=strict every component must come from the provider its
# alg<N>-propquery pins; under max, a preference that was not honoured is noted.
#
# Env: HYP_HOST/HYP_PORT (default 127.0.0.1:4433); HYP_STEERING and
#      HYP_MLKEM_PROVIDER as for the server (a client in another container must
#      use the same values to offer the same groups).
# Exit 0 == every group negotiated as offered, served by the hybrid provider,
# with every pinned component from its pinned provider.
# =============================================================================
set -u
. "$(dirname "$0")/hyp-env.sh"

hyp_prepare_cnf || exit 1
export OPENSSL_CONF="$ACTIVE_CNF"
STEERING_MODE=${HYP_STEERING:-strict}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

if [ $# -gt 0 ]; then
    GROUPS_LIST=$(printf '%s\n' "$@")
elif [ -s "$GROUPS_FILE" ]; then
    GROUPS_LIST=$(cat "$GROUPS_FILE")
else
    GROUPS_LIST=$(hyp_hybrid_groups)
fi

hyp_wait_port "$HYP_HOST" "$HYP_PORT" 25 || {
    echo "FAIL: no server at ${HYP_HOST}:${HYP_PORT}" >&2
    echo "      start one with:  docker run -d --name hyp -p 4433:4433 hyp-3alg" >&2
    exit 1
}

# The server cert is for "localhost": connect to HYP_HOST but verify as localhost.
URL="https://localhost:${HYP_PORT}"
CURL_ARGS=(--cacert "$CA" --resolve "localhost:${HYP_PORT}:${HYP_HOST}")
SCLIENT_ARGS=(-connect "${HYP_HOST}:${HYP_PORT}" -servername localhost
              -verify_hostname localhost -verify_return_error -CAfile "$CA" -tls1_3)

# Slot pins from the active cnf: PIN[N] = provider for alg<N>, "?name" when it
# is only a preference. Log lines list components in slot order (alg1 first).
STEERING=$(hyp_component_steering | tr '\n' ' ')
declare -A PIN
while read -r slot prov; do
    PIN[${slot#alg}]=$prov
done < <(hyp_component_steering)

# Components of the first "hybrid: <op> <group>: ..." line in a file, or "".
op_line() { sed -n "s/^hybrid: $1 $2: //p" "$3" | head -1; }

# Compare "<comp>@<provider> ..." with the slot pins; prints what differs.
slot_mismatches() {
    local n=0 c p want
    for c in $1; do
        n=$((n + 1)); p=${c##*@}; want=${PIN[$n]:-}
        case "$want" in
            "") ;;
            \?*) [ "$p" = "${want#\?}" ] || echo -n "alg${n} preferred ${want#\?}, served by ${p}; " ;;
            *)   [ "$p" = "$want" ]      || echo -n "alg${n} pinned ${want}, served by ${p}; " ;;
        esac
    done
}

pass=0; fail=0; noted=0
for g in $GROUPS_LIST; do
    id=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
    bad=0; note=""

    srv_off=-1
    [ -r "$SERVER_LOG" ] && srv_off=$(stat -c %s "$SERVER_LOG")

    HYBRID_LOG=ops "$CURL" -sv --curves "$g" "${CURL_ARGS[@]}" \
        "${URL}/kem/${g}?id=${id}" -o "$TMP/body" 2>"$TMP/curl.log"
    curl_g=$(grep -oE 'SSL connection using TLSv1\.3 / [^/]+ / [^ ]+' "$TMP/curl.log" \
             | awk '{print $NF}')
    server_g=$(grep -oE 'negotiated=[^ ]+' "$TMP/body" 2>/dev/null | cut -d= -f2)

    sclient_g=$(echo Q | "$OPENSSL" s_client "${SCLIENT_ARGS[@]}" -groups "$g" 2>/dev/null \
                | sed -n 's/^Negotiated TLS1.3 group: //p')

    if [ -r "$KEM_LOG" ]; then
        log_g=$(grep -F "id=${id} " "$KEM_LOG" | grep -oE 'curve=[^ ]+' | tail -1 | cut -d= -f2)
    else
        log_g="n/a"   # client runs outside the server's container
    fi

    for v in "$curl_g" "$sclient_g" "$server_g"; do [ "$v" = "$g" ] || bad=1; done
    [ "$log_g" = "n/a" ] || [ "$log_g" = "$g" ] || bad=1

    # Provenance from the hybrid provider's own log lines.
    cli_kg=$(op_line keygen "$g" "$TMP/curl.log")
    cli_dc=$(op_line decapsulate "$g" "$TMP/curl.log")
    [ -n "$cli_kg" ] && [ -n "$cli_dc" ] || bad=1
    srv="n/a"
    if [ "$srv_off" -ge 0 ]; then
        srv=""
        for _ in 1 2 3 4 5; do        # the copy of nginx's stderr may lag a moment
            tail -c +$((srv_off + 1)) "$SERVER_LOG" >"$TMP/srv.log"
            srv=$(op_line encapsulate "$g" "$TMP/srv.log")
            [ -n "$srv" ] && break
            sleep 0.2
        done
        [ -n "$srv" ] || { srv="<none>"; bad=1; }
    fi
    for line in "$cli_kg" "$cli_dc" "$srv"; do
        case "$line" in ""|n/a|"<none>") continue ;; esac
        m=$(slot_mismatches "$line")
        case "$m" in
            "") ;;
            *pinned*) bad=1; note="$m" ;;
            *)        note="$m" ;;
        esac
    done

    comps=${cli_kg:-<none: the hybrid provider did not run the client side>}
    [ "$cli_dc" = "$cli_kg" ] || comps="$comps | decaps: ${cli_dc:-<none>}"
    [ "$srv" = "$cli_kg" ] && srv="same"

    if [ "$bad" != 0 ]; then verdict=FAIL; fail=$((fail + 1))
    elif [ -n "$note" ]; then verdict="OK*"; pass=$((pass + 1)); noted=$((noted + 1))
    else verdict=OK; pass=$((pass + 1)); fi
    printf '[%-4s] %s\n' "$verdict" "$g"
    printf '         curl=%s  s_client=%s  server=%s  log=%s\n' \
        "${curl_g:-<none>}" "${sclient_g:-<none>}" "${server_g:-<none>}" "${log_g:-<none>}"
    printf '         comps: %s   (client keygen+decaps; server encaps: %s)\n' "$comps" "$srv"
    [ -z "$note" ] || printf '         note:  %s\n' "$note"
done

echo
echo "steering: HYP_STEERING=${STEERING_MODE}; active cnf: ${STEERING:-<none>}"
[ "$noted" = 0 ] || echo "OK* = served as negotiated, but a preferred provider was not the one used (HYP_STEERING=max)"
echo "RESULT: ${pass} OK (${noted} of them OK*), ${fail} FAIL of $((pass + fail)) groups at ${HYP_HOST}:${HYP_PORT}"
[ "$fail" = 0 ] && [ "$pass" -gt 0 ]
