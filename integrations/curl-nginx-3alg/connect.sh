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
#   comps     which provider each component of the group was fetched from
#             (trace-enabled image only): the component fetches of the client's
#             key-share keygen, from OpenSSL QUERY trace lines in the hybrid
#             provider's private component context. A trace line records the
#             property query, not the resolution, so only a strict
#             "provider=<name>" pin proves the provider. A preference
#             ("?provider=") or no query is reported as unverified: a FAIL
#             under HYP_STEERING=strict, accepted (as OK*) under max.
#
# Env: HYP_HOST/HYP_PORT (default 127.0.0.1:4433), HYP_TRACE=0 to skip comps,
#      HYP_STEERING / HYP_MLKEM_PROVIDER as for the server (a client in another
#      container must use the same values to offer the same groups).
# Exit 0 == every group negotiated as offered on every available source.
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

# Component provenance needs libcrypto built with enable-trace.
TRACE=0
if [ "${HYP_TRACE:-1}" != 0 ]; then
    OPENSSL_TRACE=QUERY "$OPENSSL" list -providers >/dev/null 2>"$TMP/probe"
    grep -q "QUERY:" "$TMP/probe" && TRACE=1
fi
# A hybrid's components are key types: keep only trace entries naming a key
# manager of a component provider (drops the RNG/cipher/digest fetches those
# keygens also make). Derived from the providers, not a hardcoded list.
if [ "$TRACE" = 1 ]; then
    for p in $(sed -n 's/^component-providers *= *//p' "$ACTIVE_CNF" | tr ',' ' '); do
        OPENSSL_CONF=/dev/null "$OPENSSL" list -provider-path "$MODULES" -provider "$p"             -key-managers 2>/dev/null
    done | sed -nE 's/^ *IDs: *//p' | sed -E 's/@.*//; s/[{}]//g' | tr ',' '\n' \
        | sed -E 's/^ +//; s/ +$//' \
        | grep -v '^$' | sort -u >"$TMP/keytypes"
fi
STEERING=$(hyp_component_steering | tr '\n' ' ')

pass=0; fail=0; unverified=0
for g in $GROUPS_LIST; do
    id=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
    bad=0; unv=0

    "$CURL" -sv --curves "$g" "${CURL_ARGS[@]}" "${URL}/kem/${g}?id=${id}" \
        -o "$TMP/body" 2>"$TMP/curl.log"
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

    comps="n/a (image built without ENABLE_TRACE=1)"
    if [ "$TRACE" = 1 ]; then
        OPENSSL_TRACE=QUERY "$OPENSSL" genpkey -algorithm "$g" -out /dev/null \
            >/dev/null 2>"$TMP/trace" || true   # KEM keys have no encoder; keygen ran
        comps=$(grep -E "Non-default library context, Algorithm \(" "$TMP/trace" \
                | sed -E 's/.*Algorithm \(([^ ]+) [^)]*\), Properties \(([^)]*)\).*/\1 \2/' \
                | grep -v "^${g} " | sort -u \
                | while read -r name props; do
                      grep -qxF "$name" "$TMP/keytypes" && echo "$name $props"
                  done \
                | while read -r name props; do
                      case "$props" in
                          provider=*)  echo -n "${name}<-${props#provider=} " ;;
                          \?provider=*) echo -n "${name}<-unverified(prefers ${props#\?provider=}) " ;;
                          *)           echo -n "${name}<-unverified(any provider) " ;;
                      esac
                  done)
        [ -n "$comps" ] || comps="none traced (no private component context?)"
        case "$comps" in
            *unverified*) if [ "$STEERING_MODE" = strict ]; then bad=1; else unv=1; fi ;;
        esac
    fi

    if [ "$bad" != 0 ]; then verdict=FAIL; fail=$((fail + 1))
    elif [ "$unv" != 0 ]; then verdict="OK*"; pass=$((pass + 1)); unverified=$((unverified + 1))
    else verdict=OK; pass=$((pass + 1)); fi
    printf '[%-4s] %s\n' "$verdict" "$g"
    printf '         curl=%s  s_client=%s  server=%s  log=%s\n' \
        "${curl_g:-<none>}" "${sclient_g:-<none>}" "${server_g:-<none>}" "${log_g:-<none>}"
    printf '         comps: %s\n' "$comps"
done

echo
echo "steering: HYP_STEERING=${STEERING_MODE}; active cnf: ${STEERING:-<none>}"
[ "$unverified" = 0 ] || echo "OK* = negotiated as offered, but a component's provider is unverified (preference steering)"
echo "RESULT: ${pass} OK (${unverified} of them OK*), ${fail} FAIL of $((pass + fail)) groups at ${HYP_HOST}:${HYP_PORT}"
[ "$fail" = 0 ] && [ "$pass" -gt 0 ]
