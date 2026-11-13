#!/bin/bash
# =============================================================================
# What happens WITHOUT the bespoke openssl.cnf?  Can hybrid-provider still be
# activated from the command line alone?
#
# Removes the config from OPENSSLDIR, unsets OPENSSL_CONF, and asserts, per
# tool, the observed outcome (an "expected failure" passes when it fails the
# way documented):
#
#   openssl  -provider flags     -> YES, full 3-alg group (all providers in the
#                                   app context; no per-component steering)
#   curl     --engine hybrid     -> PARTIAL: curl loads ONE named provider (+
#                                   default) into its own libctx, so hybrids
#                                   built from default components work, the
#                                   HQC group does not (no oqsprovider there)
#   nginx                        -> NO: no provider directive; refuses to start
#
# Exit code 0 == every row behaved as documented.
# =============================================================================
set -u

GROUP=HQCKEM192MLKEM768X25519
INSTALLDIR=${INSTALLDIR:-/opt/pq}
NGINX_PREFIX=${NGINX_PREFIX:-/opt/nginx}
OPENSSL=${INSTALLDIR}/bin/openssl
CURL=${INSTALLDIR}/bin/curl
NGINX=${NGINX_PREFIX}/sbin/nginx
MODULES=${INSTALLDIR}/lib64/ossl-modules
DEMO=${INSTALLDIR}/demo
CA=${DEMO}/CA.crt
NGINX_PORT=4433          # fixed by nginx.conf
SSERVER_PORT=4444

# Everything the hybrid group needs, loaded purely by CLI flags.
ALL_PROVS="-provider-path ${MODULES} -provider default -provider oqsprovider -provider wolfprov -provider hybrid"
[ -e "${MODULES}/wolfprov.so" ] || ALL_PROVS=${ALL_PROVS/ -provider wolfprov/}

hr() { printf '\n========== %s ==========\n' "$1"; }
FAILS=0
check() {   # check <description> <0 if outcome is as documented>
    if [ "$2" = "0" ]; then echo "  OK   $1"; else echo "  FAIL $1"; FAILS=$((FAILS + 1)); fi
}
wait_port() {   # plain TCP probe: a cnf-less TLS probe could not handshake
    for _ in $(seq 1 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}
negotiated() {  # negotiated <port> <extra s_client args...>
    local port=$1; shift
    echo Q | "$OPENSSL" s_client -connect "127.0.0.1:${port}" -CAfile "$CA" -tls1_3 "$@" 2>/dev/null \
        | grep -iE "Negotiated .*group"
}

# ---------------------------------------------------------------------------
hr "removing the bespoke config"
# Keep a private copy ONLY to bring up a known-good nginx peer for the client
# rows; nothing else gets to see it.
PEER_CNF=/tmp/peer-openssl.cnf
mv "${INSTALLDIR}/ssl/openssl.cnf" "$PEER_CNF"
unset OPENSSL_CONF
echo "  OPENSSLDIR: $("$OPENSSL" version -d | cut -d'"' -f2)  (openssl.cnf removed, OPENSSL_CONF unset)"

# ---------------------------------------------------------------------------
hr "1. openssl, no flags: provider and group absent"
"$OPENSSL" list -providers 2>/dev/null | grep -q hybrid; check "hybrid provider not loaded" "$((! $?))"
"$OPENSSL" list -tls-groups 2>/dev/null | grep -qi "$GROUP"; check "$GROUP not offered" "$((! $?))"

# ---------------------------------------------------------------------------
hr "2. nginx, no cnf: refuses to start"
# nginx has no provider-loading directive (ssl_engine is ENGINE-only), and
# libcrypto reads its config before nginx parses nginx.conf, so `env` cannot help.
timeout 5 "$NGINX" -p "$NGINX_PREFIX" -c conf/nginx-demo.conf >/tmp/nginx-noconf.log 2>&1
NGX_RC=$?
grep -E "emerg" /tmp/nginx-noconf.log | sed 's/^/    /'
[ "$NGX_RC" != 0 ] && [ "$NGX_RC" != 124 ] && grep -q "$GROUP" /tmp/nginx-noconf.log
check "nginx exits with [emerg] on ssl_ecdh_curve $GROUP" $?

# Known-good nginx peer for the client rows (uses the private copy).
rm -f "${NGINX_PREFIX}/logs/nginx.pid"
OPENSSL_CONF="$PEER_CNF" "$NGINX" -p "$NGINX_PREFIX" -c conf/nginx-demo.conf 2>/tmp/nginx.log &
NGINX_PID=$!
wait_port "$NGINX_PORT" || { echo "FAIL: nginx peer did not come up" >&2; exit 1; }

# ---------------------------------------------------------------------------
hr "3. curl, no cnf: cannot negotiate $GROUP"
"$CURL" -s --curves "$GROUP" --cacert "$CA" "https://127.0.0.1:${NGINX_PORT}/" -o /dev/null 2>/dev/null
CURL_RC=$?
[ "$CURL_RC" != 0 ]; check "curl fails (rc=$CURL_RC)" $?

# ---------------------------------------------------------------------------
hr "4. openssl s_client -provider ...: full 3-alg handshake with nginx"
echo "    flags: $ALL_PROVS"
NEG=$(negotiated "$NGINX_PORT" $ALL_PROVS -groups "$GROUP")
echo "    $NEG"
echo "$NEG" | grep -qi "$GROUP"; check "s_client negotiated $GROUP" $?

# ---------------------------------------------------------------------------
hr "5. no cnf on EITHER side: s_server -provider ... <-> s_client -provider ..."
"$OPENSSL" s_server $ALL_PROVS -accept "$SSERVER_PORT" -cert "$DEMO/server.crt" \
    -key "$DEMO/server.key" -groups "$GROUP" -tls1_3 -www >/tmp/s_server.log 2>&1 &
SSERVER_PID=$!
wait_port "$SSERVER_PORT"
NEG=$(negotiated "$SSERVER_PORT" $ALL_PROVS -groups "$GROUP")
echo "    $NEG"
echo "$NEG" | grep -qi "$GROUP"; check "cnf-less s_server/s_client negotiated $GROUP" $?
kill "$SSERVER_PID" 2>/dev/null; wait "$SSERVER_PID" 2>/dev/null

# ---------------------------------------------------------------------------
hr "6. curl --engine hybrid (curl's provider hook: ONE provider + default)"
"$CURL" -sv --engine hybrid --curves "$GROUP" --cacert "$CA" \
    "https://127.0.0.1:${NGINX_PORT}/" -o /dev/null >/tmp/curl-engine.log 2>&1
grep -E "curves|SSL connection" /tmp/curl-engine.log | sed 's/^/    /'
grep -q "failed setting curves list" /tmp/curl-engine.log
check "$GROUP rejected: HQC component has no provider in curl's libctx" $?

# A hybrid group composed purely from default components IS reachable.
# Derived, not hardcoded: first group (default+hybrid) offers that default alone doesn't.
"$OPENSSL" list -tls-groups 2>/dev/null | tr ':' '\n' >/tmp/g-default
DEF_GROUP=$("$OPENSSL" list -provider-path "$MODULES" -provider default -provider hybrid \
              -tls-groups 2>/dev/null | tr ':' '\n' | grep -vxFf /tmp/g-default | head -1)
echo "    default-backed hybrid group: ${DEF_GROUP:-<none>}"
"$OPENSSL" s_server -provider-path "$MODULES" -provider default -provider hybrid \
    -accept "$SSERVER_PORT" -cert "$DEMO/server.crt" -key "$DEMO/server.key" \
    -groups "$DEF_GROUP" -tls1_3 -www >/tmp/s_server2.log 2>&1 &
SSERVER_PID=$!
wait_port "$SSERVER_PORT"
"$CURL" -sv --engine hybrid --curves "$DEF_GROUP" --cacert "$CA" \
    "https://127.0.0.1:${SSERVER_PORT}/" -o /dev/null >/tmp/curl-engine2.log 2>&1
grep -E "SSL connection" /tmp/curl-engine2.log | sed 's/^/    /'
[ -n "$DEF_GROUP" ] && grep -qE "SSL connection using TLSv1.3 .*/ ${DEF_GROUP} /" /tmp/curl-engine2.log
check "curl --engine hybrid negotiated ${DEF_GROUP:-<none>}" $?
kill "$SSERVER_PID" 2>/dev/null; wait "$SSERVER_PID" 2>/dev/null

kill "$NGINX_PID" 2>/dev/null
mv "$PEER_CNF" "${INSTALLDIR}/ssl/openssl.cnf"

# ---------------------------------------------------------------------------
hr "RESULT"
cat <<EOF
  without openssl.cnf:
    openssl CLI  YES      -provider flags load everything; full $GROUP
                          (components resolve in the app context: no per-component
                           provider steering, that needs alg<N>-propquery in a cnf)
    curl         PARTIAL  --engine <provider> loads one provider + default;
                          default-backed hybrids only, not $GROUP
    nginx        NO       needs a cnf (OPENSSL_CONF may point anywhere)
EOF
if [ "$FAILS" = 0 ]; then
    echo "  PASS: all rows behaved as documented"; exit 0
else
    echo "  FAIL: $FAILS row(s) deviated" >&2; exit 1
fi
