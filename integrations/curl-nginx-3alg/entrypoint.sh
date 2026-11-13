#!/bin/bash
# =============================================================================
# Proof driver for the hybrid-provider 3-alg downstream demo.
#   1. shows the group is absent with the stock config and present with the
#      hybrid config (the delta is config-only);
#   2. starts nginx offering ONLY HQCKEM192MLKEM768X25519;
#   3. connects with curl and with `openssl s_client`, both verbose;
#   4. asserts the negotiated group is the 3-alg hybrid group.
# Exit code 0 == the preussmattsson 3-alg handshake succeeded.
# =============================================================================
set -u

GROUP=HQCKEM192MLKEM768X25519
INSTALLDIR=${INSTALLDIR:-/opt/pq}
NGINX_PREFIX=${NGINX_PREFIX:-/opt/nginx}
OPENSSL=${INSTALLDIR}/bin/openssl
CURL=${INSTALLDIR}/bin/curl
NGINX=${NGINX_PREFIX}/sbin/nginx
MODULES=${INSTALLDIR}/lib64/ossl-modules
HYBRID_CNF=${INSTALLDIR}/ssl/openssl.cnf
STOCK_CNF=${INSTALLDIR}/ssl/openssl-stock.cnf
CA=${INSTALLDIR}/demo/CA.crt

hr() { printf '\n========== %s ==========\n' "$1"; }

# ---------------------------------------------------------------------------
# Build the active config, picking the ML-KEM source (default: wolfProvider).
# Auto-fall back to the default provider if the wolfProvider module is not
# present, so the proof still runs (3 algs, but from 2 providers). The strict
# propquery makes an HP_MLKEM_PROVIDER that cannot serve ML-KEM-768 fail
# visibly below instead of silently resolving to another provider.
# ---------------------------------------------------------------------------
ACTIVE_CNF=/tmp/openssl-active.cnf
cp "$HYBRID_CNF" "$ACTIVE_CNF"
MLKEM_PROV="${HP_MLKEM_PROVIDER:-wolfprov}"
if [ "$MLKEM_PROV" = "wolfprov" ] && [ ! -e "${MODULES}/wolfprov.so" ]; then
    echo "NOTE: ${MODULES}/wolfprov.so absent -> sourcing ML-KEM-768 from the default provider instead"
    MLKEM_PROV=default
    # Also drop it from the private component context: a listed provider that
    # cannot load keeps the hybrid provider from activating at all.
    sed -i -E 's/^(component-providers *=.*)[[:space:]]wolfprov\b/\1/' "$ACTIVE_CNF"
fi
sed -i "s|^alg2-propquery = .*|alg2-propquery = provider=${MLKEM_PROV}|" "$ACTIVE_CNF"

hr "component -> provider map (from openssl.cnf)"
echo "  X25519      (alg1) <- default"
echo "  ML-KEM-768  (alg2) <- ${MLKEM_PROV}"
echo "  HQC-192     (alg3) <- oqsprovider"
grep -E '^(component-providers|alg[0-9]-propquery)' "$ACTIVE_CNF" | sed 's/^/    /'

hr "config-only proof: diff stock vs hybrid openssl.cnf"
diff -u "$STOCK_CNF" "$HYBRID_CNF" | sed 's/^/    /' || true

hr "group availability WITHOUT the hybrid plugin (stock cnf)"
OPENSSL_CONF="$STOCK_CNF" "$OPENSSL" list -tls-groups 2>/dev/null | grep -i "$GROUP" \
    && echo "  unexpected: present without hybrid" \
    || echo "  $GROUP: NOT available (as expected) "

hr "group availability WITH the hybrid plugin (hybrid cnf)"
export OPENSSL_CONF="$ACTIVE_CNF"
"$OPENSSL" list -providers 2>/dev/null | sed 's/^/    /'
if "$OPENSSL" list -tls-groups 2>/dev/null | grep -i "$GROUP"; then
    echo "  $GROUP: AVAILABLE via hybrid-provider"
else
    echo "FAIL: $GROUP not advertised even with the hybrid plugin" >&2
    echo "      (each alg<N>-propquery provider must serve that component;" >&2
    echo "       ML-KEM-768 here: provider=${MLKEM_PROV})" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
hr "starting nginx (offers only $GROUP)"
rm -f "${NGINX_PREFIX}/logs/nginx.pid"
OPENSSL_CONF="$ACTIVE_CNF" "$NGINX" -p "${NGINX_PREFIX}" -c conf/nginx-demo.conf 2>/tmp/nginx.log &
NGINX_PID=$!
for i in $(seq 1 50); do
    "$OPENSSL" s_client -connect localhost:4433 </dev/null >/dev/null 2>&1 && break
    sleep 0.2
done

# ---------------------------------------------------------------------------
hr "curl -v  (client)"
"$CURL" -sv --curves "$GROUP" --cacert "$CA" https://127.0.0.1:4433/ >/tmp/curl.body 2>/tmp/curl.log
CURL_RC=$?
sed 's/^/    /' /tmp/curl.log
CURL_GROUP=$(grep -oiE "TLSv1\.3[^\"]*/ ?${GROUP}" /tmp/curl.log | head -1)
echo "    --- response body ---"; sed 's/^/    /' /tmp/curl.body

# ---------------------------------------------------------------------------
hr "openssl s_client  (independent cross-check of the negotiated group)"
NEG=$(echo Q | "$OPENSSL" s_client -connect 127.0.0.1:4433 \
        -groups "$GROUP" -CAfile "$CA" -tls1_3 2>/dev/null \
        | grep -iE "Negotiated .*group")
echo "    $NEG"

# ---------------------------------------------------------------------------
hr "server-side evidence (nginx debug log)"
grep -iE "SSL_do_handshake|SSL server|cipher:" /tmp/nginx.log | tail -3 | sed 's/^/    /' || true

# ---------------------------------------------------------------------------
### +++ ADDED (opt-in): crypto-provenance trace -- which provider served each
### component. Needs the image built with --build-arg ENABLE_TRACE=1 and run
### with -e HP_TRACE=1. Separate script so the add-on is self-contained. +++
if [ "${HP_TRACE:-0}" = "1" ]; then
    "${INSTALLDIR}/bin/tls-trace.sh" 4433 || true
fi

kill "$NGINX_PID" 2>/dev/null

# ---------------------------------------------------------------------------
hr "RESULT"
if [ "$CURL_RC" = "0" ] && echo "$NEG" | grep -qi "$GROUP"; then
    echo "  PASS: curl <-> nginx completed a TLS 1.3 handshake over $GROUP"
    echo "        (X25519 + ML-KEM-768[$MLKEM_PROV] + HQC-192, composed by hybrid-provider)"
    [ -n "$CURL_GROUP" ] && echo "  curl confirmed: $CURL_GROUP"
    exit 0
else
    echo "  FAIL: curl rc=$CURL_RC, negotiated='$NEG' (expected $GROUP)" >&2
    exit 1
fi
