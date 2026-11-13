#!/bin/bash
# =============================================================================
# Opt-in crypto-provenance tracer for the 3-alg demo (add-on; not part of the
# oqs-demos baseline). It shows which provider actually serves each KEM
# component — X25519, ML-KEM-768 (fetched as MLKEM768) and HQC-192 (fetched as
# hqc3) — inside the hybrid provider's private component context.
#
# How: it first confirms a live TLS 1.3 handshake negotiates the group, then
# traces the client's KEY-SHARE GENERATION for that group. That key share is an
# ordinary EVP keygen of the hybrid key — the exact per-component fetch path the
# TLS client runs during the handshake — but, unlike a full s_client trace, it
# is not polluted by the capability/operability probe that libssl triggers for
# every *other* advertised group. The decisive trace events are OpenSSL QUERY
# lines of the form:
#   QUERY: Non-default library context, Algorithm (MLKEM768 : .), Properties (provider=wolfprov)
# i.e. the component fetch in the hybrid's OWN (non-default) libctx under the
# per-component property query. We extract the resolved provider from those and
# cross-check it against the alg{1,2,3}-propquery keys in the active openssl.cnf.
#
# Requires the image built with  --build-arg ENABLE_TRACE=1  (OPENSSL_TRACE is a
# no-op unless libcrypto was configured with `enable-trace`). Invoked by
# entrypoint.sh when run with  -e HP_TRACE=1 , or standalone:  tls-trace.sh <port>
# =============================================================================
set -u
PORT="${1:-4433}"
INSTALLDIR="${INSTALLDIR:-/opt/pq}"
OPENSSL="${INSTALLDIR}/bin/openssl"
CA="${INSTALLDIR}/demo/CA.crt"
CNF="${OPENSSL_CONF:-${INSTALLDIR}/ssl/openssl.cnf}"
GROUP=HQCKEM192MLKEM768X25519
TRACE_LOG=/tmp/openssl-trace.log

hr() { printf '\n========== %s ==========\n' "$1"; }

hr "crypto-provenance trace"

# (1) Tie the provenance to a real TLS session (untraced; just the verdict line).
NEG=$(echo Q | "$OPENSSL" s_client -connect "127.0.0.1:${PORT}" -groups "$GROUP" \
        -CAfile "$CA" -tls1_3 2>/dev/null | grep -iE "Negotiated .*group")
[ -n "$NEG" ] && echo "  handshake: $NEG"

# (2) Trace the client's key-share generation for this group (== the component
#     fetches performed during the handshake), steered by alg*-propquery and
#     resolved in the hybrid's private (non-default) component libctx.
OPENSSL_TRACE="QUERY" "$OPENSSL" genpkey -algorithm "$GROUP" -out /dev/null \
    2>"$TRACE_LOG" || true

if ! grep -q "QUERY:" "$TRACE_LOG"; then
    echo "  No trace output captured."
    echo "  OPENSSL_TRACE needs libcrypto built with 'enable-trace'."
    echo "  Rebuild with:  docker build --build-arg ENABLE_TRACE=1 -t hp-3alg-trace ..."
    echo "  then run:      docker run --rm -e HP_TRACE=1 hp-3alg-trace"
    exit 0
fi
echo "  captured $(wc -l <"$TRACE_LOG") trace lines -> $TRACE_LOG"

# --- raw evidence: the component fetches in the private (non-default) libctx ---
hr "trace evidence: component fetch -> provider (hybrid's private libctx)"
grep -E "Non-default library context, Algorithm \((X25519|MLKEM768|hqc3) :" "$TRACE_LOG" \
    | sed -E 's/.*Algorithm \(([^ ]+) [^)]*\), Properties \(([^)]*)\)/    \1  ->  \2/' \
    | sort -u

# --- verdict table: cnf intent vs what the key-share generation actually did ---
# component logical slot -> alg{N}-propquery key in the active cnf.
comps="X25519:alg1:X25519 MLKEM768:alg2:ML-KEM-768 hqc3:alg3:HQC-192"
hr "provenance summary (cnf steer vs handshake reality)"
printf '  %-10s %-12s %-12s %-12s %s\n' COMPONENT FETCH-NAME CNF-STEER RESOLVED MATCH
ok=1
for triple in $comps; do
    alg="${triple%%:*}"; rest="${triple#*:}"; key="${rest%%:*}"; human="${rest#*:}"
    actual=$(grep -E "Non-default library context, Algorithm \(${alg} :" "$TRACE_LOG" \
             | grep -oE "\??provider=[A-Za-z0-9_]+" | head -1 | cut -d= -f2)
    expected=$(grep -E "^[[:space:]]*${key}-propquery" "$CNF" 2>/dev/null \
             | grep -oE "provider=[A-Za-z0-9_]+" | head -1 | cut -d= -f2)
    [ -z "$actual" ]   && actual="<none>"
    [ -z "$expected" ] && expected="<unset>"
    if [ "$actual" = "$expected" ]; then m="OK"; else m="??"; ok=0; fi
    printf '  %-10s %-12s %-12s %-12s %s\n' "$human" "$alg" "$expected" "$actual" "$m"
done
echo
[ "$ok" = 1 ] \
  && echo "  => each component was served by the provider its alg*-propquery names" \
  || echo "  => mismatch above; inspect $TRACE_LOG"
