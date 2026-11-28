# =============================================================================
# Shared environment for entrypoint.sh (server) and connect.sh (client).
# Sourced, not executed: one place for paths, the active openssl.cnf and the
# list of hybrid groups, so server and client always agree.
# =============================================================================

INSTALLDIR=${INSTALLDIR:-/opt/pq}
NGINX_PREFIX=${NGINX_PREFIX:-/opt/nginx}
OPENSSL=${INSTALLDIR}/bin/openssl
CURL=${INSTALLDIR}/bin/curl
NGINX=${NGINX_PREFIX}/sbin/nginx
MODULES=${INSTALLDIR}/lib64/ossl-modules
HYBRID_CNF=${INSTALLDIR}/ssl/openssl.cnf          # as shipped
STOCK_CNF=${INSTALLDIR}/ssl/openssl-stock.cnf     # baseline without the plugin
CA=${INSTALLDIR}/demo/CA.crt
NGINX_TEMPLATE=${NGINX_PREFIX}/conf/nginx-demo.conf
KEM_LOG=${NGINX_PREFIX}/logs/kem-access.log       # written by nginx.conf's access_log

HYP_STATE=${HYP_STATE:-/tmp/hyp}                     # per-container runtime state
ACTIVE_CNF=${HYP_STATE}/openssl-active.cnf
GROUPS_FILE=${HYP_STATE}/server-groups
NGINX_CONF=${HYP_STATE}/nginx.conf
SERVER_LOG=${HYP_STATE}/server.log                # nginx stderr: HYBRID_LOG lines

HYP_HOST=${HYP_HOST:-127.0.0.1}
HYP_PORT=${HYP_PORT:-4433}

# Second server for the interop check (interop.sh): nginx under the STOCK cnf,
# so oqsprovider serves its OWN hybrids there, not the hybrid provider.
# HYP_OQS_PORT=0 disables it.
HYP_OQS_PORT=${HYP_OQS_PORT:-4434}
OQS_GROUPS_FILE=${HYP_STATE}/oqs-server-groups
OQS_NGINX_CONF=${HYP_STATE}/nginx-oqs.conf
OQS_SERVER_LOG=${HYP_STATE}/server-oqs.log
OQS_KEM_LOG=${NGINX_PREFIX}/logs/kem-access-oqs.log

# Build the active config once per container (idempotent). HYP_STEERING:
#   max (default)  an exact copy of the shipped openssl.cnf: the pure drop-in
#                  for oqsprovider's hybrids. No component pins, so every group
#                  whose components exist is offered (incl. the Frodo/BIKE/HQC
#                  hybrids), each component from whichever component provider
#                  has it; connect.sh reports which one did.
#   strict         the three-provider proof (THREE-PROVIDERS.md; default for
#                  `entrypoint.sh selftest`): adds the ML-KEM provider
#                  (HYP_MLKEM_PROVIDER, default wolfProvider) to
#                  component-providers and pins every component slot to one
#                  provider. alg<N>-propquery is positional (alg2 = the 2nd
#                  component of EVERY group), so only groups whose components
#                  the pinned providers serve are offered (with wolfprov: the
#                  ML-KEM ones), and every component's provider is provable.
#                  If the wolfProvider module is missing, ML-KEM comes from the
#                  default provider instead (a listed provider that cannot load
#                  keeps the hybrid provider from activating at all).
export HYP_STEERING="${HYP_STEERING:-max}"

hyp_prepare_cnf() {
    local prov
    [ -s "$ACTIVE_CNF" ] && return 0
    mkdir -p "$HYP_STATE"
    cp "$HYBRID_CNF" "$ACTIVE_CNF.tmp"
    case "${HYP_STEERING}" in
    max) ;;
    strict)
        prov="${HYP_MLKEM_PROVIDER:-wolfprov}"
        if [ "$prov" = "wolfprov" ] && [ ! -e "${MODULES}/wolfprov.so" ]; then
            echo "NOTE: ${MODULES}/wolfprov.so absent -> sourcing ML-KEM from the default provider instead" >&2
            prov=default
        fi
        grep -qE "^component-providers *=.*[[:space:]]${prov}([[:space:]]|\$)" "$ACTIVE_CNF.tmp" \
            || sed -i -E "s/^(component-providers *=.*)\$/\1 ${prov}/" "$ACTIVE_CNF.tmp"
        # [pq_sect] is the last section, so appended lines belong to it.
        cat >>"$ACTIVE_CNF.tmp" <<EOF
# --- added for HYP_STEERING=strict (three-provider proof, THREE-PROVIDERS.md):
# one provider per component slot; for HQCKEM192MLKEM768X25519 these are
# alg1 = X25519, alg2 = ML-KEM-768, alg3 = HQC-192.
alg1-propquery = provider=default
alg2-propquery = provider=${prov}
alg3-propquery = provider=oqsprovider
EOF
        ;;
    *)  echo "FAIL: HYP_STEERING must be 'max' or 'strict' (got '${HYP_STEERING}')" >&2
        rm -f "$ACTIVE_CNF.tmp"
        return 1 ;;
    esac
    mv "$ACTIVE_CNF.tmp" "$ACTIVE_CNF"
}

# The provider each alg<N>-propquery pins in the active cnf, e.g. "alg2 wolfprov".
hyp_component_steering() {
    grep -E '^alg[0-9]+-propquery' "$ACTIVE_CNF" \
        | sed -E 's/^(alg[0-9]+)-propquery *= *(\??)provider=([A-Za-z0-9_]+).*/\1 \2\3/'
}

# Groups served by the hybrid provider: those offered under the active cnf
# minus those OpenSSL offers without any cnf. Derived, never hardcoded.
hyp_hybrid_groups() {
    comm -23 \
        <(OPENSSL_CONF="$ACTIVE_CNF" "$OPENSSL" list -tls-groups 2>/dev/null | tr ':' '\n' | sort -u) \
        <(OPENSSL_CONF=/dev/null "$OPENSSL" list -tls-groups 2>/dev/null | tr ':' '\n' | sort -u) \
        | grep -v '^$'
}

# Groups for the interop check: hybrid groups the hybrid provider serves
# under the active cnf AND oqsprovider serves under the stock cnf, i.e. the
# same group name implemented twice, independently. Derived, never hardcoded.
hyp_shared_groups() {
    comm -12 \
        <(hyp_hybrid_groups | sort -u) \
        <(OPENSSL_CONF="$STOCK_CNF" "$OPENSSL" list -tls-groups 2>/dev/null | tr ':' '\n' | sort -u) \
        | grep -v '^$'
}

hyp_wait_port() {   # hyp_wait_port <host> <port> [tries]: plain TCP probe
    local i
    for i in $(seq 1 "${3:-50}"); do
        (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}
