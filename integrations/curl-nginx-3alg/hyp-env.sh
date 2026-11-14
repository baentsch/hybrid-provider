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

HYP_HOST=${HYP_HOST:-127.0.0.1}
HYP_PORT=${HYP_PORT:-4433}

# Build the active config once per container (idempotent), picking the ML-KEM
# source (HYP_MLKEM_PROVIDER, default wolfProvider). If the wolfProvider module
# is missing, fall back to the default provider, and drop wolfprov from
# component-providers too: a listed provider that cannot load keeps the hybrid
# provider from activating at all.
#
# HYP_STEERING picks how that pin is written. alg<N>-propquery is positional:
# alg2 pins the 2nd component of EVERY group, not just the ML-KEM ones.
#   strict (default)  alg2 = provider=<name>: only groups whose 2nd component
#                     that provider serves (with wolfprov: the ML-KEM ones);
#                     every component's provider is provable.
#   max               alg2 = ?provider=<name>: preferred, else any provider, so
#                     every group whose components exist is offered; which
#                     provider served a non-preferred component is not provable.
hyp_prepare_cnf() {
    local prov q
    [ -s "$ACTIVE_CNF" ] && return 0
    case "${HYP_STEERING:-strict}" in
        strict) q="provider=" ;;
        max)    q="?provider=" ;;
        *)      echo "FAIL: HYP_STEERING must be 'strict' or 'max' (got '${HYP_STEERING}')" >&2
                return 1 ;;
    esac
    mkdir -p "$HYP_STATE"
    cp "$HYBRID_CNF" "$ACTIVE_CNF.tmp"
    prov="${HYP_MLKEM_PROVIDER:-wolfprov}"
    if [ "$prov" = "wolfprov" ] && [ ! -e "${MODULES}/wolfprov.so" ]; then
        echo "NOTE: ${MODULES}/wolfprov.so absent -> sourcing ML-KEM from the default provider instead" >&2
        prov=default
        sed -i -E 's/^(component-providers *=.*)[[:space:]]wolfprov\b/\1/' "$ACTIVE_CNF.tmp"
    fi
    sed -i "s|^alg2-propquery = .*|alg2-propquery = ${q}${prov}|" "$ACTIVE_CNF.tmp"
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

hyp_wait_port() {   # hyp_wait_port <host> <port> [tries]: plain TCP probe
    local i
    for i in $(seq 1 "${3:-50}"); do
        (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}
