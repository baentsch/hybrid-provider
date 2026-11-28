#!/bin/bash
# =============================================================================
# Interop check: the hybrid provider vs. oqsprovider's OWN hybrids, over TLS.
#
#   interop.sh [-v|--verbose] [GROUP ...]   default: every group both stacks serve
#
#   -v  per pairing, both sides: stack and config, the group that side actually
#       negotiated, and which provider served it (for a hyb side: each
#       component's provider, from the hybrid provider's own log).
#       Also HYP_VERBOSE=1.
#
# Two stacks, chosen purely by openssl.cnf (same curl, same nginx binaries):
#   hyb  the hybrid cnf (default + hybrid provider; oqsprovider only as a
#        component source inside the hybrid provider)
#   oqs  the stock cnf (default + oqsprovider, which serves its own hybrids)
# Two servers (entrypoint.sh server): hyb on HYP_PORT (4433), oqs on
# HYP_OQS_PORT (4434). For each group, curl connects in all four pairings
# (client stack > server stack), offering ONLY that group, and checks:
#   negotiated  curl's own report and the server's $ssl_curve (response body)
#               both name the group
#   stacks      the hybrid provider ran on exactly the "hyb" sides: its
#               HYBRID_LOG=ops lines appear for a hyb client (keygen) and a hyb
#               server (encapsulate), and never for an oqs side
#   log         the serving nginx's access log has this exact request
#               (same container only)
# hyb>hyb and oqs>oqs are the baselines; hyb>oqs and oqs>hyb prove that the two
# implementations of the same name are interchangeable on the wire.
#
# Env: HYP_HOST, HYP_PORT, HYP_OQS_PORT; HYP_STEERING and HYP_MLKEM_PROVIDER as
#      for the server (a client in another container must use the same values).
# Exit 0 == every pairing of every group negotiated, on the intended stacks.
# =============================================================================
set -u
. "$(dirname "$0")/hyp-env.sh"

hyp_prepare_cnf || exit 1
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

VERBOSE=${HYP_VERBOSE:-0}
case "${1:-}" in -v|--verbose) VERBOSE=1; shift ;; esac

if [ $# -gt 0 ]; then
    GROUPS_LIST=$(printf '%s\n' "$@")
elif [ -s "$OQS_GROUPS_FILE" ]; then
    GROUPS_LIST=$(cat "$OQS_GROUPS_FILE")
else
    GROUPS_LIST=$(hyp_shared_groups)
fi
[ -n "$GROUPS_LIST" ] || { echo "FAIL: no group is served by both stacks" >&2; exit 1; }

for p in "$HYP_PORT" "$HYP_OQS_PORT"; do
    hyp_wait_port "$HYP_HOST" "$p" 25 || {
        echo "FAIL: no server at ${HYP_HOST}:${p}" >&2
        echo "      start both with:  docker run -d --name hyp -p 4433:4433 -p 4434:4434 hyp-3alg" >&2
        exit 1
    }
done

declare -A CNF=([hyb]="$ACTIVE_CNF" [oqs]="$STOCK_CNF")
declare -A PORT=([hyb]="$HYP_PORT" [oqs]="$HYP_OQS_PORT")
declare -A SLOG=([hyb]="$SERVER_LOG" [oqs]="$OQS_SERVER_LOG")
declare -A ALOG=([hyb]="$KEM_LOG" [oqs]="$OQS_KEM_LOG")
declare -A CNFNAME=([hyb]="openssl-active.cnf" [oqs]="openssl-stock.cnf")

# Who served a group on one side, for -v: the hybrid provider's own log line
# (components with their providers), or oqsprovider on the stock stack.
served_by() {   # served_by <stack> <hybrid log line, may be empty>
    if [ "$1" = oqs ]; then echo "oqsprovider (its own hybrid; no hybrid provider loaded)"
    elif [ -n "$2" ]; then echo "hybrid-provider: $2"
    else echo "hybrid-provider: <no log line>"; fi
}

# One side of a pairing, for -v: what it negotiated, or, after a failed
# handshake, what it offered (client key share) or that nothing was used.
side() {   # side <client|server> <stack> <negotiated group or ""> <hybrid log line>
    if [ -n "$3" ]; then
        echo "group=$3  via $(served_by "$2" "$4")"
    elif [ "$1" = client ]; then
        echo "group=<none: handshake failed>  key share offered via $(served_by "$2" "$4")"
    else
        echo "group=<none: handshake failed>"
    fi
}

# One handshake: pair <group> <client stack> <server stack>.
# Prints "OK" or "FAIL:<reason>".
pair() {
    local g=$1 c=$2 s=$3 id off cg sg why="" hl
    id=$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')
    off=-1; [ -r "${SLOG[$s]}" ] && off=$(stat -c %s "${SLOG[$s]}")
    rm -f "$TMP/body"     # curl keeps a stale body when the handshake fails

    OPENSSL_CONF="${CNF[$c]}" HYBRID_LOG=ops "$CURL" -sv --curves "$g" \
        --cacert "$CA" --resolve "localhost:${PORT[$s]}:${HYP_HOST}" \
        "https://localhost:${PORT[$s]}/kem/${g}?id=${id}" \
        -o "$TMP/body" 2>"$TMP/curl.log"
    cg=$(grep -oE 'SSL connection using TLSv1\.3 / [^/]+ / [^ ]+' "$TMP/curl.log" | awk '{print $NF}')
    sg=$(grep -oE 'negotiated=[^ ]+' "$TMP/body" 2>/dev/null | cut -d= -f2)

    if [ "$cg" != "$g" ] || [ "$sg" != "$g" ]; then
        why=$(grep -oE '(TLS alert|alert|error)[^"]*' "$TMP/curl.log" | head -1)
        why="not negotiated (curl=${cg:-none} server=${sg:-none}${why:+; $why})"
    fi

    # Which stack ran on the client side: hybrid provider lines or none.
    hl=$(grep -c "^hybrid: keygen $g:" "$TMP/curl.log")
    local ccomp scomp="" sgl
    ccomp=$(sed -n "s/^hybrid: keygen $g: //p" "$TMP/curl.log" | head -1)
    if [ -z "$why" ]; then
        if [ "$c" = hyb ] && [ "$hl" = 0 ]; then why="client: hybrid provider did not run"
        elif [ "$c" = oqs ] && [ "$hl" != 0 ]; then why="client: hybrid provider ran on the oqs stack"; fi
    fi

    # Which stack ran on the server side (same container only).
    if [ -z "$why" ] && [ "$off" -ge 0 ]; then
        local n=0 i
        for i in 1 2 3 4 5; do      # the copy of nginx's stderr may lag a moment
            tail -c +$((off + 1)) "${SLOG[$s]}" >"$TMP/srv.log"
            n=$(grep -c "^hybrid: encapsulate $g:" "$TMP/srv.log")
            scomp=$(sed -n "s/^hybrid: encapsulate $g: //p" "$TMP/srv.log" | head -1)
            [ "$s" = oqs ] || [ "$n" != 0 ] && break
            sleep 0.2
        done
        if [ "$s" = hyb ] && [ "$n" = 0 ]; then why="server: hybrid provider did not run"
        elif [ "$s" = oqs ] && [ "$n" != 0 ]; then why="server: hybrid provider ran on the oqs stack"; fi
        if [ -z "$why" ] && [ -r "${ALOG[$s]}" ] && ! grep -qF "id=${id} " "${ALOG[$s]}"; then
            why="server: request missing from its access log"
        fi
    fi

    # -v details: the group each side actually used, and who served it.
    if [ "$VERBOSE" = 1 ]; then
        sgl=$sg
        if [ -z "$sgl" ] && [ -r "${ALOG[$s]}" ]; then
            sgl=$(grep -F "id=${id} " "${ALOG[$s]}" | grep -oE 'curve=[^ ]+' | tail -1 | cut -d= -f2)
        fi
        [ "$off" -ge 0 ] || scomp="<server log not readable here>"
        {
            printf '           %s>%s client: %s stack (%s)  %s\n' "$c" "$s" "$c" \
                "${CNFNAME[$c]}" "$(side client "$c" "$cg" "$ccomp")"
            printf '                   server: %s stack (%s, port %s)  %s\n' "$s" \
                "${CNFNAME[$s]}" "${PORT[$s]}" "$(side server "$s" "$sgl" "$scomp")"
        } >"$TMP/v.$c.$s"
    fi

    [ -z "$why" ] && echo OK || echo "FAIL:$why"
}

UPSTREAM_FILE=${INSTALLDIR}/demo/upstream.txt   # written at image build time
if [ -r "$UPSTREAM_FILE" ]; then
    echo "built against: $(paste -sd' ' "$UPSTREAM_FILE" | sed 's/  */ /g')"
    echo
fi

# A cross pairing only means something if both stacks can negotiate the group
# on their own. If oqsprovider cannot (its oqs>oqs baseline fails, e.g. a group
# it lists but does not enable for TLS: `openssl list -tls-groups` shows
# implemented groups, not negotiable ones), its column is n/a, not a FAIL of
# the hybrid provider. A failing hyb>hyb baseline is always a FAIL.
PAIRS="hyb:hyb hyb:oqs oqs:hyb oqs:oqs"
ok=0; fail=0; xfail=0; na=0; failed_groups=""; na_groups=""
printf '%-24s %-9s %-9s %-9s %-9s\n' "group" "hyb>hyb" "hyb>oqs" "oqs>hyb" "oqs>oqs"
for g in $GROUPS_LIST; do
    declare -A R=()
    for pr in $PAIRS; do R[$pr]=$(pair "$g" "${pr%:*}" "${pr#*:}"); done
    oqs_ok=0; [ "${R[oqs:oqs]}" = OK ] && oqs_ok=1

    line=$(printf '%-24s' "$g"); reasons=""
    for pr in $PAIRS; do
        c=${pr%:*}; s=${pr#*:}; r=${R[$pr]}
        if [ "$r" = OK ]; then
            v=OK; ok=$((ok + 1))
        elif [ "$oqs_ok" = 0 ] && [ "$pr" != hyb:hyb ]; then
            v=n/a; na=$((na + 1))
        else
            v=FAIL; fail=$((fail + 1))
            [ "$c" = "$s" ] || xfail=$((xfail + 1))
            reasons="${reasons}         ${c}>${s}: ${r#FAIL:}\n"
        fi
        line="$line $(printf '%-9s' "$v")"
    done
    echo "$line"
    if [ "$VERBOSE" = 1 ]; then
        for pr in $PAIRS; do cat "$TMP/v.${pr%:*}.${pr#*:}" 2>/dev/null; done
    fi
    if [ "$oqs_ok" = 0 ]; then
        echo "         n/a: oqsprovider cannot negotiate this group itself (oqs>oqs: ${R[oqs:oqs]#FAIL:})"
        na_groups="$na_groups $g"
    fi
    [ -z "$reasons" ] || { printf "%b" "$reasons"; failed_groups="$failed_groups $g"; }
    unset R
done

echo
echo "hyb = hybrid cnf (hybrid provider serves the group); oqs = stock cnf (oqsprovider serves it)"
echo "client>server; hyb>hyb and oqs>oqs are baselines, the other two are cross-implementation"
echo "RESULT: ${ok} OK, ${fail} FAIL (${xfail} of them cross-implementation), ${na} n/a of $((ok + fail + na)) handshakes"
[ -z "$na_groups" ] || echo "not negotiable by oqsprovider here (n/a):${na_groups}"
[ -z "$failed_groups" ] || echo "failing groups:${failed_groups}"
[ "$fail" = 0 ]
