# shellcheck shell=bash
#
# Copyright 2026 hybrid-provider contributors
# SPDX-License-Identifier: Apache-2.0
#
# pqc_corpus_common.sh — shared by the IETF Hackathon pqc-certificates corpus
# scripts (test/pqc_*certificates_interop.sh) and scripts/check-pqc-certs-drift.sh.
# Sourced, not executed. Uses OPENSSL_BIN (default: openssl).

# The whole LAMPS composite OID arc (sigs .37..54, KEMs .55..66). The KEM scripts
# match all of it, not just the OIDs we serve today: only KEMs ship decaps vectors
# and KEMRI blobs, so the match stays KEM-only, and a NEW composite OID in the
# corpus is tried (and FAILs) instead of being silently ignored.
ARC='1\.3\.6\.1\.5\.5\.7\.6\.[0-9]+'

# The arc OIDs a DER file embeds, one per line, sorted and de-duplicated. A null
# cnf keeps the hybrid provider out of the picture. Plain libcrypto has no names
# for the arc, so asn1parse prints these OIDs numerically.
pqc_embedded_oids() {   # $1 = DER file
    OPENSSL_CONF=/dev/null "${OPENSSL_BIN:-openssl}" asn1parse -inform DER -in "$1" \
            2>/dev/null \
        | grep -oE "OBJECT +:$ARC\$" | grep -oE "$ARC" | sort -u
}

# Filename vs content: the corpus names each artifact after its OID, and the
# verify loops key every result on that name. This checks the file embeds exactly
# that one arc OID, i.e. the key's algorithm (and, for a self-signed trust anchor,
# its signature algorithm too). A mislabelled artifact would otherwise be counted
# under the wrong OID. Returns 0 if coherent; else 1, with the reason on stdout.
# Only for files that carry a single arc OID: PKCS#8 keys, self-signed _ta certs
# and KEMRI EnvelopedData. A KEM _ee cert does not qualify, since its CA may sign
# with a composite signature OID.
pqc_oid_check() {   # $1 = DER file, $2 = OID from its filename
    local emb
    emb="$(pqc_embedded_oids "$1" | tr '\n' ' ')"
    [ "$emb" = "$2 " ] && return 0
    if [ -z "$emb" ]; then
        echo "$(basename "$1"): no arc OID found inside (unparseable DER, or this" \
             "OpenSSL prints the arc OIDs by name), expected $2"
    else
        echo "$(basename "$1") embeds [${emb% }] instead of its filename OID $2"
    fi
    return 1
}

# Per-peer coverage: when PQC_OID_REPORT names a file, the verify loops append one
# "<family> <peer> <oid>" line per OID a peer ships, read from the artifact
# filename. Families are sig, kem (decaps vectors) and cms (KEMRI).
# scripts/check-pqc-certs-drift.sh diffs these against the OIDs we emit.
pqc_report_oid() {   # $1 = family, $2 = peer, $3 = OID
    [ -n "${PQC_OID_REPORT:-}" ] && echo "$1 $2 $3" >> "$PQC_OID_REPORT"
    return 0
}
