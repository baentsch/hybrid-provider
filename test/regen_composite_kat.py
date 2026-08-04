#!/usr/bin/env python3
"""Regenerate test/composite_kat.txt from the draft's own reference vectors.

The KAT file is vendored so the tests stay hermetic (no network at test time),
but it must not silently go stale: run this to refresh it from the pinned draft
revision, and bump TAG when moving to a newer draft.

    python3 test/regen_composite_kat.py > test/composite_kat.txt

Source of truth: lamps-wg/draft-composite-sigs src/testvectors.json (m/pk/s are
base64 there; we emit hex). `s` is the signature over m with an empty context.
"""
import base64
import json
import sys
import urllib.request

TAG = "draft-ietf-lamps-pq-composite-sigs-19"
URL = ("https://raw.githubusercontent.com/lamps-wg/draft-composite-sigs/"
       + TAG + "/src/testvectors.json")

# testvectors.json tcId -> the algorithm name this provider registers.
NAMES = {
    "id-MLDSA44-ECDSA-P256-SHA256": "mldsa44_ecdsa_p256",
    "id-MLDSA65-RSA3072-PSS-SHA512": "mldsa65_rsa3072_pss",
    "id-MLDSA65-Ed25519-SHA512": "mldsa65_ed25519",
    "id-MLDSA87-ECDSA-P384-SHA512": "mldsa87_ecdsa_p384",
    "id-MLDSA87-Ed448-SHAKE256": "mldsa87_ed448",
}


def hexof(b64):
    return base64.b64decode(b64).hex()


def main():
    with urllib.request.urlopen(URL) as f:      # nosec: pinned, read-only
        data = json.load(f)
    msg = hexof(data["m"])
    lines = [
        "# Composite ML-DSA KAT vectors from draft-ietf-lamps-pq-composite-sigs",
        "# source: lamps-wg/draft-composite-sigs %s src/testvectors.json" % TAG,
        "# regenerate: python3 test/regen_composite_kat.py > test/composite_kat.txt",
        "# format: <name> <msg_hex> <pubkey_hex> <sig_hex>"
        "  (signature over msg, empty context)",
    ]
    seen = set()
    for t in data["tests"]:
        name = NAMES.get(t["tcId"])
        if name is None:
            continue
        lines.append("%s %s %s %s" % (name, msg, hexof(t["pk"]), hexof(t["s"])))
        seen.add(t["tcId"])
    missing = set(NAMES) - seen
    if missing:
        sys.exit("missing tcIds in source: %s" % ", ".join(sorted(missing)))
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
