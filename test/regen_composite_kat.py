#!/usr/bin/env python3
"""Regenerate test/composite_kat.txt from the draft's own reference vectors.

The KAT file is vendored so the tests stay hermetic (no network at test time),
but it must not silently go stale: run this to refresh it from the pinned draft
revision, and bump TAG when moving to a newer draft.

    python3 test/regen_composite_kat.py [testvectors.json] > test/composite_kat.txt

(an optional local copy of the pinned testvectors.json avoids the download).

Source of truth: lamps-wg/draft-composite-sigs src/testvectors.json (base64
there; we emit hex). EVERY field the draft ships is vendored and tested by
composite_kat_test, so none can silently go unchecked: the shared message `m`
and context string `ctx`, and per vector `pk`, `s` (signature over m, empty
ctx), `sWithContext` (over m with ctx), `sk` (raw private key), `sk_pkcs8` and
`x5c` (self-signed certificate). The plain ML-DSA vectors (id-ML-DSA-*) are the
default provider's algorithms, not ours, and are deliberately not vendored.
"""
import base64
import json
import sys
import urllib.request

TAG = "draft-ietf-lamps-pq-composite-sigs-19"
URL = ("https://raw.githubusercontent.com/lamps-wg/draft-composite-sigs/"
       + TAG + "/src/testvectors.json")

# Vendored per-vector fields, in KAT-file column order (after the name). The
# list is explicit, not derived from the JSON: each field needs a test, and
# composite_kat_test indexes these columns by name (its KAT_* offsets and
# kat_col_name). Staying in sync is enforced, not trusted: main() refuses any
# field the source has that is not listed here, or lacks one that is, and the
# emitted "#! columns:" header is checked by composite_kat_test against its own
# layout.
FIELDS = ("pk", "s", "sWithContext", "sk", "sk_pkcs8", "x5c")

# testvectors.json tcId -> the algorithm name this provider registers.
# Full draft-19 standardized matrix (18 combos, OIDs .37 .. .54).
NAMES = {
    "id-MLDSA44-RSA2048-PSS-SHA256": "mldsa44_rsa2048_pss",
    "id-MLDSA44-RSA2048-PKCS15-SHA256": "mldsa44_rsa2048_pkcs15",
    "id-MLDSA44-Ed25519-SHA512": "mldsa44_ed25519",
    "id-MLDSA44-ECDSA-P256-SHA256": "mldsa44_ecdsa_p256",
    "id-MLDSA65-RSA3072-PSS-SHA512": "mldsa65_rsa3072_pss",
    "id-MLDSA65-RSA3072-PKCS15-SHA512": "mldsa65_rsa3072_pkcs15",
    "id-MLDSA65-RSA4096-PSS-SHA512": "mldsa65_rsa4096_pss",
    "id-MLDSA65-RSA4096-PKCS15-SHA512": "mldsa65_rsa4096_pkcs15",
    "id-MLDSA65-ECDSA-P256-SHA512": "mldsa65_ecdsa_p256",
    "id-MLDSA65-ECDSA-P384-SHA512": "mldsa65_ecdsa_p384",
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512": "mldsa65_ecdsa_bp256",
    "id-MLDSA65-Ed25519-SHA512": "mldsa65_ed25519",
    "id-MLDSA87-ECDSA-P384-SHA512": "mldsa87_ecdsa_p384",
    "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512": "mldsa87_ecdsa_bp384",
    "id-MLDSA87-Ed448-SHAKE256": "mldsa87_ed448",
    "id-MLDSA87-RSA3072-PSS-SHA512": "mldsa87_rsa3072_pss",
    "id-MLDSA87-RSA4096-PSS-SHA512": "mldsa87_rsa4096_pss",
    "id-MLDSA87-ECDSA-P521-SHA512": "mldsa87_ecdsa_p521",
}


def hexof(b64):
    return base64.b64decode(b64).hex()


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    else:
        with urllib.request.urlopen(URL) as f:  # nosec: pinned, read-only
            data = json.load(f)
    unknown = set(data) - {"m", "ctx", "tests"}
    if unknown:
        sys.exit("unvendored top-level fields: %s" % ", ".join(sorted(unknown)))
    lines = [
        "# Composite ML-DSA KAT vectors from draft-ietf-lamps-pq-composite-sigs",
        "# source: lamps-wg/draft-composite-sigs %s src/testvectors.json" % TAG,
        "# regenerate: python3 test/regen_composite_kat.py > test/composite_kat.txt",
        "# format: m <msg_hex> | ctx <ctx_hex> | <name> " + " ".join(
            "<%s_hex>" % k for k in FIELDS),
        "#! columns: " + " ".join(("name",) + FIELDS),
        "m %s" % hexof(data["m"]),
        "ctx %s" % hexof(data["ctx"]),
    ]
    seen = set()
    for t in data["tests"]:
        name = NAMES.get(t["tcId"])
        if name is None:
            continue
        unknown = set(t) - set(FIELDS) - {"tcId"}
        if unknown:
            sys.exit("%s: unvendored fields: %s"
                     % (t["tcId"], ", ".join(sorted(unknown))))
        absent = set(FIELDS) - set(t)
        if absent:
            sys.exit("%s: fields missing from the source: %s"
                     % (t["tcId"], ", ".join(sorted(absent))))
        lines.append(" ".join([name] + [hexof(t[k]) for k in FIELDS]))
        seen.add(t["tcId"])
    missing = set(NAMES) - seen
    if missing:
        sys.exit("missing tcIds in source: %s" % ", ".join(sorted(missing)))
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
