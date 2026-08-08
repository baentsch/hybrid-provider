#!/usr/bin/env python3
"""Regenerate test/composite_kem_kat.txt from the draft's own reference vectors.

The KAT file is vendored so the tests stay hermetic (no network at test time),
but it must not silently go stale: run this to refresh it from the pinned draft
revision, and bump TAG when moving to a newer draft.

    python3 test/regen_composite_kem_kat.py > test/composite_kem_kat.txt

Source of truth: lamps-wg/draft-composite-kem src/testvectors.json. Per test we
take the PKCS#8 private key (dk_pkcs8, the single-wrap composite privateKey), the
composite ciphertext (c) and the shared secret (k); all base64 there, emitted as
hex. The KAT decapsulates c with dk_pkcs8 and checks it recovers k — a real
cross-implementation check of the decoder + ML-KEM seed expansion + the SHA3-256
combiner against bytes this provider did not produce.
"""
import base64
import json
import sys
import urllib.request

TAG = "draft-ietf-lamps-pq-composite-kem-18"
URL = ("https://raw.githubusercontent.com/lamps-wg/draft-composite-kem/"
       + TAG + "/src/testvectors.json")

# testvectors.json tcId -> the algorithm name this provider registers.
# Full draft-18 standardized matrix (12 combos, OIDs .55 .. .66).
NAMES = {
    "id-MLKEM768-RSA2048-SHA3-256": "mlkem768_rsa2048",
    "id-MLKEM768-RSA3072-SHA3-256": "mlkem768_rsa3072",
    "id-MLKEM768-RSA4096-SHA3-256": "mlkem768_rsa4096",
    "id-MLKEM768-X25519-SHA3-256": "mlkem768_x25519",
    "id-MLKEM768-ECDH-P256-SHA3-256": "mlkem768_p256",
    "id-MLKEM768-ECDH-P384-SHA3-256": "mlkem768_p384",
    "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256": "mlkem768_bp256",
    "id-MLKEM1024-RSA3072-SHA3-256": "mlkem1024_rsa3072",
    "id-MLKEM1024-ECDH-P384-SHA3-256": "mlkem1024_p384",
    "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256": "mlkem1024_bp384",
    "id-MLKEM1024-X448-SHA3-256": "mlkem1024_x448",
    "id-MLKEM1024-ECDH-P521-SHA3-256": "mlkem1024_p521",
}


def hexof(b64):
    return base64.b64decode(b64).hex()


def main():
    with urllib.request.urlopen(URL) as f:      # nosec: pinned, read-only
        data = json.load(f)
    lines = [
        "# Composite ML-KEM KAT vectors from draft-ietf-lamps-pq-composite-kem",
        "# source: lamps-wg/draft-composite-kem %s src/testvectors.json" % TAG,
        "# regenerate: python3 test/regen_composite_kem_kat.py"
        " > test/composite_kem_kat.txt",
        "# format: <name> <pkcs8_priv_hex> <ciphertext_hex> <shared_secret_hex>"
        "  (decapsulate ciphertext with priv -> shared secret)",
    ]
    seen = set()
    for t in data["tests"]:
        name = NAMES.get(t["tcId"])
        if name is None:
            continue
        lines.append("%s %s %s %s"
                     % (name, hexof(t["dk_pkcs8"]), hexof(t["c"]), hexof(t["k"])))
        seen.add(t["tcId"])
    missing = set(NAMES) - seen
    if missing:
        sys.exit("missing tcIds in source: %s" % ", ".join(sorted(missing)))
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
