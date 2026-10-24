#!/usr/bin/env python3
"""Derive test/xwing_kat_keys.txt — the EXPANDED X-Wing decapsulation keys —
from the vendored seed vectors in test/xwing_kat.txt.

Why a separate, derived oracle (and not one more column in xwing_kat.txt):

  * xwing_kat.txt mirrors the upstream draft vectors verbatim (``sk pk ct ss``)
    and is guarded — buildlessly — by scripts/check-xwing-kat-drift.sh (python3,
    git and network only). Keeping it a pure mirror preserves that guarantee.
  * This file instead holds the *expanded* decapsulation key for each vector, so
    xwing_kat_test can raw-import it with NO seed API and therefore run wherever
    ML-KEM-768 resolves — oqsprovider on 3.0-3.4, default provider on 3.5+ — not
    only on 3.5+.

Producing the expansion DOES need the 3.5+ ML-KEM seed machinery, so this script
requires an OpenSSL 3.5+ ``openssl`` with ML-KEM-768 (set $OPENSSL_BIN, default
``openssl``). That dependency lives ONLY here, off the weekly buildless path.

X-Wing expandDecapsulationKey (draft-connolly-cfrg-xwing-kem-11 §5.2):

    expanded = SHAKE-256(sk, 96)
    (d||z)   = expanded[0:64]   -> ML-KEM-768 keygen-from-seed -> dk (2400 B)
    sk_X     = expanded[64:96]  -> X25519 scalar (32 B)
    blob     = dk || sk_X       (slot order [ML-KEM | X25519], per HYBRID_KEM_LIST)

Regenerate:

    OPENSSL_BIN=/path/to/openssl-3.5 python3 test/regen_xwing_kat_keys.py \
        test/xwing_kat.txt > test/xwing_kat_keys.txt

If the upstream seeds move (xwing_kat.txt drift), regenerate BOTH files.
xwing_kat_test re-derives these keys from the seeds and asserts equality on 3.5+,
so a stale copy fails the build there.
"""
import hashlib
import os
import re
import subprocess
import sys

OPENSSL = os.environ.get("OPENSSL_BIN", "openssl")

XWING_SEED_LEN = 32      # sk
MLKEM768_SEED_LEN = 64   # d || z
X25519_PRV = 32          # sk_X
MLKEM768_PRV = 2400      # ML-KEM-768 dk


def mlkem768_dk_from_seed(dz_hex):
    """ML-KEM-768 keygen from the 64-byte (d||z) seed; return the 2400-byte dk."""
    pem = subprocess.run(
        [OPENSSL, "genpkey", "-algorithm", "ML-KEM-768",
         "-pkeyopt", "hexseed:" + dz_hex],
        capture_output=True, text=True, check=True).stdout
    text = subprocess.run(
        [OPENSSL, "pkey", "-text", "-noout"],
        input=pem, capture_output=True, text=True, check=True).stdout
    # -text prints "seed:", "dk:" and "ek:", each followed by an indented hex
    # block. Capture only the indented rows under "dk:" (the block ends at the
    # next, unindented "ek:" label).
    m = re.search(r"^dk:\n((?:[ \t]+[0-9a-f:]+\n)+)", text, re.MULTILINE)
    if m is None:
        sys.exit("error: %s did not emit a dk (needs ML-KEM / OpenSSL 3.5+)"
                 % OPENSSL)
    dk = bytes.fromhex("".join(re.findall(r"[0-9a-f]{2}", m.group(1))))
    if len(dk) != MLKEM768_PRV:
        sys.exit("error: expanded dk is %d bytes, expected %d"
                 % (len(dk), MLKEM768_PRV))
    return dk


def main():
    src = open(sys.argv[1]) if len(sys.argv) > 1 else sys.stdin
    out = [
        "# X-Wing expanded decapsulation keys (derived from test/xwing_kat.txt).",
        "# regenerate: OPENSSL_BIN=<openssl-3.5+> python3 "
        "test/regen_xwing_kat_keys.py test/xwing_kat.txt > test/xwing_kat_keys.txt",
        "# format: <sk_hex> <priv_blob_hex>   blob = ML-KEM-768 dk (2400 B) || "
        "X25519 scalar (32 B)",
        "#   xwing_kat_test raw-imports the blob (no seed API) and, on 3.5+, "
        "re-derives it from sk to self-check this file.",
    ]
    for line in src:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sk_hex = line.split()[0]
        sk = bytes.fromhex(sk_hex)
        if len(sk) != XWING_SEED_LEN:
            sys.exit("error: sk is %d bytes, expected %d" % (len(sk), XWING_SEED_LEN))
        expanded = hashlib.shake_256(sk).digest(MLKEM768_SEED_LEN + X25519_PRV)
        dz, sk_x = expanded[:MLKEM768_SEED_LEN], expanded[MLKEM768_SEED_LEN:]
        blob = mlkem768_dk_from_seed(dz.hex()) + sk_x
        out.append("%s %s" % (sk_hex, blob.hex()))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
