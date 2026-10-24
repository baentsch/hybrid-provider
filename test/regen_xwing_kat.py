#!/usr/bin/env python3
"""Regenerate test/xwing_kat.txt from the X-Wing draft's own reference vectors.

The KAT file is vendored so xwing_kat_test stays hermetic (no network at test
time), but it must not silently go stale: run this to refresh it from the pinned
draft revision, and bump TAG when moving to a newer draft. The vectors are
version-sensitive — the combiner label and the ML-KEM-768 finalisation shifted
across early revisions — so they only compare at a matched draft version.

    python3 test/regen_xwing_kat.py > test/xwing_kat.txt

Source of truth: dconnolly/draft-connolly-cfrg-xwing-kem spec/test-vectors.json
(hex already). We emit only the fields the decapsulation KAT needs:

    sk  the 32-byte X-Wing decapsulation (private) key seed
    pk  the 1216-byte encapsulation (public) key
    ct  the 1120-byte ciphertext
    ss  the expected 32-byte shared secret

The scheduled coherence check (.github/workflows/xwing-kat-drift.yml via
scripts/check-xwing-kat-drift.sh) re-runs this against the pinned tag and flags
any drift between upstream and the vendored copy.

Companion: test/regen_xwing_kat_keys.py derives test/xwing_kat_keys.txt (the
EXPANDED decapsulation keys xwing_kat_test raw-imports) from the seeds emitted
here. If these vectors move, regenerate that file too.
"""
import json
import sys
import urllib.request

# Upstream source of truth. These three lines are the ONLY place the upstream
# identity lives; scripts/check-xwing-kat-drift.sh reads REPO and TAG back out of
# this file (never hardcoding them), and everything else (URL, the vendored file
# header, the git ref for tag listing) is derived from them. Bump TAG (and, if the
# repo ever moves, REPO) to track a new draft revision.
REPO = "dconnolly/draft-connolly-cfrg-xwing-kem"   # GitHub owner/name
TAG = "draft-connolly-cfrg-xwing-kem-11"           # pinned draft tag
VECTORS_PATH = "spec/test-vectors.json"            # path within the repo
URL = "https://raw.githubusercontent.com/%s/%s/%s" % (REPO, TAG, VECTORS_PATH)

FIELDS = ("sk", "pk", "ct", "ss")


def main():
    with urllib.request.urlopen(URL) as f:      # nosec: pinned, read-only
        data = json.load(f)
    lines = [
        "# X-Wing KEM KAT vectors (reconstruct-from-seed decapsulation oracle)",
        "# source: %s  %s  %s" % (REPO, TAG, VECTORS_PATH),
        "# regenerate: python3 test/regen_xwing_kat.py > test/xwing_kat.txt",
        "# format: <sk_hex> <pk_hex> <ct_hex> <ss_hex>",
        "#   decapsulate(ct) under the key expanded from sk must yield ss.",
    ]
    for t in data:
        missing = [k for k in FIELDS if k not in t]
        if missing:
            sys.exit("vector missing fields: %s" % ", ".join(missing))
        lines.append(" ".join(t[k] for k in FIELDS))
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
