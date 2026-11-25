# Interop against the IETF Hackathon PQC certificate corpus

Status of interoperability between this provider and the multi-vendor artifact
repository [IETF-Hackathon/pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates),
driven by one tool,
[`test/pqc_corpus_interop.py`](../test/pqc_corpus_interop.py).

That repo is the canonical serialized-artifact interop corpus: each vendor
uploads, per algorithm/OID, self-signed trust-anchor certs (+ keys), composite
KEM decapsulation vectors, and CMS `EnvelopedData` (KEMRI) blobs, and CI
cross-verifies everyone against everyone — exactly the model this provider's
composite family targets.

## Capability-driven, no OID arc

The tool does **not** filter the corpus to a hand-curated OID arc. It walks every
artifact of every peer and asks one question per artifact — *can anything
currently loaded handle this?* — which partitions each algorithm OID:

- **ours** — the hybrid provider serves this OID (discovered at runtime by
  enumerating its algs and reading the OID its own keys embed). A corpus artifact
  for an OID we serve that we cannot verify / decapsulate / decrypt is a real
  **FAIL** (regression or drift). The LAMPS composite arc
  (`1.3.6.1.5.5.7.6.37`–`.66`) is must-pass too, so a brand-new composite OID the
  corpus ships is surfaced under `--strict` before `COMPOSITE_*_LIST` catches up.
- **qualified** — not ours, but a loaded component provider handles it: interop
  with that component is confirmed. Loading `oqsprovider` thus qualifies its
  plain-PQ algorithms (Falcon, …) against the corpus for free — no arc to curate
  (`--providers "default hybrid oqsprovider=/path/oqsprovider.so"`).
- **not-served** — nothing loaded can complete the operation: informational (the
  corpus ships ~30 algorithm families; e.g. McEliece with no such provider).

"Served" means the **operation actually completed to the right answer**, not that
the key merely parsed — so an algorithm whose SPKI decodes but whose signature
OpenSSL cannot verify (e.g. pre-hash HashML-DSA on an OpenSSL that lacks it) is
correctly *not-served*, not a false failure.

## The three artifact kinds

One walk covers all three overlaps the corpus and this provider share:

| Kind | Corpus artifact | Check | Floor |
|---|---|---|---|
| `sig` | `…_ta.der` trust-anchor cert | `openssl verify` the self-signed cert | 3.5+ |
| `kem` | `…_ciphertext.bin` + `…_ss.bin` + `…_priv.der` | decapsulate → match the shipped shared secret | 3.5+ |
| `cms` | `…_kemri_id-alg-hkdf-with-sha256.der` (RFC 9629) | `cms -decrypt` → match `expected_plaintext.txt` | 3.6+ |

Composite components (ML-DSA/ML-KEM + RSA/ECDSA/EdDSA/ECDH/X25519/X448) come from
the default provider (OpenSSL 3.5+; the composite OIDs from hybrid-provider). CMS
KEMRI recipient auto-selection landed in OpenSSL **3.6.0**; below that the `cms`
kind self-skips per-kind — `sig` and `kem` still run.

*Which peers* ship a given kind is curated (it mirrors the corpus and keeps a
third party's mislabeled blob in a kind it does not really publish from reddening
the gate); `--peers` overrides all three at once.

## Modes

```sh
# read peers (default), generate ours, or both:
python3 ./test/pqc_corpus_interop.py --openssl <ossl> --libpath <libdir> \
    --module-dir <build> [verify|generate|all]
```

- **`verify`** (*they generate, we read*): download each peer's zip and classify
  every artifact as above. `--strict` turns an unreachable peer — and any
  composite OID we cannot read — from SKIP into FAIL.
- **`generate`** (*we generate, others read*): emit this provider's composite
  `sig` + `kem` + `cms` artifacts in the corpus flat layout (`id-<alg>-<OID>_…`)
  and self-verify. This is the set to zip under `providers/hybrid-provider/` for a
  submission, after which the corpus CI verifies *us*.
- **`all`** — both.

Beyond verifying the cert / decapsulating / decrypting, the tool also checks
**every shipped private-key form** (`_priv`, and ML-DSA/ML-KEM's `_seed` /
`_expandedkey` / `_both`): each must load, yield the artifact's public key
("consistent"), and — for signatures — sign a message that verifies under it.
This exercises the PKCS#8 decoder and signer the cert verify never touches; a
form that does not load is a SKIP (peers ship encodings the spec does not
define), a loadable form that fails is a FAIL for an OID we must read.

Useful flags: `--providers "name[=/path] …"` (what to load), `--propquery` (pin a
contested algorithm to a provider), `--provider-param NAME:KEY=VAL`, `--csv PATH`
(flat per-OID coverage table), `--compat-csv DIR` / `--csv-consumer NAME` (write
the corpus's own `compatMatrices` submission CSVs, `<peer>_<consumer>.csv`),
`-v/--verbose` (per-artifact trail behind the summary), `--workdir` / `--keep`,
`--round` / `--cms-version`.

## Results

Representative run — every default peer, 0 failures:

- **`sig` — composite ML-DSA** (`draft-ietf-lamps-pq-composite-sigs`, OIDs
  `.37`–`.54`, 18 combos): **18/18 distinct OIDs** verified from all 12 draft-19
  composite providers (`bc`, `cht`, `composite-crypto`, `composite-sigs-ref-impl`,
  `crypto4a`, `cryptonext`, `entrust`, `openssl-composite-preliminary-impl`,
  `safelogic`, …; `carl-redhound`/`entrust-pkihub`/`leancrypto` ship subsets).
- **`kem` — composite ML-KEM** (`draft-ietf-lamps-pq-composite-kem`, OIDs
  `.55`–`.66`, 12 combos): **12/12** decapsulated from each of six independent
  impls (`composite-kem-ref-impl`, `bc`, `cht`, `crypto4a`, `cryptonext`,
  `entrust`) — the full matrix incl. brainpool `.61`/`.64`.
- **`cms` — composite ML-KEM KEMRI** (RFC 9629, 3.6+): **12/12** decrypted from
  each of two independent draft-18 impls (`composite-crypto`, `bc`).

Pure ML-DSA/ML-KEM/SLH-DSA artifacts from the same corpus come out as
**qualified** (served by the default provider), demonstrating the plain-PQ
components this provider composes with; loading another component provider
qualifies its algorithms the same way. Write direction: `generate` produces and
self-verifies **18 sig + 12 kem + 12 cms** conformant artifacts. No artifacts
have been submitted to the corpus yet — the capability is in place, participation
would be opt-in.

## Weekly drift guard

[`scripts/check-pqc-certs-drift.sh`](../scripts/check-pqc-certs-drift.sh)
(`.github/workflows/pqc-certs-interop.yml`, weekly) drives the tool's `generate`
(for the composite OIDs our encoder emits) and `--strict verify`, then diffs our
OIDs against the corpus's canonical `docs/oid_mapping.md` and flags a newer
artifact round. It exits 0 in sync, 1 on drift (opens a tracking issue), 2 on a
tooling error. Run it locally with the same `OPENSSL_BIN` / `OPENSSL_LIBPATH` /
`MODULE_DIR` the tool takes.

Beyond this static corpus, the CMS KEMRI wire format is also checked **live, both
ways** against the independent
[kemri_toy](https://github.com/carl-wallace/kemri_toy) implementation by
[`test/pqc_kem_cms_interop.sh`](../test/pqc_kem_cms_interop.sh).
