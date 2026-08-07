# Composite-signature interop: hybrid-provider ↔ composite-provider

Status of interoperability between this provider and
[CompositeCrypto/composite-provider](https://github.com/CompositeCrypto/composite-provider)
on the one thing the two overlap on: **LAMPS composite ML-DSA signatures**
(`draft-ietf-lamps-pq-composite-sigs`). Driven by
[`test/composite_interop.sh`](../test/composite_interop.sh).

- **Environment:** OpenSSL 4.1.0-dev; composite-provider `main` @ `ed86b5e`.
- **Date:** 2026-08-07.
- **Scope:** signatures only. composite-provider *also* targets composite
  ML-KEM (OID arc `.55+`), which this provider does not implement (our KEMs are
  TLS-concatenation hybrids, a different construction) — so KEM is not an overlap
  and is out of scope here. composite-provider's KEM side is a placeholder anyway.

## TL;DR

| | hybrid-provider | composite-provider (`main`, `ed86b5e`) |
|---|---|---|
| Advertises the 18 standardized combos (OIDs `.37`–`.54`) | ✅ | ✅ |
| `genpkey` (composite key generation) | ✅ all 18 | ❌ fails (`evp_keymgmt_gen: provider keymgmt failure`) |
| Self-signed cert (`req -x509`) | ✅ all 18 | ❌ (no key to sign with) |
| Decode a draft-19 composite SPKI written by the peer | ✅ | ❌ `X509_PUBKEY_get0: decode error` |
| Verify a peer-produced composite cert | ✅ (own certs; KAT-validated) | ❌ |
| Internal KAT vs draft-19 test vectors | ✅ `composite_kat_test` | — (none) |

**Bottom line:** the two cannot interoperate on composite signatures **today**,
because composite-provider's composite crypto is not yet functional — it
registers the algorithm names and OIDs but cannot generate composite keys or
decode a composite public key. This is a peer-maturity gap, **not** a wire-format
disagreement: we never get far enough to compare bytes. The check script
(`test/composite_interop.sh`) self-skips cleanly now and will exercise real
cross-verification automatically once the peer's keygen/decoder work.

## Claims vs. reality (composite-provider)

For context on the results below: composite-provider (`main`, `ed86b5e`) **makes
no interoperability claim** — the word does not appear in its README, docs, or
summary, and there are no KAT / test-vector / cross-implementation checks in the
repo. What it does state, and how that squares with observed behaviour:

- *"Implements the ML-DSA and ML-KEM composite standards."* — Its **"Standards
  Compliance"** section cites **FIPS 204 (ML-DSA)** and **FIPS 203 (ML-KEM)**,
  i.e. the *component* algorithms, not the composite construction; the composite
  part is only *"follows the principles outlined in various IETF drafts and
  academic papers"* — no named draft/version, OID/label conformance, or vectors.
- *"Full OpenSSL 3.0 Provider API compliance"* / *"C99 Standard."* — Provider
  plumbing and code style, not crypto interop.
- `IMPLEMENTATION_SUMMARY.md` calls it a *"production-ready framework"*, yet the
  same file and `docs/ARCHITECTURE.md` describe the cryptographic operations as
  **"placeholders"** and list *key generation*, *key import/export* and *ASN.1
  encoding/decoding* as **future** work — so the "production-ready" wording is
  aspirational and internally inconsistent with the placeholder crypto.

Net: the only layer genuinely aligned today is **identifiers** — it registers the
correct LAMPS OID arc and combo names. That is exactly why the check below can
*pair* algorithms by OID but cannot get past the peer's key generation / SPKI
decode to actually exchange an artifact. No interoperability is claimed, and none
can currently be substantiated.

## Algorithms — the overlap

Both providers advertise the **same 18 standardized draft-19 combos**, under the
same OID arc but different provider-local names. Matching is therefore by OID.

| OID `1.3.6.1.5.5.7.6.` | Combo | hybrid-provider name | composite-provider name |
|---|---|---|---|
| `.37` | ML-DSA-44 + RSA-2048 PSS         | `mldsa44_rsa2048_pss`    | `MLDSA44-RSA2048-PSS-SHA256` |
| `.38` | ML-DSA-44 + RSA-2048 PKCS#1v1.5  | `mldsa44_rsa2048_pkcs15` | `MLDSA44-RSA2048-PKCS15-SHA256` |
| `.39` | ML-DSA-44 + Ed25519             | `mldsa44_ed25519`        | `MLDSA44-Ed25519-SHA512` |
| `.40` | ML-DSA-44 + ECDSA P-256         | `mldsa44_ecdsa_p256`     | `MLDSA44-ECDSA-P256-SHA256` |
| `.41` | ML-DSA-65 + RSA-3072 PSS         | `mldsa65_rsa3072_pss`    | `MLDSA65-RSA3072-PSS-SHA512` |
| `.42` | ML-DSA-65 + RSA-3072 PKCS#1v1.5  | `mldsa65_rsa3072_pkcs15` | `MLDSA65-RSA3072-PKCS15-SHA512` |
| `.43` | ML-DSA-65 + RSA-4096 PSS         | `mldsa65_rsa4096_pss`    | `MLDSA65-RSA4096-PSS-SHA512` |
| `.44` | ML-DSA-65 + RSA-4096 PKCS#1v1.5  | `mldsa65_rsa4096_pkcs15` | `MLDSA65-RSA4096-PKCS15-SHA512` |
| `.45` | ML-DSA-65 + ECDSA P-256         | `mldsa65_ecdsa_p256`     | `MLDSA65-ECDSA-P256-SHA512` |
| `.46` | ML-DSA-65 + ECDSA P-384         | `mldsa65_ecdsa_p384`     | `MLDSA65-ECDSA-P384-SHA512` |
| `.47` | ML-DSA-65 + ECDSA brainpoolP256r1 | `mldsa65_ecdsa_bp256`  | `MLDSA65-ECDSA-brainpoolP256r1-SHA512` |
| `.48` | ML-DSA-65 + Ed25519             | `mldsa65_ed25519`        | `MLDSA65-Ed25519-SHA512` |
| `.49` | ML-DSA-87 + ECDSA P-384         | `mldsa87_ecdsa_p384`     | `MLDSA87-ECDSA-P384-SHA512` |
| `.50` | ML-DSA-87 + ECDSA brainpoolP384r1 | `mldsa87_ecdsa_bp384`  | `MLDSA87-ECDSA-brainpoolP384r1-SHA512` |
| `.51` | ML-DSA-87 + Ed448               | `mldsa87_ed448`          | `MLDSA87-Ed448-SHAKE256` |
| `.52` | ML-DSA-87 + RSA-3072 PSS         | `mldsa87_rsa3072_pss`    | `MLDSA87-RSA3072-PSS-SHA512` |
| `.53` | ML-DSA-87 + RSA-4096 PSS         | `mldsa87_rsa4096_pss`    | `MLDSA87-RSA4096-PSS-SHA512` |
| `.54` | ML-DSA-87 + ECDSA P-521         | `mldsa87_ecdsa_p521`     | `MLDSA87-ECDSA-P521-SHA512` |

Not part of the overlap:
- **hybrid-provider** additionally carries an experimental composite arc (e.g.
  `exp_mayo2_ecdsa_p256`, no standardized OID) — non-normative, no peer.
- **composite-provider** additionally advertises composite ML-KEM (OIDs `.55+`);
  out of scope (we don't implement composite KEM) and placeholder on their side.

## How interop is tested

`test/composite_interop.sh` treats the OID as the only stable cross-provider
identifier (the names differ) and works through **serialized artifacts**:

1. Under a `default + hybrid` config and a `default + composite` config, list
   each provider's signature algorithms and, for each, `genpkey` → `req -x509` a
   self-signed certificate. The classical + ML-DSA components come from the
   default provider (OpenSSL 3.5+).
2. Read each cert's composite OID (`asn1parse`, matching the `1.3.6.1.5.5.7.6.*`
   arc). Non-composite entries have no such OID and drop out.
3. For every OID produced by **both** providers, cross-verify both directions:
   - the **hybrid**-generated cert is verified under **composite-provider**;
   - the **composite-provider**-generated cert is verified under **hybrid**.

`PASS` = cross-verify succeeds, `FAIL` = a shared OID fails to verify (a genuine
interop break), `SKIP` = only one side produced that OID (different subsets) or a
provider could not produce the artifact at all.

```sh
# Peer already on the module path:
./test/composite_interop.sh --openssl <ossl> --libpath <libdir> --module-dir <build>
# Or fetch + build the peer first (into .interop/, symlinked into the module dir):
OPENSSL_PREFIX=<prefix> ./test/composite_interop.sh --build --module-dir <build> ...
```

## Results (which generated, which read)

Against composite-provider `main` @ `ed86b5e`:

| Direction | Generator | Reader / verifier | Result |
|---|---|---|---|
| hybrid → composite-provider | hybrid (all 18) | composite-provider | ❌ reader fails: `X509_PUBKEY_get0: decode error` for every combo — it recognizes the OID but cannot decode the composite SPKI |
| composite-provider → hybrid | composite-provider | hybrid | ⏭️ not reachable: composite-provider cannot `genpkey` (`evp_keymgmt_gen: provider keymgmt failure`), so it produces no cert to hand over |

Consequently the script's OID-matched cross-verify forms **zero pairs** (one side
generates nothing) and reports `SKIP` with the reason
*"composite-provider produced no composite certs (keygen unimplemented …)"*.

For reference, the hybrid-provider side is independently proven within this repo:
`composite_kat_test` validates the same 18 combos byte-for-byte against the
draft-19 published test vectors, and `composite_test` / `composite_encode` round-
trip keys and signatures through our own encoders/decoders.

## Conclusion & re-test

- The composite-signature overlap is **specified-compatible** (identical OID
  arc, identical combo set) but **not yet interoperable in practice**, blocked
  entirely on composite-provider's composite crypto being non-functional
  (keygen + SPKI decode) as of `ed86b5e`.
- Nothing here indicates a wire-format problem on the hybrid-provider side; a
  real byte-level comparison is only possible once the peer can produce/consume
  composite keys.
- Re-run `test/composite_interop.sh --build` after the peer matures; it will move
  from `SKIP` to `PASS`/`FAIL` automatically as soon as both sides can generate
  and read composite certificates.
