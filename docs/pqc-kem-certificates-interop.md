# Interop against the IETF Hackathon PQC corpus — composite ML-KEM

Status of interoperability between this provider and the multi-vendor artifact
repository [IETF-Hackathon/pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates)
for the **KEM** overlap, driven by
[`test/pqc_kem_certificates_interop.sh`](../test/pqc_kem_certificates_interop.sh).
This is the KEM companion to [`pqc-certificates-interop.md`](pqc-certificates-interop.md)
(composite ML-DSA signatures, issue #31).

- **Environment:** OpenSSL 3.5.6; artifact round **r5**.
- **Overlap:** LAMPS **composite ML-KEM**
  (`draft-ietf-lamps-pq-composite-kem`), OID arc `1.3.6.1.5.5.7.6.55`–`.66` —
  exactly this provider's `COMPOSITE_KEM_LIST` (12 standardized combos).
- **Components:** the ML-KEM + RSA-OAEP/ECDH/X25519/X448 halves come from the
  default provider (OpenSSL 3.5+).
- **Peer:** the LAMPS reference implementation only
  (`providers/composite-kem-ref-impl/`). This is deliberate — the reference impl
  is the conformance oracle; the harness does not consume any other provider's
  artifacts.

## Why a decapsulation check (not a cert verify)

The signature interop verifies self-signed trust-anchor certificates. A KEM
public key cannot sign, so there is no self-signed anchor to verify. Instead the
reference implementation ships, per composite-KEM OID, a self-contained
decapsulation vector:

```
id-<combo>-<OID>_ee.der         end-entity cert carrying the composite ML-KEM pubkey
id-<combo>-<OID>_priv.der       PKCS#8 composite private key (mlkemSeed || tradSK)
id-<combo>-<OID>_ciphertext.bin composite ciphertext (mlkemCT || tradCT)
id-<combo>-<OID>_ss.bin         the 32-byte shared secret
```

The interop check is therefore: load their `_priv.der`, decapsulate their
`_ciphertext.bin`, and confirm we recover their `_ss.bin`. A pass exercises the
decoder, the ML-KEM seed expansion, the traditional-component decapsulation and
the SHA3-256 combiner end-to-end against bytes this provider did not produce.

## How this is tested

`test/pqc_kem_certificates_interop.sh` has three modes, run under a
`default + hybrid` OpenSSL config:

- **`verify`** (read direction — *reference generates, we read*): download
  `composite-kem-ref-impl/artifacts_certs_r5.zip`; for each composite-KEM OID,
  `openssl pkeyutl -decap` the reference ciphertext with the reference key and
  compare the recovered secret to the reference `_ss.bin`. A shared OID whose
  secret does not match is a real FAIL; an unreachable zip is a SKIP.
- **`generate`** (write direction — *we generate, others read*): emit this
  provider's composite ML-KEM artifacts (PKCS#8 `_priv.der`, SPKI `_pub.der`, and
  a self-encapsulated `_ciphertext.bin` + `_ss.bin`) in the repo's r5 flat
  naming, and self-verify by decapsulating. This is the set to submit under
  `providers/hybrid-provider/` so peers can decapsulate our ciphertexts.
- **`all`** — both.

Composites are identified by the LAMPS OID arc, never by a name convention: the
generate direction enumerates the provider's KEM algorithms and keeps only those
whose public key encodes to a `1.3.6.1.5.5.7.6.55`–`.66` OID.

Not wired into ctest (needs network + an external corpus); it self-skips on an
unreachable zip or a missing component. The in-repo `composite_kem_kat_test`
(the draft's own vectors) covers the same construction hermetically.

## Results (OpenSSL 3.5.6, r5)

Read direction — `composite-kem-ref-impl` decaps vectors checked by hybrid-provider:

| Peer | Decapsulated to reference secret |
|---|---|
| `composite-kem-ref-impl` (LAMPS reference) | **12 / 12** |

**12/12 distinct composite-KEM OIDs recovered the reference shared secret, zero
failures** — real cross-implementation interop against the LAMPS reference
implementation for the full combo matrix (ML-KEM-768/1024 × RSA-OAEP / ECDH
P-256·P-384·P-521·brainpool / X25519 / X448), corroborating the in-repo
`composite_kem_kat_test` over the wire.

Write direction — `generate` produces + self-verifies **12/12** conformant
artifacts.

## Reproduce

```sh
test/pqc_kem_certificates_interop.sh \
    --openssl /path/to/openssl-3.5+/bin/openssl \
    --libpath /path/to/openssl-3.5+/lib64 \
    --module-dir build \
    all
```
