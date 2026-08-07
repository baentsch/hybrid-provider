# Interop against the IETF Hackathon PQC certificate corpus

Status of interoperability between this provider and the multi-vendor artifact
repository [IETF-Hackathon/pqc-certificates](https://github.com/IETF-Hackathon/pqc-certificates),
driven by [`test/pqc_certificates_interop.sh`](../test/pqc_certificates_interop.sh).

- **Environment:** OpenSSL 4.1.0-dev; artifact round **r5**.
- **Overlap:** LAMPS **composite ML-DSA signatures**
  (`draft-ietf-lamps-pq-composite-sigs`), OID arc `1.3.6.1.5.5.7.6.37`–`.54` —
  exactly this provider's `COMPOSITE_SIG_LIST` (18 standardized combos). Pure
  ML-DSA/ML-KEM are the default provider's; our concatenation hybrid KEMs and
  oqs-arc hybrid signatures are not part of that repo's "modern" set.
- **Components:** the ML-DSA + RSA/ECDSA/EdDSA halves come from the default
  provider (OpenSSL 3.5+).

## What the repo is

Each vendor uploads `providers/<name>/artifacts_certs_r5.zip` — self-signed
trust-anchor certs (`…_ta.der`/`.pem`) plus keys (`…_priv.der`) named
`id-<combo>-<OID>_…`, one per algorithm/OID — and CI cross-verifies every
provider against every other. It is the canonical serialized-artifact interop
corpus, exactly the model this provider's composite family targets.

## How this is tested

`test/pqc_certificates_interop.sh` has three modes:

- **`verify`** (read direction — *they generate, we read*): download each peer's
  `artifacts_certs_r5.zip`, and for every composite trust-anchor cert (matched by
  the arc OID in the filename) run `openssl verify` under a `default + hybrid`
  config. hybrid-provider must decode the composite SPKI and check the composite
  signature. A shared OID that fails to verify is a real FAIL; an unreachable zip
  or a peer with no composite certs is a SKIP.
- **`generate`** (write direction — *we generate, others read*): emit this
  provider's composite artifacts (self-signed `_ta` cert in DER+PEM, PKCS#8
  `_priv.der`) in the repo's r5 flat naming, and self-verify them. This is the
  set to zip as `artifacts_certs_r5.zip` for a `providers/hybrid-provider/`
  submission, after which the repo's own CI (OQS docker + the other providers'
  `check.sh`) verifies *us* — the reverse direction, run there.
- **`all`** — both.

```sh
./test/pqc_certificates_interop.sh --openssl <ossl> --libpath <libdir> \
    --module-dir <build> all
# customise peers / round / output dir:
./test/pqc_certificates_interop.sh --peers "bc composite-sigs-ref-impl" --round r5 \
    --outdir ./hp-artifacts generate
```

The composite algorithm names are enumerated from the provider (the
`mldsa*`-prefixed signature algorithms), not hard-coded; matching against peers
is purely by OID, since the friendly names differ between implementations.

## Results

### Read direction — peers' composite certs verified by hybrid-provider (r5)

| Peer (`providers/<name>`) | Composite trust-anchor certs verified |
|---|---|
| `composite-sigs-ref-impl` (LAMPS reference impl) | **18 / 18** |
| `bc` (BouncyCastle) | **18 / 18** |
| `openssl-composite-preliminary-impl` | **18 / 18** |
| `composite-crypto` | **18 / 18** |
| `ossl35` | — (ships no composite certs in r5; skipped) |

**All 18 standardized composite combos verify against every peer that provides
them** — i.e. hybrid-provider reads and verifies real draft-19 composite
certificates from four independent implementations. This corroborates, over the
wire and against third parties, the byte-exact conformance the in-repo
`composite_kat_test` asserts against the draft-19 published vectors.

### Write direction — hybrid-provider's own artifacts

`generate` produced and self-verified **18 / 18** composite artifacts in the r5
flat layout (54 files: `_ta.der`, `_ta.pem`, `_priv.der` per combo), e.g.
`id-mldsa44_ecdsa_p256-1.3.6.1.5.5.7.6.40_ta.der`. Notes:

- The filename prefix is this provider's local algorithm name; the **OID is the
  canonical identifier** the repo's automation keys on. A formal submission may
  rename the prefix to the registered friendly name — functionally moot.
- We emit the standard PKCS#8 `_priv.der`; the impl-specific `_priv.raw` form is
  omitted.
- Local self-verification proves the artifacts round-trip through our own
  decoder/verify. The actual *cross*-verification of our artifacts by other
  implementations is what the pqc-certificates CI runs once the zip is submitted
  under `providers/hybrid-provider/`.

## Conclusion

For the composite-signature overlap, hybrid-provider is **fully interoperable in
the read direction today**: 18/18 across four independent third-party
implementations, no failures. It also produces a conformant r5 artifact set for
the write direction; landing that in the repo (as a `providers/hybrid-provider/`
submission) is the remaining step to appear in the public compatibility matrix.
