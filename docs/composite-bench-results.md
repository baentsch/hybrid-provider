# Composite certificate benchmark — results snapshot & deployment notes

This is an **illustrative snapshot** of `composite_bench` (see the *Composite
certificate benchmark* section of [../TESTING.md](../TESTING.md) for what it
measures and how to run it). Numbers are hardware-, build- and run-specific —
regenerate them in your own environment before drawing conclusions; do **not**
treat the values below as authoritative.

> ⚠️ **Interop scope.** The **experimental** rows are *not* deployable in an
> interoperating PKI: non-normative labels and OIDs in the private
> `1.3.9999.99.*` arc, interoperable only with ourselves / a matching
> oqsprovider. Deployment advice below therefore applies to the **standardized
> ML-DSA composite tier**; the experimental numbers are for research and for
> informing which families are worth pushing toward standardization.

## How to reproduce

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./composite_bench 2000
```

The experimental rows need [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
on the module search path; combos whose components are unavailable are skipped.

## Snapshot

Measured on an **AMD Ryzen 7 5800U**, **OpenSSL 3.5.6**, PQ components from
oqsprovider, per-op budget `2000` ms. `keygen`/`sign`/`verify` are milliseconds
per operation; `cert` is the DER length of a self-signed X.509 certificate.
Rows are grouped by NIST level so the standardized ML-DSA composites sit
side-by-side with the experimental OQS-family composites at the same level.

```
algorithm                          tier   keygen(ms)  sign(ms) verify(ms)  cert(bytes)
--- NIST level 1 (128-bit): ML-DSA-44 vs experimental ---
mldsa44_rsa2048_pss                std      29.440     1.026     0.120       4400
mldsa44_rsa2048_pkcs15             std      39.824     1.009     0.115       4400
mldsa44_ed25519                    std       0.114     0.527     0.189       3970
mldsa44_ecdsa_p256                 std       0.108     0.505     0.156       4009
exp_falconpadded512_ecdsa_p256     exp       5.191     0.425     0.307       1833
exp_mayo2_ecdsa_p256               exp       0.211     0.319     0.297       5367
exp_cross128bal_ecdsa_p256         exp       0.189     0.859     0.700      13495
exp_ovIspkc_ecdsa_p256             exp       1.051     0.314     0.381      66945
exp_snova2454_ecdsa_p256           exp       0.244     0.549     0.349       1533
exp_mqom2cat1_ecdsa_p256           exp       0.256     1.008     0.875       3604
--- NIST level 3 (192-bit): ML-DSA-65 vs experimental ---
mldsa65_rsa3072_pss                std     143.350     2.344     0.198       6185
mldsa65_rsa3072_pkcs15             std     136.361     2.345     0.188       6185
mldsa65_rsa4096_pss                std     395.560     4.564     0.213       6441
mldsa65_rsa4096_pkcs15             std     490.554     4.282     0.215       6441
mldsa65_ecdsa_p256                 std       0.172     0.900     0.215       5539
mldsa65_ecdsa_p384                 std       0.822     1.536     0.729       5604
mldsa65_ecdsa_bp256                std       0.450     1.160     0.457       5539
mldsa65_ed25519                    std       0.183     0.843     0.248       5499
exp_mayo3_ecdsa_p384               exp       1.132     1.236     0.961       4000
exp_snova2455_ecdsa_p384           exp       0.997     1.756     1.081       2291
exp_mqom2cat3_ecdsa_p384           exp       1.239     3.874     3.395       8159
--- NIST level 5 (256-bit): ML-DSA-87 vs experimental ---
mldsa87_ecdsa_p384                 std       0.925     1.713     0.818       7561
mldsa87_ecdsa_bp384                std       0.903     1.691     0.865       7560
mldsa87_ed448                      std       0.402     1.128     0.426       7532
mldsa87_rsa3072_pss                std     131.766     2.505     0.273       8143
mldsa87_rsa4096_pss                std     605.155     4.493     0.309       8399
mldsa87_ecdsa_p521                 std       1.845     2.688     1.565       7633
exp_falconpadded1024_ecdsa_p521    exp      16.522     2.333     1.674       3477
exp_mayo5_ecdsa_p521               exp       2.006     2.518     1.795       6922
exp_snova2965_ecdsa_p521           exp       1.972     3.065     1.875       3575
exp_mqom2cat5_ecdsa_p521           exp       2.506     7.990     7.103      14299
--- reference (single algorithm, default provider) ---
ML-DSA-44                          ref       0.084     0.483     0.099       3877
ML-DSA-65                          ref       0.147     0.861     0.152       5406
ML-DSA-87                          ref       0.209     0.967     0.235       7364
ED25519                            ref       0.027     0.029     0.088        215
```

## Deployment recommendations (standardized tier)

**Prefer ECDSA- or EdDSA-paired combos over RSA-paired ones.** At the same
security level the RSA halves cost **130–605 ms** to keygen (e.g.
`mldsa87_rsa4096_pss` ~605 ms) versus **< 2 ms** for every EC/Ed combo — a
100–1000× keygen penalty — while sign/verify and cert size are otherwise
comparable. Choose an RSA half only when policy or legacy-verifier compatibility
forces it; for fresh deployments the `*_ecdsa_*` / `*_ed25519` / `*_ed448`
combos are strictly better operationally.

**Verify is cheap everywhere.** All standardized composites verify in
**0.12–1.6 ms**, and the cost rides the classical curve (P-521 ~1.5 ms, P-256
~0.15 ms), not the ML-DSA half. Against network RTT this is noise, so let curve
choice follow the security level, not verify speed.

**The composite "tax" is small.** A composite cert is only ~130 bytes larger
than the pure ML-DSA cert of the same level, with negligible added sign/verify
time — the cost is in the primitives, not the EVP composition. Classical + PQ
defence-in-depth is therefore inexpensive insurance.

**Sensible default: `mldsa65_ecdsa_p384` (L3)** — 192-bit, ~5.6 KB cert, sub-ms
keygen, ~0.7 ms verify. Drop to `mldsa44_ecdsa_p256` / `mldsa44_ed25519` (L1,
~4 KB) only when size-constrained; go L5 only if the threat model demands it.

**Weight the metrics by role.** `keygen + sign` is per-issuance cost (matters
for a CA minting many / short-lived certs → avoid RSA halves there); `verify` is
per-use cost (sub-2 ms, rarely the bottleneck); `cert` size is per-connection
bandwidth and chain-depth budget (the metric most likely to bite in TLS).

## Informational (experimental families — not for deployment)

If certificate **size** is the binding constraint (constrained links, deep
chains, embedded), the experimental data shows what a future *standardized*
non-ML-DSA composite could offer: **SNOVA** (1.5 KB at L1, 3.6 KB at L5) and
**Falcon-padded** (1.8 / 3.5 KB) produce the smallest certs — roughly half an
ML-DSA composite. Worth tracking, not deploying.

Some families are poor fits for **certificates specifically**, regardless of
standardization status:

- **UOV** — 67 KB cert (huge public key). Disqualifying wherever the public key
  travels in-band (TLS chains).
- **MQOM2** — slowest sign + verify (up to ~8 ms / ~7 ms at L5) and 14 KB cert.
- **CROSS** — 13.5 KB cert.

These have legitimate uses elsewhere (e.g. UOV's tiny, fast signatures suit
sign-heavy scenarios where the public key is distributed out of band), but for
X.509 certificates they are the ones to avoid.
