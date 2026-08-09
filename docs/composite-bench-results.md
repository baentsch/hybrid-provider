# Composite certificate benchmark — results snapshot & deployment notes

This is an **illustrative snapshot** of `composite_bench` (see the *Composite
certificate benchmark* section of [../TESTING.md](../TESTING.md) for what it
measures and how to run it). Numbers are hardware-, build- and run-specific —
regenerate them in your own environment before drawing conclusions; do **not**
treat the values below as authoritative.

> ⚠️ **Interop scope.** Only the **standardized ML-DSA composite tier** has real
> LAMPS OIDs and can interoperate with other implementations. The
> **experimental** rows use non-normative labels and OIDs in the private
> `1.3.9999.99.*` arc and interoperate only with this provider — they are here
> for research (measuring what each PQ family costs inside a certificate), not
> for deployment. The analysis below is a per-axis "what wins on which metric"
> comparison across *all* rows; where deployability matters it is called out as
> a separate, factual constraint rather than folded into the ranking.

## How to reproduce

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./composite_bench 2000
```

The experimental rows need [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
on the module search path (it supplies the PQ *components* — the composite
combination itself is done by this provider); combos whose components are
unavailable are skipped.

## Snapshot

Measured on an **AMD Ryzen 7 5800U**, **OpenSSL 3.5.6**, PQ components from
oqsprovider, per-op budget `2000` ms. `keygen`/`sign`/`verify` are milliseconds
per operation; `cert` is the DER length of a self-signed X.509 certificate; `sk`
is the DER length of the PKCS8 private key. Rows are grouped by NIST level so the
standardized ML-DSA composites sit side-by-side with the experimental OQS-family
composites at the same level.

```
algorithm                          tier     keygen      sign    verify      cert      sk
                                              (ms)      (ms)      (ms)   (bytes) (bytes)
--- NIST level 1 (128-bit): ML-DSA-44 vs experimental ---
mldsa44_rsa2048_pss                std      36.391     1.028     0.119      4400    1245
mldsa44_rsa2048_pkcs15             std      38.852     1.037     0.117      4400    1246
mldsa44_ed25519                    std       0.119     0.509     0.187      3970      83
mldsa44_ecdsa_p256                 std       0.103     0.529     0.157      4010     174
exp_falconpadded512_ecdsa_p256     exp       5.484     0.428     0.303      1833    1422
exp_mayo2_ecdsa_p256               exp       0.206     0.309     0.288      5367     163
exp_cross128bal_ecdsa_p256         exp       0.180     0.860     0.683     13494     171
exp_ovIspkc_ecdsa_p256             exp       0.973     0.297     0.380     66943  348847
exp_snova2454_ecdsa_p256           exp       0.237     0.687     0.426      1533     187
exp_mqom2cat1_ecdsa_p256           exp       0.303     1.078     0.907      3605     227
--- NIST level 3 (192-bit): ML-DSA-65 vs experimental ---
mldsa65_rsa3072_pss                std     118.167     2.452     0.198      6185    1822
mldsa65_rsa3072_pkcs15             std     167.490     2.484     0.197      6185    1824
mldsa65_rsa4096_pss                std     422.615     4.559     0.235      6441    2403
mldsa65_rsa4096_pkcs15             std     327.145     4.600     0.226      6441    2402
mldsa65_ecdsa_p256                 std       0.177     0.923     0.225      5538     174
mldsa65_ecdsa_p384                 std       0.843     1.562     0.763      5602     220
mldsa65_ecdsa_bp256                std       0.477     1.251     0.470      5539     175
mldsa65_ed25519                    std       0.189     0.931     0.260      5499      83
exp_mayo3_ecdsa_p384               exp       1.032     1.302     0.998      4000     217
exp_snova2455_ecdsa_p384           exp       1.063     1.804     1.089      2291     233
exp_mqom2cat3_ecdsa_p384           exp       1.235     3.881     3.542      8159     319
--- NIST level 5 (256-bit): ML-DSA-87 vs experimental ---
mldsa87_ecdsa_p384                 std       0.943     1.776     0.871      7561     220
mldsa87_ecdsa_bp384                std       0.948     1.682     0.902      7560     224
mldsa87_ed448                      std       0.425     1.160     0.454      7532     108
mldsa87_rsa3072_pss                std     120.872     2.632     0.292      8143    1821
mldsa87_rsa4096_pss                std     364.361     4.568     0.319      8399    2404
mldsa87_ecdsa_p521                 std       1.835     2.699     1.599      7633     277
exp_falconpadded1024_ecdsa_p521    exp      18.000     2.407     1.700      3477    2548
exp_mayo5_ecdsa_p521               exp       2.155     2.751     1.974      6922     283
exp_snova2965_ecdsa_p521           exp       2.138     3.340     2.039      3575     291
exp_mqom2cat5_ecdsa_p521           exp       2.704     8.546     7.677     14299     423
--- reference (single algorithm, default provider) ---
ML-DSA-44                          ref       0.093     0.536     0.107      3877    2626
ML-DSA-65                          ref       0.159     0.887     0.165      5406    4098
ML-DSA-87                          ref       0.223     1.035     0.257      7364    4962
ED25519                            ref       0.029     0.031     0.094       215      48
```

## What wins on which axis

There is no single best composite: each metric has a different winner, and the
right choice depends on which axis binds in your deployment. The rankings below
cover **all** rows (standardized and experimental); deployability is treated as
a separate constraint in the next section, not baked into the ranking.

**Certificate size** (per-connection bandwidth and chain-depth budget — usually
the metric most likely to bite in TLS). The smallest certs at every level come
from the experimental families: **SNOVA** (1.5 KB L1, 2.3 KB L3, 3.6 KB L5) and
**Falcon-padded** (1.8 KB L1, 3.5 KB L5) — roughly half the size of the smallest
standardized composite at the same level. Among the standardized (deployable)
rows the EdDSA pairings are smallest (`mldsa44_ed25519` 4.0 KB, `mldsa65_ed25519`
5.5 KB, `mldsa87_ed448` 7.5 KB). At the far end, **UOV** (67 KB) and **CROSS**
(13.5 KB) carry a large public key in-band and are the worst fit for certificates.

**Private-key size.** The composites store the PQ half as a 32-byte seed (see
`pq_priv_seed`), so most composite private keys are tiny — 83–423 bytes — and are
in fact *smaller* than the corresponding pure-ML-DSA reference key, which the
default provider serializes in expanded form (2.6–5.0 KB). The exceptions are the
families whose components have no seed encoding through the EVP path: RSA halves
(1.2–2.4 KB), Falcon-padded (1.4–2.5 KB), and **UOV**, whose ~349 KB private key
dwarfs everything else and rules it out where private keys are stored at scale.

**Keygen.** Cheapest are the EC/EdDSA-paired ML-DSA composites (0.1–0.2 ms at L1,
still < 2 ms at L5) — indistinguishable from the pure-ML-DSA references, because
the classical half is nearly free. The outliers are the **RSA** halves, whose
keygen explodes to 36–423 ms (a 100–1000× penalty over EC at the same level), and
**Falcon-padded**, which is the slowest experimental keygen (5.5 ms L1, 18 ms L5).

**Sign.** Fastest signers at L1 are the multivariate experimentals — **UOV**
(0.30 ms) and **MAYO** (0.31 ms) — ahead of every ML-DSA composite; at higher
levels the EdDSA pairings lead the standardized rows. The slowest signer by a
wide margin is **MQOM2** (up to 8.5 ms at L5).

**Verify.** Verify cost rides the *classical* curve, not the PQ half: fastest are
the RSA and small-curve EC combos (0.12–0.16 ms at L1), rising with curve size
(P-521 ≈ 1.6 ms). Against network RTT all standardized composites (0.12–1.6 ms)
are noise. The only genuinely slow verifier is **MQOM2** (7.7 ms at L5).

**Composite overhead vs. the pure PQ signature.** Comparing a composite to the
pure ML-DSA reference of the same level, the added cost of carrying a classical
half is small: the certificate grows by only ~130–500 bytes and sign/verify by a
fraction of a millisecond — the cost lives in the primitives, not in the EVP
composition. Classical + PQ defence-in-depth is therefore inexpensive on every
axis except keygen (and there only for the RSA pairings).

## Deployability constraint (a fact, not a ranking)

Only the **standardized ML-DSA composite tier** carries real LAMPS OIDs, so today
it is the only tier that can be presented to a non-cooperating relying party.
That does not make ML-DSA the winner on any performance axis above — on cert size
and (at L1) on sign speed the experimental families beat it — it only means the
experimental rows are, for now, research artifacts. Several of them (SNOVA,
Falcon-padded) are attractive enough on the size axis that they are worth
tracking as standardization candidates; if standardized they would be the ones to
prefer where certificate size binds. UOV, CROSS and MQOM2 remain poor fits for
certificates regardless of standardization status:

- **UOV** — 67 KB cert and ~349 KB private key (huge public/private key).
  Disqualifying wherever the public key travels in-band (TLS chains) or private
  keys are stored at scale, despite its very fast sign.
- **MQOM2** — slowest sign + verify (up to ~8.5 ms / ~7.7 ms at L5) and 14 KB
  cert at L5.
- **CROSS** — 13.5 KB cert at L1.

These families have legitimate uses elsewhere (e.g. UOV's tiny, fast signatures
suit sign-heavy scenarios where the public key is distributed out of band), but
for X.509 certificates they are the ones to avoid.
