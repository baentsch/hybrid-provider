# Composite KEM benchmark — results snapshot & deployment notes

This is an **illustrative snapshot** of `composite_kem_bench` (the KEM analogue of
`composite_sig_bench`; see the *Composite KEM benchmark* section of
[../TESTING.md](../TESTING.md) for what it measures and how to run it). Numbers are
hardware-, build- and run-specific — regenerate them in your own environment
before drawing conclusions; do **not** treat the values below as authoritative.

> ⚠️ **Interop scope.** Only the **standardized ML-KEM composite tier** has real
> LAMPS OIDs and can interoperate with other implementations. The
> **experimental** rows (FrodoKEM/BIKE/HQC) use non-normative labels and OIDs in
> the private `1.3.9999.99.*` arc and interoperate only with this provider — they
> are here for research (measuring what each PQ KEM family costs inside a composite
> for X.509/CMS use), not for deployment. The analysis below is a per-axis "what
> wins on which metric" comparison across *all* rows; deployability is a separate,
> factual constraint, not part of the ranking.

## How to reproduce

```sh
cd build
LD_LIBRARY_PATH=/path/to/openssl/lib OPENSSL_MODULES=. ./composite_kem_bench 2000
```

The experimental rows need [oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
on the module search path (it supplies the PQ *components* — the composite
combination itself is done by this provider); combos whose components are
unavailable are skipped.

## Snapshot

Measured on an **AMD Ryzen 7 5800U**, **OpenSSL 3.5.6**, PQ components from
oqsprovider, per-op budget `2000` ms. `keygen`/`encaps`/`decaps` are milliseconds
per operation; `pk` is the SubjectPublicKeyInfo DER length, `ct` the composite
ciphertext length, `sk` the PKCS8 private-key DER length. Rows are grouped by NIST
level (the standardized composite ML-KEM tier only exists at L3/L5 — the draft has
no ML-KEM-512, so L1 is experimental-only).

```
algorithm                      tier     keygen    encaps    decaps        pk      ct      sk
                                          (ms)      (ms)      (ms)   (bytes) (bytes) (bytes)
--- NIST level 1 (128-bit): experimental only ---
exp_frodo640aes_p256           exp       0.416     0.619     1.200      9699    9817   20029
exp_bikel1_p256                exp       0.376     0.315     1.435      1624    1638    5364
exp_hqc1_p256                  exp       1.155     2.242     4.656      2324    4498    2462
--- NIST level 3 (192-bit): ML-KEM-768 vs experimental ---
mlkem768_rsa2048               std      31.766     2.294     2.847      1475    1344    1278
mlkem768_rsa3072               std     165.066     2.343     3.905      1603    1472    1855
mlkem768_rsa4096               std     344.376     2.318     5.638      1731    1600    2437
mlkem768_x25519                std       0.056     0.072     0.085      1237    1120     115
mlkem768_p256                  std       0.045     0.084     0.109      1270    1153     206
mlkem768_p384                  std       0.672     1.304     0.710      1302    1185     252
mlkem768_bp256                 std       0.320     0.565     0.335      1270    1153     207
exp_frodo976aes_p384           exp       1.243     2.109     2.243     15747   15889   31483
exp_bikel3_p384                exp       1.360     1.584     3.501      3198    3212   10292
exp_hqc3_p384                  exp       3.716     7.327    12.999      4629    9075    4789
--- NIST level 5 (256-bit): ML-KEM-1024 vs experimental ---
mlkem1024_rsa3072              std     131.495     2.263     3.808      1987    1952    1854
mlkem1024_p384                 std       0.701     1.314     0.730      1686    1665     252
mlkem1024_bp384                std       0.703     1.307     0.724      1686    1665     256
mlkem1024_x448                 std       0.219     0.336     0.217      1645    1624     140
mlkem1024_p521                 std       1.616     3.097     1.629      1722    1701     310
exp_frodo1344aes_p521          exp       2.507     4.399     4.046     21671   21829   43331
exp_bikel5_p521                exp       3.208     3.563     8.129      5273    5287   16737
exp_hqc5_p521                  exp       9.293    18.332    32.242      7388   14554    7576
--- reference (single algorithm, default provider) ---
ML-KEM-768                     ref       0.030     0.017     0.025      1206    1088    2498
ML-KEM-1024                    ref       0.043     0.022     0.033      1590    1568    3266
```

## What wins on which axis

Unlike the composite-*signature* picture — where some experimental families (SNOVA,
Falcon-padded) beat ML-DSA on certificate size — the composite-**KEM** picture is
lopsided: the standardized **ML-KEM** composites win essentially every axis, and
the experimental FrodoKEM/BIKE/HQC families pay for their different security
assumptions with larger keys/ciphertexts and slower ops. Rankings cover **all**
rows; deployability is treated separately below.

**Ciphertext size** (per-*handshake* bytes — the metric that binds hardest for a
KEM, since the ciphertext travels on every key establishment). Smallest are the
ML-KEM EC/X combos: `mlkem768_x25519` (1120 B), `mlkem768_p256` (1153 B) at L3;
`mlkem1024_x448` (1624 B) at L5. No experimental combo beats ML-KEM here. The
smallest experimental is **BIKE-L1** (1638 B, on par with ML-KEM); the largest are
**FrodoKEM** (9.8 KB → 21.8 KB) and **HQC** (4.5 KB → 14.6 KB).

**Public-key size** (travels in the certificate / SPKI). Same shape: ML-KEM combos
1.2–1.7 KB; BIKE 1.6–5.3 KB; HQC 2.3–7.4 KB; **FrodoKEM the outlier at 9.7–21.7 KB**.

**Private-key size.** The composite ML-KEM combos store the PQ half as a seed, so
their private keys are *tiny* — 115–310 B — and smaller than the pure-ML-KEM
reference key (2.5–3.3 KB, expanded). The experimental combos serialize the raw PQ
private key, so they are much larger: HQC 2.5–7.6 KB, BIKE 5.4–16.7 KB, and
**FrodoKEM 20–43 KB** (disqualifying where private keys are stored at scale).

**Keygen.** Cheapest are the ML-KEM EC/X combos (sub-millisecond to ~1.6 ms) —
indistinguishable from pure ML-KEM. The outliers are the **RSA-OAEP** combos, whose
keygen explodes to 31–344 ms (RSA keygen dominates); the experimental combos are
mostly sub-4 ms (HQC-L5 the slowest at ~9 ms).

**Encaps / decaps.** ML-KEM EC/X combos are fastest (sub-millisecond up to ~3 ms);
RSA combos add the OAEP cost. The experimental families are slower, **HQC most so**
(decaps up to ~32 ms at L5), with **BIKE** also decaps-heavy (up to ~8 ms) — both
code-based schemes have costlier decoding than lattice ML-KEM.

**Composite overhead vs. pure ML-KEM.** A composite ML-KEM combo adds only a small
constant over the pure reference — the classical half plus one SHA3-256 combiner
pass — so `mlkem768_p256` vs pure `ML-KEM-768` is ~+65 B ciphertext and a fraction
of a millisecond. Classical + PQ defence-in-depth is inexpensive on every axis
except keygen, and there only for the RSA pairings.

## Deployability constraint (a fact, not a ranking)

Only the **standardized ML-KEM composite tier** carries real LAMPS OIDs, so today
it is the only tier that can be presented to a non-cooperating relying party. On
the metrics above it also happens to win, so — unlike the signature families —
there is no size/speed argument for the experimental KEMs in a certificate.

Their value is **cryptographic diversity**, not efficiency: FrodoKEM is
conservative (unstructured LWE), and BIKE/HQC are **code-based** rather than
lattice-based, so they hedge against a future break of structured lattices that
would affect ML-KEM. That hedge costs real bytes and cycles:

- **FrodoKEM** — largest public key (up to ~22 KB), ciphertext (~22 KB) and private
  key (~43 KB). The conservative choice, but heavy wherever the key or ciphertext
  travels in-band.
- **HQC** — largest ciphertext growth relative to public key and the slowest ops
  (encaps ~18 ms, decaps ~32 ms at L5).
- **BIKE** — the most compact of the three (ciphertext on par with ML-KEM at L1),
  but decaps-heavy and code-based decoding has historically needed care.

For X.509 / CMS composite KEMs the standardized ML-KEM tier is the one to deploy;
the experimental families are worth tracking as a **non-lattice fallback**, not as
a performance or size option.
