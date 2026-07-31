# Hybrid + Composite Redesign

Status: **planning** (reconstructed 2026-07-31). This document is the canonical
plan; the memory notes under `.claude/.../memory/` mirror only its headline
decisions. Keep this file authoritative.

## Overarching goal

Interop is the entire point of this work, split by algorithm family:

- **Hybrid family → interop with oqsprovider.** Format- and OID-identical to the
  upstream oqs-provider **GitHub `main`** branch (open-quantum-safe/oqs-provider),
  NOT the locally installed `oqsprovider.so`. In-process (same OpenSSL libctx).
- **Composite family (LAMPS) → interop with external software like Bouncy
  Castle.** Out-of-process; validated via serialized DER/PEM artifacts + KAT
  vectors exchanged both directions.
- **No self-contained / private OID formats, ever.** Matching an existing peer's
  assigned OIDs (oqsprovider's, or the LAMPS drafts') is interop, not a
  violation of this rule.

## Architecture constraint (applies to both families)

The hybrid-provider is a **composition layer only**, using the public EVP API.
It must NEVER assume which provider supplies the PQ primitives (ML-KEM/ML-DSA and
the other OQS base algorithms):

- PQ primitives come via EVP from **either oqsprovider or OpenSSL's default
  provider**, seamlessly interchangeable (default provider supplies ML-KEM/ML-DSA
  on OpenSSL 3.5+; oqsprovider supplies those plus Frodo/BIKE/HQC/MAYO/… bases).
- **Classic crypto (ECDH/ECDSA/RSA/X25519/Ed25519) ALWAYS comes from OpenSSL's
  default provider** via EVP.
- A given hybrid/composite combination is constructible as long as *some* loaded
  provider offers the named base PQ primitive.

---

## Phase 1 — Hybrid, full oqsprovider parity (do first)

Implement the **entire** current oqsprovider `main` hybrid matrix — all hybrid
KEMs and all hybrid SIGs — matching oqsprovider's names, TLS code points, X.509
OIDs and wire formats exactly. **Endgame: oqsprovider deletes its own hybrid
logic and delegates to this provider.**

### Wire formats (from oqsprovider main @ 00fde33)

**Hybrid KEM** (`oqs_hyb_kem.c`):
- Ciphertext = concat(classical_ct, pq_ct); shared secret = concat(classical_ss,
  pq_ss).
- Order set by `reverse_share`: if the classical algorithm is NOT FIPS-approved
  but the PQ one is → **PQ share first**; otherwise **classical first**.
  (So X25519-based → PQ first; P-256/P-384-based → classical first.)
- Key material: classical component stored behind a **4-byte big-endian length
  prefix** (`SIZE_OF_UINT32`), then the PQ component (`oqsprov_keys.c`).
- EXCEPTION — the 3 IETF-standardized MLX KEMs use the **raw-concat** IETF
  format (no length prefix); these already work in today's provider:
  `X25519MLKEM768` (0x11ec), `SecP256r1MLKEM768` (0x11eb),
  `SecP384r1MLKEM1024` (0x11ED).

**Hybrid SIG** (`oqs_sig.c`):
- signature = `ENCODE_UINT32(classical_sig_len)` (4-byte BE) `|| classical_sig
  || pq_sig`.
- OIDs on the OQS `1.3.9999.*` arc (see table below).

### Phase-1 hybrid KEM inventory (oqsprovider main)

Default-provider MLX group (raw concat, no length prefix — already done in this
provider; interop peer is OpenSSL's **default** provider, NOT oqsprovider):
| name | code point | components |
|------|-----------|-----------|
| X25519MLKEM768 | 0x11ec | X25519 + ML-KEM-768 |
| SecP256r1MLKEM768 | 0x11eb | P-256 + ML-KEM-768 |
| SecP384r1MLKEM1024 | 0x11ED | P-384 + ML-KEM-1024 |
| X448MLKEM1024 | (none) | X448 + ML-KEM-1024 — KEM-API only, no TLS codepoint |

> `X448MLKEM1024` (ML-KEM-**1024**) exists only in OpenSSL's default provider
> (`defltprov.c`), has no `TLS_GROUP_ENTRY`, and is distinct from oqsprovider's
> `x448_mlkem768` (ML-KEM-**768**, length-prefixed, code point 0x2FB7) listed
> below. Do not conflate them.

OQS-legacy hybrids (4-byte length-prefixed key material; interop peer is
oqsprovider):
- ML-KEM: `p256_mlkem512` (0x2F4B), `x25519_mlkem512` (0x2FB6),
  `bp256_mlkem512` (65056), `p384_mlkem768` (0x2F4C), `x448_mlkem768` (0x2FB7),
  `bp384_mlkem768` (65057), `p521_mlkem1024` (0x2F4D), `bp512_mlkem1024` (65058)
- FrodoKEM: `p256_frodo640aes`, `x25519_frodo640aes`, `p384_frodo976aes`,
  `x448_frodo976aes`, `p521_frodo1344aes`, and the `*shake` variants; likewise
  `efrodo*` (65024–65039 range)
- BIKE: `p256_bikel1`, `x25519_bikel1`, `p384_bikel3`, `x448_bikel3`,
  `p521_bikel5`
- HQC: `p256_hqc1`, `x25519_hqc1`, `p384_hqc3`, `x448_hqc3`, `p521_hqc5`

Priority order within Phase 1: **ML-KEM hybrids first** (base available from
default OR oqsprovider), then Frodo/BIKE/HQC (base only from oqsprovider).

### Phase-1 hybrid SIG inventory (oqsprovider main)

| name | OID | code point |
|------|-----|-----------|
| p256_mldsa44 | 1.3.9999.7.5 | 0xff06 |
| rsa3072_mldsa44 | 1.3.9999.7.6 | 0xff07 |
| p384_mldsa65 | 1.3.9999.7.7 | 0xff08 |
| p521_mldsa87 | 1.3.9999.7.8 | 0xff09 |
| p256_falcon512 | 1.3.9999.3.12 | 0xfed8 |
| rsa3072_falcon512 | 1.3.9999.3.13 | 0xfed9 |
| p256_falconpadded512 | 1.3.9999.3.17 | 0xfedd |
| rsa3072_falconpadded512 | 1.3.9999.3.18 | 0xfede |
| p521_falcon1024 | 1.3.9999.3.15 | 0xfedb |
| p521_falconpadded1024 | 1.3.9999.3.20 | 0xfee0 |
| p256_mayo1/2, p384_mayo3, p521_mayo5 | 1.3.9999.8.* | 0xff36–0xff39 |
| p256_OV_* (pkc / pkc_skc enabled variants) | 1.3.9999.9.* | 0xff1a–0xff1f |
| p256/p384/p521_snova* | 1.3.9999.10.* | 0xff3b… |
| p256/p384/p521_mqom2* | 1.3.9999.11.* | 0xff64… |

Priority order within Phase 1: **ML-DSA hybrids first** (`p256_mldsa44`,
`rsa3072_mldsa44`, `p384_mldsa65`, `p521_mldsa87`), then the rest.

> Note: SLH-DSA has no hybrid combinations; the standalone `mldsa*`/`mlkem*`
> entries are NOT hybrids and are out of scope for this provider.

### Phase-1 code structure

Extend the existing `hybrid_*` files (no new family yet):
- `hybrid_prov.h` / info tables: add every hybrid combination with its OID, code
  point, component algorithm names, `reverse_share` flag, and format flag
  (raw-concat vs length-prefixed).
- `hybrid_keymgmt.c`, `hybrid_kem.c`, `hybrid_sig.c`: generalize to the full
  matrix; honor per-entry `reverse_share` and the length-prefix format.
- `hybrid_caps.c`: advertise all hybrid TLS groups / sig algs with correct code
  points.
- Encoders/decoders: emit/parse the oqsprovider key & signature serialization
  (length-prefixed classical component). Source of truth:
  `oqsprov/oqs_encode_key2any.c`, `oqs_decode_der2key.c`, `oqsprov_keys.c`.

### Phase-1 testing

In-process cross-provider round-trips vs oqsprovider `main`, both directions, for
every algorithm: keygen ↔ import, encaps/decaps shared-secret equality, sign in
one / verify in the other, and key-material byte-for-byte round-trip.

### Phase-1 implementation roadmap (sequenced)

Delta from today's code (as of this planning): only the 4 raw-concat
default-provider MLX KEMs exist; the 6 signature entries use a **non-oqsprovider**
wire format (`alg1‖alg2`, ECDSA zero-padded to max) and non-oqsprovider names
(incl. `ed25519/ed448` combos oqsprovider does not have); there are **no
encoders/decoders and no OID registration**. Ordering below is gated by
base-primitive availability and by the fact that nothing counts as done until it
round-trips against oqsprovider `main`.

**M0 — oqsprovider interop test rig (acceptance gate).** Build oqsprovider from
GitHub `main` for the test build (NOT the local /opt install). Add a dual-libctx
cross-provider test: this provider in one libctx, oqsprovider in the other. Per
algorithm: encaps/decaps shared-secret equality, sign-here/verify-there (and
reverse), and key-material byte-for-byte import/export. This gate blocks every
later milestone.

> **Reproducibility:** `test/setup_oqs_interop.sh` (re)builds the oqsprovider-main
> peer + liboqs-main into `.local`/`.interop` (both gitignored, never `/tmp`) and
> symlinks `oqsprovider.so` into `build/`. One command after any machine wipe.
>
> **Empirical finding (2026-07-31, oqsprovider main @ 00fde33 on OpenSSL 3.5.6):**
> under 3.5 oqsprovider exposes NONE of the standardized MLX KEM names
> (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` — ceded to the
> default provider). It exposes only its OQS-legacy hybrids: `p256_mlkem512`,
> `x25519_mlkem512`, `bp256_mlkem512`, `p384_mlkem768`, `x448_mlkem768`,
> `bp384_mlkem768`, `p521_mlkem1024`, `bp512_mlkem1024`, plus Frodo/BIKE/HQC.
> Consequence: there is **zero KEM-name overlap** with today's provider, so the
> first real cross-provider assertion requires implementing one OQS-legacy hybrid
> (M3) — e.g. `p384_mlkem768` or `x25519_mlkem512`. M0 therefore delivers the rig;
> the first green cross-test lands with M3.

**M1 — Metadata & wire-format generalization (refactor, no new algs).** Extend
`HYBRID_KEM_INFO`/`HYBRID_SIG_INFO` with: `format` (`RAW_CONCAT_MLX` vs
`OQS_LENPREFIX`), `reverse_share`, TLS code point, OID string, oqs canonical
name, and component EVP names resolvable from **either** provider (map e.g.
`ML-KEM-768` ↔ `mlkem768`). Implement the OQS length-prefixed key-material
serialization (`SIZE_OF_UINT32` classical prefix) and the `ENCODE_UINT32` sig
format alongside the existing raw-concat paths.

> **M1 empirical finding (probe `test/probe_oqs_hybrid.c` vs oqsprovider main,
> OpenSSL 3.5.6).** For OQS-legacy ML-KEM hybrids, oqsprovider's byte layout is:
> - `ENCODED_PUBLIC_KEY` (TLS key share) = **raw concat**, no prefix.
> - encapsulation ciphertext = **raw concat** (classical ephemeral pub ‖ ML-KEM ct).
> - shared secret = **raw concat** (classical ss ‖ ML-KEM ss).
> - `PUB_KEY` param = raw concat **+ 4-byte length prefix** on the classical part.
> - `PRIV_KEY` param = 4-byte-prefixed; **EC** classical component stored
>   **DER-encoded** (X25519/X448 stored raw scalar).
> - component order = oqsprovider `reverse_share`: classical-not-FIPS & PQ-FIPS →
>   PQ first (`x25519_*`, `x448_*` → alg2 slot 0); else classical first
>   (`p256_*`, `p384_*` → alg2 slot 1). Same pattern the MLX table already uses.
>
> Consequence: the KEM **runtime** path (encaps/decaps + `ENCODED_PUBLIC_KEY`) is
> already raw-concat-compatible in `hybrid_kem.c`. The 4-byte prefix / EC-DER form
> appears ONLY in the `PUB_KEY`/`PRIV_KEY` param serialization → deferred to M2
> (encoders/decoders). So M3's first cross-provider KEM interop reduces to adding
> table entries (sizes + slot) and exchanging keys via `ENCODED_PUBLIC_KEY`.

**M2 — Encoders & decoders (currently missing subsystem).** New
`hybrid_encoder.c` / `hybrid_decoder.c`: DER + PEM + text for
`PrivateKeyInfo`/`SubjectPublicKeyInfo` keyed by the OQS OIDs, matching
`oqs_encode_key2any.c` / `oqs_decode_der2key.c`. Register OIDs to match
oqsprovider. Gate: `openssl pkey`/`x509` round-trips a key produced by
oqsprovider and vice versa.

**M3 — ML-KEM legacy hybrid KEMs** (base primitive available from default OR
oqsprovider): `p256_mlkem512`, `x25519_mlkem512`, `p384_mlkem768`,
`x448_mlkem768`, `p521_mlkem1024`, then brainpool `bp256/bp384/bp512` variants.
Uses `reverse_share` + length-prefixed format + OQS code points.

> **DONE (2026-07-31).** All eight ML-KEM legacy hybrids implemented via the new
> `HYBRID_KEM_LIST` X-macro (one row each; generates info table + keymgmt thunks +
> registration). `alg2_slot = 1 - reverse_share` from oqsprovider's nid table.
> Bidirectional cross-provider interop vs oqsprovider main passes 16/16
> (`test/hybrid_oqs_test.c`, wired into ctest). The runtime path needed no new
> wire-format code (raw concat already matched). NOT yet done: full key-material
> byte-for-byte round-trip via the prefixed `PUB_KEY`/`PRIV_KEY` param + key-file
> (SPKI/PKCS8) interop — that is the M2 encoder/decoder work. TLS-group
> capability advertisement for these code points also still pending (M7).

**M4 — ML-DSA legacy hybrid sigs, realigned to oqsprovider.** Switch to oqs
names/format/OIDs: `p256_mldsa44` (1.3.9999.7.5), `rsa3072_mldsa44` (.6),
`p384_mldsa65` (.7), `p521_mldsa87` (.8); add RSA-3072 classical support.
**Decided: DROP today's `ed25519mldsa*` / `ed448mldsa87` / hyphen-less
signature entries entirely** — they are not oqsprovider algorithms and only add
non-interop surface. Implement only oqsprovider's exact sig set/names/format/OIDs.

**M5 — Remaining oqs hybrid sigs** (base only from oqsprovider): Falcon,
FalconPadded, MAYO, OV (pkc/pkc_skc variants), SNOVA, MQOM.

**M6 — Remaining oqs hybrid KEMs** (base only from oqsprovider): FrodoKEM, BIKE,
HQC.

> **DONE (2026-07-31).** Enabled by **runtime component-size discovery**
> (`hybrid_kem_ensure_sizes`): sizes are queried from the component algorithms at
> key setup (throwaway keygen; EC private width from field bits since EC exposes
> PRIV_KEY as a BIGNUM), so the algorithm table carries NO size constants — adding
> a hybrid is just `(name, classical, group, PQ-base, slot)`. All 10 Frodo, 5
> BIKE and 5 HQC hybrids added as rows. Cross-provider interop now covers **all 28
> oqs hybrid KEMs bidirectionally: 56/56** (`test/hybrid_oqs_test.c`). Provider
> advertises 32 hybrid KEMs total. Full ctest suite green.

**M7 — Drop-in compatibility polish.** `OQS_CODEPOINT_*` / `OQS_OID_*` env-var
overrides, full TLS-GROUP + TLS-SIGALG capability advertisement, and per-algorithm
enable/disable parity with oqsprovider defaults.

**M8 — Replacement validation & upstreaming.** Run oqsprovider's own test suite +
TLS interop with hybrid-provider substituted for its hybrid code; then prepare the
oqsprovider PR that removes its hybrid logic and delegates to this provider.

Decisions: (a) use oqsprovider canonical names as the primary registered names
(required for true drop-in); (b) DROP the current non-oqs signature combos
(decided 2026-07-31).

---

## Phase 2 — Composite (LAMPS), later

Separate **`composite_*`** family alongside `hybrid_*` (no shared combiner
abstraction — duplication accepted for clarity). Full LAMPS matrix:

- Composite ML-DSA — draft-ietf-lamps-pq-composite-**sigs**
- Composite ML-KEM — draft-ietf-lamps-pq-composite-**kem**

Distinct from hybrid: **single assigned OID per combination**,
**SEQUENCE-of-components** serialization (not byte-concat), and a
**domain-separated combiner** with a fixed per-OID label for signatures.

### Phase-2 files (proposed)
```
composite_prov.h        composite OID/info tables, COMPOSITE_KEY
composite_keymgmt.c     key management
composite_kem.c         encaps/decaps
composite_sig.c         sign/verify with domain separator
composite_encoder.c     DER + PEM + text: key, SPKI, signature
composite_decoder.c     DER + PEM decode by composite OID
```

### Phase-2 interop / testing
- Peer: external software like **Bouncy Castle** (Java, out-of-process).
- Method: emit DER/PEM composite key + signature → BC verifies; BC emits → we
  decode + verify. Both directions. Plus KAT vectors from the drafts/oqsprovider.
- PQ primitives via EVP from {oqsprovider | default}; classic from default only.

### Phase-2 open items
- [ ] Exact composite matrix + OIDs from oqsprovider `main` (LAMPS combos) — not
  yet enumerated.
- [ ] Which LAMPS draft revision Bouncy Castle currently tracks (affects the sig
  combiner + OIDs).
- [ ] Internal order — assumption: composite sig before composite KEM, encoders
  alongside each.

---

## Reference source (oqsprovider main @ 00fde33)

- `ALGORITHMS.md` — code points + OIDs tables.
- `oqs-template/generate.yml` — master algorithm matrix.
- `oqsprov/oqs_hyb_kem.c` — hybrid KEM concat + `reverse_share` order.
- `oqsprov/oqs_sig.c` — hybrid sig length-prefixed serialization.
- `oqsprov/oqsprov_keys.c` — hybrid key material length-prefix layout.
- `oqsprov/oqs_encode_key2any.c`, `oqs_decode_der2key.c` — key file encode/decode.
