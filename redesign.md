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

**Follow-up (open):** separate-process cross-provider TLS for the Frodo/BIKE/HQC
hybrids. The in-process dual-libctx `hybrid_tls_test` can't cover them — the
hybrid side must load oqsprovider to source their PQ base, and then both providers
advertise the same group name/code point in one libctx, so the TLS keyshare keygen
can't be steered to the hybrid implementation (see the note near the end of
`test/hybrid_tls_test.c`). `test/hybrid_scenarios.sh` already drives real
`s_server`/`s_client` runs and is the natural home for this; extend it to negotiate
these groups hybrid-vs-oqsprovider across two processes. Tracked in **issue #2**
(raised in PR #1 review).

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

**M2 — Encoders & decoders (the key-file serialization subsystem, absent in the
original provider).** New
`hybrid_encoder.c` / `hybrid_decoder.c`: DER + PEM + text for
`PrivateKeyInfo`/`SubjectPublicKeyInfo` keyed by the OQS OIDs, matching
`oqs_encode_key2any.c` / `oqs_decode_der2key.c`. Register OIDs to match
oqsprovider. Gate: `openssl pkey`/`x509` round-trips a key produced by
oqsprovider and vice versa.

> **oqsprovider byte format (from `oqsprov_keys.c` / `oqs_encode_key2any.c`):**
> - **SPKI** = `AlgorithmIdentifier(OID)` + `BIT STRING(pubblob)` where
>   `pubblob = ENCODE_UINT32(classical_pub_len) ‖ classical_pub ‖ pq_pub`
>   (order reversed to `‖ pq_pub ‖ classical_pub` for the reverse-share KEMs,
>   i.e. our `alg2_slot == 0`). The UINT32 always encodes the CLASSICAL length;
>   classical_pub is the raw EC point / X25519 key.
> - **PKCS8** = `AlgorithmIdentifier(OID)` + `OCTET STRING(i2d(OCTET STRING(privblob)))`
>   (inner-octet-string wrapped) where `privblob = ENCODE_UINT32(classical_der_len)
>   ‖ classical_privkey_DER ‖ pq_privkey_raw` — the CLASSICAL private key is
>   DER-encoded (variable length), the PQ private key raw. (Some cases append the
>   PQ public key after.)
> - OIDs: sigs on `1.3.9999.*` (already in `HYBRID_SIG_INFO`); KEM hybrids need
>   their OIDs added too. Orthogonal KEM vs SIG encode/decode paths per the user.
> - **Slice order:** SPKI public-key DER first (proves SPKI + sig wire format via
>   "oqsprovider verifies our signature from our SPKI"), then PKCS8 private, then
>   PEM/text, then KEM OIDs.
>
> **SPKI public-key encoder DONE (2026-07-31).** `hybrid_encoder.c`: DER + PEM
> SubjectPublicKeyInfo, one encoder pair per signature algorithm, emitting the
> oqs pub blob (UINT32 classical-len prefix + ordered component pubkeys) with the
> algorithm's OID. Avoids the core-BIO method by rendering to a memory BIO and
> pushing bytes via a captured `BIO_write_ex` up-call. `hybrid_encode_test`:
> hybrid signs + emits SPKI, oqsprovider decodes it and verifies our signature.
>
> **SPKI public-key DECODER DONE (2026-07-31).** `hybrid_decoder.c`: DER
> SubjectPublicKeyInfo -> hybrid key. Reads the core BIO via a captured
> `BIO_read_ex` up-call, parses the X509_PUBKEY, matches the AlgId OID against the
> sig table, rebuilds the key from the blob (UINT32 prefix), and hands it back as
> an object reference; added `OSSL_FUNC_KEYMGMT_LOAD` so the reference
> materializes. `hybrid_encode_test` now tests **both directions, 32/32**:
> hybrid-SPKI+sig verified by oqs, AND oqs-SPKI+sig verified by hybrid.
>
> **PKCS8 private-key encode+decode DONE (2026-07-31).** DER + PEM PrivateKeyInfo;
> blob = `UINT32(classical_der_len) || i2d_PrivateKey(classical) || pq_privkey ||
> pq_pubkey` in an inner OCTET STRING (matches oqsprovider's default pubkey-append);
> decode d2i's the classical and loads the PQ raw. Full private-key round-trip vs
> oqsprovider both directions (`hybrid_encode_test` now **64/64**: SPKI both ways +
> PKCS8 both ways). Suite 6/6 green.
>
> **RSA classical DONE (2026-07-31).** Classical public key is the octet param
> (EC point / X25519) with an `i2d_PublicKey` fallback for RSA (RSAPublicKey DER,
> matching oqsprovider); decode uses `d2i_PublicKey` for RSA. All 19 sig algs
> (EC + RSA) round-trip SPKI + PKCS8 both ways — `hybrid_encode_test` **76/76**.
>
> **KEM key files DONE (2026-08-01), gated by `HYBRID_KEM_ENCODERS`.** Mirrors
> oqsprovider's off-by-default `OQS_KEM_ENCODERS`. The encode/decode code is
> orthogonal-by-reuse: the SAME generic SPKI/PKCS8 path serves KEM and SIG, keyed
> off `HYBRID_KEM_INFO.oid` (a uniform new column, NULL where oqsprovider leaves
> it NULL — most hybrid KEMs); the KEM-specific bits are handled generically, not
> per-algorithm: reverse-share ordering via `alg2_slot`, and raw-vs-DER classical
> via try-`get_raw_private_key`-then-`i2d` (X25519/X448 raw, EC/RSA DER), matching
> oqsprovider's `raw_key_support`. Private blob is
> `UINT32(classical_len) || [pq_priv|classical (reverse) | classical|pq_priv] ||
> pq_pub` (pq_pub always trailing; verified against real oqsprovider bytes).
> Only `p256_mlkem512`, `x25519_mlkem512` (and `SecP384r1MLKEM1024` on
> OpenSSL < 3.5) have OIDs and thus interop; the MLX KEMs are default-provider TLS
> groups with **no** key-file encoders on either side (not serializable anywhere),
> so NULL OID is correct, not self-contained. `hybrid_kem_encode_test` round-trips
> SPKI + PKCS8 both ways vs oqsprovider (8/8; exercises both orderings and raw
> classical), self-skipping per-alg when oqsprovider doesn't provide it (e.g.
> SecP384r1MLKEM1024 ceded on 3.5). **M2 complete.** Only optional leftover: a
> `text` encoder (human-readable dump; no interop role).

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

> **DONE (2026-07-31).** Old non-oqs sigs dropped. The 4 ML-DSA hybrids
> (`p256_mldsa44`, `rsa3072_mldsa44`, `p384_mldsa65`, `p521_mldsa87`) generated
> from a `HYBRID_SIG_LIST` X-macro (like the KEMs), with runtime size discovery
> extended to sigs and RSA-3072 keygen support. `hybrid_sig.c` rewritten to the
> oqsprovider wire format: `ENCODE_UINT32(classical_len) || classical_sig ||
> pq_sig`, classical = `EVP_PKEY_sign` over a SHA-256/384/512 digest chosen by PQ
> NIST level (ECDSA DER / RSA PKCS#1 v1.5), PQ signs the raw message. Self-
> consistency + wrong-message pass (`hybrid_test`, 36/36); full ctest green. OIDs
> recorded in the table for M2. NOTE: cross-provider sig interop (sign-here /
> verify-in-oqsprovider) needs key import → deferred to M2 (encode/decode); the
> format matches oqsprovider by construction (from `oqs_sig.c`).

**M5 — Remaining oqs hybrid sigs** (base only from oqsprovider): Falcon,
FalconPadded, MAYO, OV (pkc/pkc_skc variants), SNOVA, MQOM.

> **Falcon/FalconPadded/MAYO DONE (2026-07-31).** 10 rows added to
> `HYBRID_SIG_LIST` (p256/rsa3072/p521 Falcon + Falcon-padded, p256/p384/p521
> MAYO-1/2/3/5) with their oqs OIDs and NIST levels (Falcon-512/padded-512 &
> MAYO-1/2 = L1; MAYO-3 = L3; Falcon-1024/padded-1024 & MAYO-5 = L5). Provider
> advertises 14 hybrid sigs. Self-consistency (sign/verify + tamper-reject) with
> the PQ base sourced from oqsprovider passes in `hybrid_oqs_test`.
>
> **OV / SNOVA / MQOM DONE (2026-07-31).** 12 more rows: p256 OV-Is/Ip-pkc(+skc)
> (L1); SNOVA p256_2454/2454esk/37172 (L1), p384_2455 (L3), p521_2965 (L5); MQOM2
> p256_cat1/p384_cat3/p521_cat5 gf16-fast-r5 (L1/3/5). NIST levels taken
> authoritatively from liboqs `claimed_nist_level` (a small probe over
> OQS_SIG_alg_identifier), OIDs/base-names from oqsprovider. **All oqs hybrid sig
> families now implemented: 26 hybrid sigs; sign/verify self-consistency 22/22 in
> `hybrid_oqs_test` (suite 78/78).** Cross-provider sig verification still needs
> M2 (encode/decode).

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

> **KEM TLS-GROUP part DONE (2026-07-31).** `hybrid_caps.c` now generates the
> TLS-group table from the master list (code point + secbits per row; code
> point 0 = KEM-API-only, skipped). Provider advertises 31 hybrid TLS groups.
> In-process TLS 1.3 handshake interop (`hybrid_tls_test.c`, 28/28) covers:
> MLX groups vs the **default** provider, and the 8 OQS-legacy **ML-KEM** groups
> vs **oqsprovider**, both directions, with matching negotiated group + exported
> keying material.
>
> **Frodo/BIKE/HQC over TLS — DONE via a private component context.** Their PQ
> base exists only in oqsprovider; loading oqsprovider into the *application*
> context would collide on group names (both providers advertise the same
> group+code point, and an optional `?provider=hybrid` query loses to
> oqsprovider; a mandatory `provider=hybrid` query wins the group but then also
> hits cert/signature fetches the default provider must serve). Fix: the
> **`component-providers` config key** makes the hybrid provider load its
> component providers (`default oqsprovider`) into its OWN libctx and source all
> sub-algorithms from there. The application context then holds only
> `default + hybrid` — no collision — so these groups resolve to hybrid with a
> plain query and handshake against pure oqsprovider. `hybrid_compctx_test.c`:
> Frodo/BIKE-L3/L5/HQC, both directions, 24/24. (BIKE-L1 groups aren't negotiated
> by the oqsprovider peer over TLS in this build — its own client/server reject
> them — so they're KEM-level-only; not a hybrid-provider limitation.)
>
> Still pending for full M7: `OQS_CODEPOINT_*`/`OQS_OID_*` env overrides and
> TLS-SIGALG advertisement (post M4/M5) — the latter tracked in **issue #5**.

**M8 — Replacement validation & upstreaming.** (tracked in **issue #3**) Run
oqsprovider's own test suite +
TLS interop with hybrid-provider substituted for its hybrid code; then prepare the
oqsprovider PR that removes its hybrid logic and delegates to this provider.

Decisions: (a) use oqsprovider canonical names as the primary registered names
(required for true drop-in); (b) DROP the current non-oqs signature combos
(decided 2026-07-31).

> **Hybrid-logic removal is performance-neutral — it needs no further work to
> avoid a regression.** On OpenSSL ≥ 3.5 oqsprovider's *own native* hybrid
> signatures are already ~1.9× slower than on 3.4 (measured: native
> `p256_falcon512` ~0.38 ms/op in a real oqsprovider-only deployment on main),
> because oqsprovider sets `*no_cache = 1` for the whole provider once its ≥3.5
> algorithm filter turns on (see Performance effect 2). Delegating the same hybrid
> to this provider composes the standalone components via EVP and reproduces the
> **same** ~0.38 ms/op — no *new* regression. So M8 introduces no perf
> prerequisite: the fast-sig cost pre-exists equally in the current native code
> and the delegated path.
>
> The `no_cache` behaviour itself is a **separate, pre-existing oqsprovider
> performance bug** (blanket `no_cache=1` from a static algorithm filter; see
> `docs/oqsprovider-no-cache-issue.md`). Fixing it speeds up *both* the current
> native hybrids and any future delegated path equally — tracked for a later
> oqsprovider code review, not a blocker for M8.

#### M8 test-coverage gap analysis (keep the hybrid slice alive)

When oqsprovider deletes its hybrid combinations, the *hybrid rows* drop out of
its test suite; the **pure-PQ** rows stay (its tests iterate the provider's own
algorithm list, so post-removal they simply cover fewer algorithms). Our job is
therefore **not** to mirror oqsprovider's test files wholesale, but to guarantee
this project's suite is a **superset of the hybrid-slice behavioural coverage**.
Three principles bound the work:

1. **Scope to hybrids only.** Pure-PQ (ML-KEM/ML-DSA/Falcon/MAYO/SLH-DSA…) stays
   in oqsprovider and is not ours to test.
2. **The pinned pre-M8 oqsprovider is the oracle.** Cross-version interop
   (this provider ↔ oqsprovider `main @ 00fde33`, both directions, full hybrid
   matrix) is a stronger drop-in proof than re-running oqsprovider's self-tests,
   because that peer has those tests' expectations baked into its implementation.
3. **Assert wire-compat, not oqsprovider internals.** Do not lock in oqsprovider
   private constants (esp. the OQS KEM OID arc — kept behind `HYBRID_KEM_ENCODERS`
   exactly as oqsprovider gates `OQS_KEM_ENCODERS`; see the "no private OID
   formats" principle).

Mapping of oqsprovider's e2e tests (hybrid slice) to our coverage:

| oqsprovider test | hybrid slice | our equivalent | status |
| --- | --- | --- | --- |
| `oqs_test_kems` | hybrid encaps/decaps | `hybrid_test`, `hybrid_oqs_test` | ✅ |
| `oqs_test_groups` | hybrid TLS handshake | `hybrid_tls_test`, `hybrid_compctx_test`, `hybrid_scenarios.sh tls*` | ✅ |
| `oqs_test_signatures` | hybrid sign/verify | `hybrid_test` sig path | ✅ |
| `oqs_test_tlssig` | hybrid sig cert auth in TLS | `hybrid_cert_tls_test` | ✅ |
| `oqs_test_endecode` | hybrid key-file round-trip | `hybrid_encode_test`, `hybrid_kem_encode_test` (gated) | ~ partial (KEM endecode gated by design) |
| `oqs_test_evp_pkey_params` | hybrid key param get/set | `hybrid_param_test` (+ incidental in `hybrid_test`) | ✅ |
| `oqs_test_alg_overlap` | provider coexistence / no clash | `hybrid_coexist_test` | ✅ |
| `scripts/*cmssign/*cmsverify` | hybrid sig in CMS | `hybrid_cms_test` | ✅ |
| `scripts/test_tls_full.py` | external s_client/s_server matrix | `hybrid_scenarios.sh tls`/`tls-compctx`, `hybrid_matrix_test` | ✅ |

Gaps closed as part of M8 (each a provider-agnostic, EVP-only test, driven off
the master tables so nothing is silently omitted):

- [x] **Coexistence test** (`hybrid_coexist_test`) — the analog of
      `oqs_test_alg_overlap`, with the *inverse* assertion: we deliberately
      re-advertise default's MLX group names (and every OQS-legacy hybrid name)
      for drop-in, so the test proves "hybrid + default (+ oqsprovider) coexist
      and every hybrid algorithm resolves to the intended provider." Fetch-only,
      so it covers the whole inventory without a PQ base. The contract holds only
      under a **mandatory** `provider=…` propquery: an optional `?provider=…`
      clause is merely a scoring hint and falls back to another provider, so the
      test uses the mandatory form.
- [x] **CMS sign/verify** (`hybrid_cms_test`) — self-signed hybrid cert →
      `CMS_sign`/`CMS_verify` SignedData round-trip (+ tamper-reject), driven off
      the master signature table: the standardized (ML-DSA) hybrids run against
      the default provider, the non-standardized PQ signatures need oqsprovider
      and are skipped without it. This surfaced and fixed a real provider gap:
      CMS drives the *streaming* `EVP_DigestSignUpdate` path, which hybrid sigs
      (one-shot) do not implement. The keymgmt now advertises an empty
      `OSSL_PKEY_PARAM_MANDATORY_DIGEST` (`""` → `"UNDEF"`), the documented
      provider-keymgmt convention (as ML-DSA/EdDSA do) that makes CMS's
      `cms_signature_nomd()` select the one-shot `EVP_DigestSign` path instead.
      (The CMS propquery is left NULL so the generic message digest still
      resolves from the default provider.)
- [x] **Deeper `EVP_PKEY` param round-trip** (`hybrid_param_test`) — descriptor
      params (bits/security-bits/max-size) plus `EVP_PKEY_todata`→`fromdata`→`eq`
      on the raw `PUB_KEY` param, and for sigs a sign/verify through the
      reimported public key. This surfaced and fixed a second gap: RSA classical
      components expose no raw `PUB_KEY` octet, so the raw-param public path now
      falls back to `i2d_PublicKey`/`d2i_PublicKey` (constant-length for a fixed
      modulus), symmetric with the decoder's existing RSA handling. (RSA
      *private* raw-param stays deferred: its DER length varies, so it belongs to
      the length-prefixed DER encoder path, not the fixed-offset octet form.)
- [x] **Full-matrix cross-version interop sweep** (`hybrid_matrix_test`) — the
      pinned oqsprovider interop extended to the *entire* hybrid KEM + SIG
      inventory (driven off the master tables), both directions. Each KEM is
      crossed against whichever second peer implements the name: oqsprovider for
      the non-standardized hybrids, the default provider for the standardized MLX
      groups (which oqsprovider lacks). Signatures cross only against oqsprovider
      (the default provider has no hybrid signatures), so the sweep is skipped
      wholesale when oqsprovider is absent (issue #3, work item 2).

Explicitly **excluded** (not ours / conflicts with principles): pure-PQ tests;
any test depending on the OQS private KEM OID arc beyond the gated encoders.

---

## Performance (measured 2026-07-31, OpenSSL 3.5.6 + oqsprovider main)

The provider is a **near-zero-cost EVP composition layer**: its own glue adds ~0,
but a hybrid is only ever as fast as each component's *EVP path* — which for fast
PQ signatures is slower than a provider's internal direct call.

- **Our composition glue ≈ 0.** The hybrid provider's sign time equals a
  hand-written inline composite doing the identical EVP calls (no provider
  boundary): ML-DSA 0.504 vs 0.494 ms; Falcon 0.382 vs 0.384 ms. The provider
  double-dispatch is negligible on both a slow and a fast PQ primitive.
- **KEM encaps/decaps: parity** with default and oqsprovider (ML-KEM's default
  portable-C impl is fast — no rejection sampling).
- **Keygen: faster than oqsprovider** (e.g. `p256_mlkem512` 0.09 vs 0.94 ms;
  `p256_mldsa44` 0.21 vs 2.83 ms); ~2× the native MLX keygen for the tiny
  hybrid KEMs (two EVP keygens vs one integrated impl), but sub-0.2 ms absolute.
- **Sign/verify: two distinct effects, both outside our code.**
  1. *Wrong-implementation trap (ML-DSA rows).* Under 3.5 the default provider
     supplies `MLDSA44/65/87` (and standalone ML-KEM) in **portable C** —
     oqsprovider *cedes* them — so `?provider=oqsprovider` for the PQ part
     silently resolves to portable C (~0.48 ms/ML-DSA-44-sign) while native
     oqsprovider calls liboqs ML-DSA (AVX2, ~0.07 ms). Not apples-to-apples.
  2. *oqsprovider `no_cache` policy on OpenSSL ≥ 3.5 (Falcon/MAYO/SNOVA rows).*
     Here both sides use the **same liboqs** primitive, and the fast-sig tax is
     **oqsprovider's, not OpenSSL's and not our composition.** Root cause:
     `do_sigver_init` fetches the key's keymgmt from its provider on every
     `EVP_DigestSignInit` (`evp_keymgmt_fetch_from_prov`); OpenSSL caches that
     method **unless the provider sets `*no_cache = 1`** in its
     `query_operation`. oqsprovider does exactly that — on **OpenSSL ≥ 3.5.0** it
     sets `rt_algo_filter_enabled = 1` (to runtime-hide ML-DSA/SLH-DSA now
     provided natively) and returns `*no_cache = rt_algo_filter_enabled` for the
     **whole provider**, so *no* method is cached and every sign reconstructs the
     full method table (`ossl_method_construct`, O(provider algorithm count)). On
     3.4 the filter is off → `no_cache = 0` → cached → fast. Proven independent of
     oqs/OpenSSL-version by a ~200-algorithm stub provider toggling only the flag
     (same binary): `no_cache=0` ≈ 0.0008 ms/op vs `no_cache=1` ≈ 0.5 ms/op on
     **both** 3.4 and main — OpenSSL's behaviour is identical across versions; only
     oqsprovider's flag flips. The disabled-algorithm list is static after init, so
     the query result is deterministic and there is no reason to disable caching —
     **an oqsprovider bug, fixable there** (`oqsprov/oqsprov.c`
     `oqsprovider_query`). (Secondary: OpenSSL reconstructing *all* of a provider's
     algorithms to fetch *one* under `no_cache` is arguably wasteful — an optional
     upstream enhancement, not the cause.)

**Not worth doing:** per-key caching of the component fetch/context. The libctx
method store already caches implicit fetches (reuse-ctx == init-every-op, exactly:
Falcon 0.354 == 0.354). Reusing a pre-fetched `EVP_SIGNATURE` + pkey-ctx recovers
only ~14% (0.363 → 0.306) and still can't skip the sub-provider's per-init key
load — not worth the added thread-safety complexity.

**The performance lever is primitive sourcing.** `pq-propquery` /
`classic-propquery` steer each component to the fastest provider exposing the
standalone EVP algorithm; the hybrid then inherits that path's speed with no code
change. **On M8:** delegating oqsprovider's hybrid logic here is **perf-neutral** —
oqsprovider's own native hybrids already pay the ≥3.5 `no_cache` cost (effect 2), so
the delegated path reproduces the same number, no new regression. Fixing that
`no_cache` bug in oqsprovider (separate, pre-existing) speeds up both equally.
`test/hybrid_bench.c` runs the comparison; note only the Falcon/MAYO/SNOVA rows are
apples-to-apples (the ML-DSA rows compare portable-C vs AVX2, per effect 1 above).

**UNFAIR is a 3.5+ artifact — under OpenSSL 3.4 the tags flip to FAIR.** Effect 1
exists only because 3.5's default provider added ML-KEM/ML-DSA, which oqsprovider
then cedes. On 3.4 the default provider has no PQ primitives to cede, so
oqsprovider registers them all standalone; `?provider=oqsprovider` always reaches
liboqs, matching native, so every OQS-legacy KEM and SIG row is FAIR. `hybrid_bench`
decides the tag at runtime (`pq_from_oqs_{kem,sig}` probes), so this flips
automatically with no code change. Caveat: the MLX-vs-default rows can't run on
3.4 at all (default lacks MLX/standalone ML-KEM pre-3.5) — they SKIP rather than
becoming meaningful. A useful side effect: on 3.4 the ML-DSA rows become a genuine
FAIR comparison and show **parity** (hybrid == native), since on 3.4 oqsprovider's
algorithm filter is off (`no_cache=0`), so effect 2 does not occur — confirming both
that our composition is free and that the
fast-sig tax is purely oqsprovider's ≥3.5 `no_cache` policy, not OpenSSL or us.

---

## Phase 2 — Composite (LAMPS), later

*Tracked as epic **issue #6** (deferred until the LAMPS drafts / BC interop target
are pinned).*

Separate **`composite_*`** family alongside `hybrid_*` (no shared combiner
abstraction — duplication accepted for clarity). Full LAMPS matrix:

- Composite ML-DSA — draft-ietf-lamps-pq-composite-**sigs**
- Composite ML-KEM — draft-ietf-lamps-pq-composite-**kem**

Distinct from hybrid: **single assigned OID per combination** and a
**domain-separated combiner**. Per **draft-19** the serialization is **raw
concatenation** — `pubkey = mldsaPK || tradPK`, `privkey = mldsaSeed || tradSK`,
`sig = mldsaSig || tradSig`, the concatenation wrapped in a single SPKI BIT
STRING / `OneAsymmetricKey` OCTET STRING under the composite OID (component sizes
are fixed per OID, so the split is unambiguous). The layout is close to the
hybrid concat layout; the distinguishers are the single OID and the signed
message representative:

```
M' = Prefix || Label || len(ctx) || ctx || PH(M)
  Prefix = "CompositeAlgorithmSignatures2025"   (fixed ASCII)
  Label  = per-combo, e.g. "COMPSIG-MLDSA44-ECDSA-P256-SHA256"
  PH     = per-combo prehash (SHA-256/512, SHAKE256, …)
mldsaSig = ML-DSA.Sign(mldsaSK, M', ctx=Label)   tradSig = Trad.Sign(tradSK, M')
```

### Phase-2 packaging decision (2026-08) — capability here, not a separate provider

**Decision: composite ships as a build-flag-gated capability *inside this
provider* (default on), as a cleanly-removable module — not a separate
`composite.so`, not a separate repo.** The `composite_*` files stay a distinct
family (own OIDs, ASN.1, domain-separated combiner — no shared *combiner*
abstraction), but reuse the generic two-`EVP_PKEY` key plumbing and the
config-selected PQ / classic component sourcing.

Rationale:

- **Composite is stabilizing, not churning.** `draft-ietf-lamps-pq-composite-sigs`
  is at **-19** (Apr 2026), already past **IETF Last Call** and in IESG review
  toward Proposed Standard; the matrix is bounded (ML-DSA × {RSA-PSS, RSA-PKCS1.5,
  ECDSA, Ed25519, Ed448}). So there is no blast-radius / "stability-coupling" case
  for isolating it in its own `.so`.
- **Hybrid is the family that grows,** not composite: each NIST additional-signature
  on-ramp alg oqsprovider lands (Round 3, May 2026: FAEST, HAWK, MAYO, MQOM, QR-UOV,
  SDitH, SNOVA, SQIsign, UOV) becomes a new hybrid combo here. Hybrid is the
  long-term differentiator worth a stable standalone identity; composite is bounded.
- **Deployment-surface isolation needs only a build flag,** not a second provider:
  the M8 hybrid-backend build simply omits composite (the `HYBRID_KEM_ENCODERS`
  precedent). Shared core → a separate provider would just duplicate the skeleton.
- **Composite is transitional — treat it like the MLX KEMs.** OpenSSL is tracking a
  native implementation (issue [openssl#26121](https://github.com/openssl/openssl/issues/26121),
  triaged feature, gated on its ML-DSA/PKI work). So design composite as a
  **gap-filler that cedes to the default provider's composite once it ships**, exactly
  as hybrid cedes MLX to default today. A build-flagged module is as cheap to remove
  later as a separate provider would be.

Would only flip to a separate `.so` if composite ever needed a materially different
release cadence — a locked spec + build-flag gating removes that.

### Phase-2 design: generic over the PQ component, two-tier

The combiner is generic — nothing about `M'` or the concat serialization needs
ML-DSA specifically. So composite is **info-table-driven, exactly like the hybrid
master list** (`COMPOSITE_SIG_LIST`): one row per combination, the combiner reads
the row and delegates to both components via EVP with **zero ML-DSA hardcoding**.
This makes composite span research PQ sigs (Falcon/MAYO/SLH-DSA/on-ramp round-3)
the same way the hybrid matrix does — experimentation over the same growing PQ set.

A row = `{ pq_alg, trad_alg, trad_group, oid, label, prehash, pq_priv_form, tier }`.
Per-row (not hardcoded): `label` + `prehash` (normative constants for ML-DSA combos),
`pq_priv_form` (ML-DSA stores the draft's 32-byte **seed**; other PQ sigs use their
raw private form), and `tier`.

**Firm two-tier split — never blurred:**

| Tier | PQ component | OID arc | Wire contract |
| --- | --- | --- | --- |
| **standardized** | ML-DSA only | IANA/LAMPS registered | byte-exact vs BouncyCastle / future OpenSSL-native; normative |
| **experimental** | any other PQ sig | a **distinct experimental arc** | non-normative; interop only with ourselves / oqsprovider-if-it-matches |

Why the split is load-bearing:
- **Cede-to-default stays symmetric with hybrid.** When OpenSSL ships native
  composite (ML-DSA only, openssl#26121) we cede *exactly* the standardized subset
  and keep the experimental one — the MLX-to-default move again. A shared OID arc
  would make that impossible to do cleanly.
- **No collision.** Experimental combos can never be mistaken for a standards-track
  OID; a peer that only knows the standard set simply won't resolve ours.

Experimental rows reuse the same `Prefix` (whole-scheme domain separator) with our
own, explicitly non-normative `label`s.

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

### Phase-2 interop status — BouncyCastle vs draft-19 (checked 2026-08)

**BouncyCastle does NOT yet implement draft-19; our code is aligned to draft-19
and is therefore *ahead* of BC, not wrong.** The blocker is the OID arc:

| | OID arc | id-MLDSA44-ECDSA-P256-SHA256 |
| --- | --- | --- |
| **draft-19** (our impl) | PKIX `1.3.6.1.5.5.7.6` | `…6.40` |
| **BouncyCastle 1.85** | Entrust `2.16.840.1.114027.80.9.1` | `…9.1.3` |
| BouncyCastle 1.79–1.83 | Entrust `2.16.840.1.114027.80.8.1` | `…8.1.4` |

- Verified against the raw I-D text: the string `114027` does **not** appear in
  draft-19; its ASN.1 module assigns `pkix(7) alg(6) 40`. Our OIDs +
  `CompositeAlgorithmSignatures2025` prefix + `COMPSIG-…` labels match draft-19.
- BC is still on the Entrust arc (pre-IANA/PKIX assignment, ~draft-13/14 era; BC
  itself moved `…80.8.1` → `…80.9.1` between releases, tracking the draft but
  lagging the final arc).
- **Consequence:** current BC ↔ our draft-19 code will not interop out of the box
  — the AlgorithmIdentifier OIDs differ, and the signing construction *may* also
  differ (some pre-final drafts used the **OID DER** as the domain separator, not
  the ASCII label). OID mismatch confirmed; BC's exact combiner not yet confirmed.

**Decision: do NOT retrofit to BC's older draft.** Chasing a moving pre-final BC
means matching a construction that is about to change. Options, in order of
preference:
1. Hold on draft-19; validate against a **draft-19 peer** — OpenSSL-native
   composite once openssl#26121 lands, or a reference implementation / draft KAT
   vectors — rather than BC.
2. Wait for BC to track the **final RFC** (draft-19 is past IETF LC), then interop
   as-is.
3. Only if near-term BC interop is required: add a **BC-compatibility tier**
   (Entrust OID arc + BC's combiner if it differs), kept disjoint from the
   draft-19 standardized rows — fits the two-tier design.

### Phase-2 interop status — draft-19 KAT interop ACHIEVED (2026-08)

Cross-implementation interop is by KAT: `test/composite_kat_test` imports the
draft-19 reference public keys and verifies the reference signatures from the
draft's own `testvectors.json` (`lamps-wg/draft-composite-sigs`, distilled into
`test/composite_kat.txt`). This is real cross-implementation interop — verify
recomputes `M'` and checks both component signatures against bytes we did not
produce — against the authoritative source (the reference impl that generated the
draft's vectors), the strongest validation short of a live peer.

Known upstream inconsistency: `labelsTable.md` drops the `ECDSA-` infix for the
ECDSA combos (e.g. `COMPSIG-MLDSA87-P384-SHA512`), whereas `algParams.md` and the
`generate_test_vectors.py` that produced the KATs keep it
(`COMPSIG-MLDSA87-ECDSA-P384-SHA512`). We follow `algParams.md`/the KATs, which
are authoritative; the doc inconsistency is reported to the draft editors out of
band.

### Phase-2 open items
- [ ] Enumerate the exact composite matrix + OIDs against
  `draft-ietf-lamps-pq-composite-sigs-19` (bounded: ML-DSA × {RSA-PSS, RSA-PKCS1.5,
  ECDSA, Ed25519, Ed448}) and cross-check oqsprovider `main`.
- [x] Confirm the LAMPS revision Bouncy Castle currently tracks — **done**: BC 1.85
  is on the Entrust OID arc (`…80.9.1`), an earlier draft than -19; see "Phase-2
  interop status" above. Our impl targets draft-19.
- [x] Validate against a draft-19 peer — **done** via the reference KAT vectors
  (`test/composite_kat_test`, 5/5). BC interop remains optional: hold for BC's RFC
  update, or add a BC-compat tier only if near-term BC interop is required (then
  first pin BC's exact combiner).
- [ ] Report the reference doc-vs-code label inconsistency (MLDSA87-ECDSA-P384 in
  `labelsTable.md`) to the draft editors, out of band.
- [ ] **Experimental OID arc:** pick the arc for the non-ML-DSA experimental combos —
  match oqsprovider `main` if it defines composite combos (for interop, as we match
  its hybrid OIDs), else assign our own experimental arc. Must be disjoint from the
  IANA/LAMPS standardized arc.
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
