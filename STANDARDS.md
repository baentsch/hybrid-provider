# Standards & Conformance

This document is the single catalogue of every standard and standards-proposal
the provider touches, cut along **provenance** rather than algorithm family. Each
algorithm sits in exactly one of four buckets:

1. **[Ceded to the default provider](#1-ceded-to-the-default-provider-by-design)** —
   served by OpenSSL itself, so this provider withdraws its copies by design.
2. **[Standard / draft-backed](#2-backed-by-a-standard-or-draft)** — implemented
   against a named RFC or Internet-Draft, with registered identifiers.
3. **[Convention-only](#3-convention-only-non-normative)** — no standard; follows
   the oqsprovider wire/naming convention or this provider's own experimental arc.
4. **[Future work](#4-future-work--could-be-served)** — specs this design could
   serve but does not yet.

> The algorithm tables in the source
> (`HYBRID_KEM_LIST` / `HYBRID_SIG_LIST` in `hybrid_prov.h`, `COMPOSITE_SIG_LIST`
> in `composite_prov.h`, `COMPOSITE_KEM_LIST` in `composite_kem_prov.h`) are the
> single source of truth for names, OIDs and TLS code points. This file groups
> those same rows by provenance; `hybrid_count_test` guards the totals. If a row
> is added, classify it here too.

---

## 1. Ceded to the default provider by design

The provider **cedes** whatever the default provider already serves in the same
library context: on load it enumerates the default provider's algorithms — **by
name, TLS code point or OID** — and withdraws its own duplicates (`hybrid_apply_cede()`).

**This bucket is deliberately not a fixed list.** It is computed at load time from
whatever the co-loaded default provider happens to offer, so it tracks the running
OpenSSL rather than a hard-coded set. On a current OpenSSL (3.5+) the default
provider serves the standardized hybrid TLS KEM groups, so those are what gets
ceded:

| Served natively by OpenSSL ≥ 3.5 | This provider's matching row | Origin |
|---|---|---|
| `X25519MLKEM768` | `x25519mlkem768` | RFC 10024 ([§2.1](#21-hybrid-kem-for-tls-13--rfc-10024-pqt-hybrid-ecdhe-mlkem)) |
| `SecP256r1MLKEM768` | `secp256r1mlkem768` | RFC 10024 |
| `SecP384r1MLKEM1024` | `secp384r1mlkem1024` | RFC 10024 |
| `X448MLKEM1024` | `x448mlkem1024` | default-provider extension (see note) |

**Note on `X448MLKEM1024`.** It is **not** unstandardized crypto: it uses the
identical construction to its RFC siblings (concatenation of the ML-KEM-1024 and
X448 shared secrets) and conforms to NIST **SP 800-227** — OpenSSL lists both
under "CONFORMING TO" in `EVP_PKEY-MLX-KEM(7)`. What it lacks is a **TLS
NamedGroup code-point registration**: RFC 10024 deliberately omitted the X448
pairing from its group list ("X448MLKEM1024 is not defined by this document"), so
it has no IANA TLS code point (table row `0x0000`), cannot be negotiated in a
handshake, and is reachable only as a KEM primitive. OpenSSL offering extra MLX
*parameter pairings* beyond the TLS group list is deliberate — `curveSM2MLKEM768`
(SM2-based, default-provider only) is another — not invented cryptography. This
provider mirrors `X448MLKEM1024` purely for default-provider parity, so it is
ceded like the three registered groups.

If a future OpenSSL adds more (e.g. native composite ML-DSA, tracked in
openssl#26121), those are ceded automatically by the same name/code-point/OID
match — no code change here.

Ceding is switchable **off** (`cede-to-default = no` / `HYBRID_CEDE_TO_DEFAULT=0`)
to run both implementations under the same identifiers for interop testing; the
test suite forces it off. See [USAGE.md](USAGE.md) and `design.md` §Cede-to-default.

---

## 2. Backed by a standard or draft

### 2.1 Hybrid KEM for TLS 1.3 — **RFC 10024** (PQ/T hybrid ECDHE-MLKEM)

Formerly `draft-ietf-tls-ecdhe-mlkem`; published as **RFC 10024** (Proposed
Standard, August 2026). Byte-compatible with OpenSSL's built-in MLX KEM and the
interop baseline (cross-encaps/decaps + key round-trip against the default
provider). These are the rows ceded in §1 when the default provider serves them.

RFC 10024 defines exactly three groups:

| Algorithm | Components | TLS code point |
|---|---|---|
| `X25519MLKEM768` | X25519 + ML-KEM-768 | `0x11EC` (the only "Recommended" group) |
| `SecP256r1MLKEM768` | P-256 + ML-KEM-768 | `0x11EB` |
| `SecP384r1MLKEM1024` | P-384 + ML-KEM-1024 | `0x11ED` |

`X448MLKEM1024` (X448 + ML-KEM-1024) is **not** one of them. It is **not**
unstandardized crypto: it uses the identical construction to its three RFC
siblings (concatenation of the ML-KEM and X448 shared secrets) and conforms to
NIST **SP 800-227** — OpenSSL lists both under "CONFORMING TO" in
`EVP_PKEY-MLX-KEM(7)`. What it lacks is a **TLS NamedGroup code-point
registration**: RFC 10024 deliberately omitted the X448 pairing from its group
list (the man page states "X448MLKEM1024 is not defined by this document"), so it
has no IANA TLS code point (table row `0x0000`), cannot be negotiated in a
handshake, and is reachable only as a KEM primitive. The provider mirrors it for
default-provider parity — see [§1](#1-ceded-to-the-default-provider-by-design).

Underlying component standards: FIPS 203 (ML-KEM), RFC 7748 (X25519/X448),
RFC 5480/SEC1 (ECDH P-256/P-384).

### 2.2 mlkem512 TLS groups — `draft-rosomakho-tls-ecdhe-mlkem512-00`

Level-1 variant; code points and the `SecP256r1MLKEM512` name follow the draft
(adopted by oqsprovider #802). The OIDs are oqsprovider's (see §3).

| Algorithm | Components | TLS code point |
|---|---|---|
| `SecP256r1MLKEM512` | P-256 + ML-KEM-512 | `0x11E9` |
| `x25519_mlkem512` | X25519 + ML-KEM-512 | `0x11EA` |

### 2.3 Composite signatures — `draft-ietf-lamps-pq-composite-sigs-19`

LAMPS standards-track (Active I-D, v19). Full **18-combo standardized matrix**,
OIDs `1.3.6.1.5.5.7.6.37 … .54`, each verified against the draft's reference
test vectors (`composite_kat_test`). ML-DSA only. Message-representative
construction `M' = prefix || label || len(ctx) || ctx || PH(M)`, raw-concat
serialization. **Normative** (byte-exact vs. BouncyCastle / future OpenSSL-native).

| Tier | Algorithms |
|---|---|
| ML-DSA-44 | `mldsa44_rsa2048_pss`, `mldsa44_rsa2048_pkcs15`, `mldsa44_ed25519`, `mldsa44_ecdsa_p256` |
| ML-DSA-65 | `mldsa65_rsa3072_pss`, `mldsa65_rsa3072_pkcs15`, `mldsa65_rsa4096_pss`, `mldsa65_rsa4096_pkcs15`, `mldsa65_ecdsa_p256`, `mldsa65_ecdsa_p384`, `mldsa65_ecdsa_bp256`, `mldsa65_ed25519` |
| ML-DSA-87 | `mldsa87_ecdsa_p384`, `mldsa87_ecdsa_bp384`, `mldsa87_ed448`, `mldsa87_rsa3072_pss`, `mldsa87_rsa4096_pss`, `mldsa87_ecdsa_p521` |

**TLS code points** for these are the one documented exception to "code points
match their origin": `draft-reddy-tls-composite-mldsa` (not WG-adopted) proposed
points in a range that collided with OpenSSL 4.1 native SLH-DSA (`0x0912`), so the
provider assigns **private-use** points `0xFFE0…` (RFC 8446 §4.2.3) instead. See
`design.md` §get_capabilities.

### 2.4 Composite ML-KEM — `draft-ietf-lamps-pq-composite-kem-18`

LAMPS standards-track (combiner stable since -14). Full **12-combo standardized
matrix**, OIDs `1.3.6.1.5.5.7.6.55 … .66`, verified against the draft's reference
vectors (`composite_kem_kat_test`) and interop-tested against the LAMPS reference
implementation (see
[docs/pqc-kem-certificates-interop.md](docs/pqc-kem-certificates-interop.md)).
Single fixed KDF combiner `ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)`.
PKI/CMS only — **no** TLS key-exchange code point. **Normative.**

| ML-KEM level | Algorithms |
|---|---|
| ML-KEM-768 | `mlkem768_rsa2048`, `mlkem768_rsa3072`, `mlkem768_rsa4096`, `mlkem768_x25519`, `mlkem768_p256`, `mlkem768_p384`, `mlkem768_bp256` |
| ML-KEM-1024 | `mlkem1024_rsa3072`, `mlkem1024_p384`, `mlkem1024_bp384`, `mlkem1024_x448`, `mlkem1024_p521` |

Underlying: FIPS 203 (ML-KEM), RFC 8017 (RSA-OAEP), RFC 7748, RFC 5480.

---

## 3. Convention-only (non-normative)

No governing standard. These interoperate with a specific ecosystem (oqsprovider)
or only with this provider; they carry private-enterprise / private-use
identifiers and must never be mistaken for standards-track.

### 3.1 OQS-legacy hybrid KEMs — oqsprovider naming/wire format

`uint32`-prefixed classical‖PQ wire format, oqsprovider names, OIDs in the OQS
private arc (`1.3.6.1.4.1.22554.*`) where assigned, TLS code points in oqsprovider's
private ranges (`0x2F00…`, `0xFE00…`). ML-KEM variants compose from the default
provider or oqsprovider; Frodo/eFrodo/BIKE/HQC need oqsprovider.

| Family | Algorithms |
|---|---|
| ML-KEM (non-RFC) | `bp256_mlkem512`, `p384_mlkem768`, `x448_mlkem768`, `bp384_mlkem768`, `p521_mlkem1024`, `bp512_mlkem1024` |
| FrodoKEM | `p256_frodo640aes`, `x25519_frodo640aes`, `p256_frodo640shake`, `x25519_frodo640shake`, `p384_frodo976aes`, `x448_frodo976aes`, `p384_frodo976shake`, `x448_frodo976shake`, `p521_frodo1344aes`, `p521_frodo1344shake` |
| eFrodoKEM | `p256_efrodo640aes`, `x25519_efrodo640aes`, `p256_efrodo640shake`, `x25519_efrodo640shake`, `p384_efrodo976aes`, `x448_efrodo976aes`, `p384_efrodo976shake`, `x448_efrodo976shake`, `p521_efrodo1344aes`, `p521_efrodo1344shake` |
| BIKE | `p256_bikel1`, `x25519_bikel1`, `p384_bikel3`, `x448_bikel3`, `p521_bikel5` |
| HQC | `p256_hqc1`, `x25519_hqc1`, `p384_hqc3`, `x448_hqc3`, `p521_hqc5` |

### 3.2 Hybrid (concatenation) signatures — oqsprovider convention

Classical first (ECDSA on the named curve, or RSA-3072), PQ second; wire format
matches oqsprovider (`uint32` classical-length prefix, classical sig, PQ sig).
No standard governs the concatenation; there is no composite binding. ML-DSA
variants compose from the default provider or oqsprovider; the research families
need oqsprovider.

| Family | Algorithms |
|---|---|
| ML-DSA | `p256_mldsa44`, `rsa3072_mldsa44`, `p384_mldsa65`, `p521_mldsa87` |
| Falcon | `p256_falcon512`, `rsa3072_falcon512`, `p521_falcon1024` |
| Falcon-padded | `p256_falconpadded512`, `rsa3072_falconpadded512`, `p521_falconpadded1024` |
| MAYO | `p256_mayo1`, `p256_mayo2`, `p384_mayo3`, `p521_mayo5` |
| UOV | `p256_OV_Is_pkc`, `p256_OV_Ip_pkc`, `p256_OV_Is_pkc_skc`, `p256_OV_Ip_pkc_skc` |
| SNOVA | `p256_snova2454`, `p256_snova2454esk`, `p256_snova37172`, `p384_snova2455`, `p521_snova2965` |
| MQOM2 | `p256_mqom2cat1gf16fastr5`, `p384_mqom2cat3gf16fastr5`, `p521_mqom2cat5gf16fastr5` |

### 3.3 Experimental composite tiers — this provider's private arc

The composite signature and KEM tables each carry an **experimental tier** that
reuses the standardized LAMPS *construction* but pairs non-ML PQ algorithms with a
level-matched classical half (L1→P-256, L3→P-384, L5→P-521). Non-normative labels
and OIDs in a **disjoint private arc `1.3.9999.99.*`** (a leaf of the arc OQS uses
for its own hybrids); they interoperate only with this provider (oqsprovider
supplies the PQ components but implements no composites). Because they serialize
the raw PQ private key rather than a seed, they run from the oqsprovider floor
(OpenSSL 3.2+), unlike the standardized tiers (3.5+).

| | Algorithms |
|---|---|
| Composite sigs (exp.) | `exp_falconpadded512_ecdsa_p256`, `exp_falconpadded1024_ecdsa_p521`, `exp_mayo2_ecdsa_p256`, `exp_mayo3_ecdsa_p384`, `exp_mayo5_ecdsa_p521`, `exp_cross128bal_ecdsa_p256`, `exp_ovIspkc_ecdsa_p256`, `exp_snova2454_ecdsa_p256`, `exp_snova2455_ecdsa_p384`, `exp_snova2965_ecdsa_p521`, `exp_mqom2cat1_ecdsa_p256`, `exp_mqom2cat3_ecdsa_p384`, `exp_mqom2cat5_ecdsa_p521` |
| Composite KEM (exp.) | `exp_frodo640aes_p256`, `exp_frodo976aes_p384`, `exp_frodo1344aes_p521`, `exp_bikel1_p256`, `exp_bikel3_p384`, `exp_bikel5_p521`, `exp_hqc1_p256`, `exp_hqc3_p384`, `exp_hqc5_p521` |

(Default-provider extensions such as `X448MLKEM1024` — standards-conforming MLX
pairings with no TLS code point — are not a separate provenance class; they are
default-provider algorithms, catalogued under
[§1](#1-ceded-to-the-default-provider-by-design).)

### 3.4 Experimentation surface

Carrying pre-/non-standardization constructions is the point of this provider, so
everything in §3 is deliberately available for experimentation. Two boundaries
keep that honest:

- **Operation-only vs serializable.** A combination can always be *exercised* via
  the public EVP API (keygen / encaps / decaps / sign / verify) and KATs. It is
  only **serializable** (SPKI/PKCS8 key files, X.509 certs, CMS) or
  **TLS-negotiable** when it carries an identifier — an OID for PKI/CMS, a code
  point for TLS. Standardized rows get these from their spec; convention-only rows
  reuse oqsprovider's or this provider's private `1.3.9999.99.*` arc; an *ad-hoc*
  pairing has none and is therefore operation-only (the same limitation the
  research KEMs already carry — see the HYBRID_KEM_ENCODERS notes in the README).
- **Security = weakest component.** A hybrid/composite is no stronger than its
  strongest-surviving half by design, but a deliberately odd or level-mismatched
  pairing (e.g. P-256 + ML-KEM-1024) carries the *lower* classical strength. These
  are non-normative and interoperate only with this provider.

**What is available today** is the curated, level-matched set that §3.1–§3.3
enumerate (following oqsprovider and the LAMPS experimental tiers) — **not** the
full classical×PQ cross-product. Pairings outside that set (e.g. X448 + ML-KEM-768
as a *concatenation* KEM, Ed448 + ML-DSA-44 composite, RSA + ML-DSA concatenation)
are not registered. Making **arbitrary** component pairs exercisable — without
shipping a giant static table — is the subject of a planned runtime
"define-a-hybrid" config mechanism
([#112](https://github.com/baentsch/hybrid-provider/issues/112); see
[Tracking](#tracking)): cnf-declared experimental hybrids, operation-only by
default, private identifiers optional, never shadowing a standardized identifier.

---

## 4. Future work — could be served

Specs that combine classical + PQ and fit the EVP-composition model but are **not
yet implemented**. Candidates, strongest fit first:

| Spec | What it adds | Why it fits |
|---|---|---|
| **X-Wing** — `draft-connolly-cfrg-xwing-kem` (CFRG) | General-purpose hybrid KEM X25519 + ML-KEM-768 with a **strongly-binding** combiner (ML-KEM pubkey folded into the KDF) | A genuinely different combiner from the §2.1 concatenation; exercises the table-driven combiner design |
| **Composite ML-DSA in CMS** — `draft-ietf-lamps-cms-composite-sigs` | CMS binding of the §2.3 composite signatures | We already have `hybrid_cms_test.c` (SignedData) and the composite signers |
| **Composite ML-KEM in CMS / KEMRI** — **RFC 9629** (Using KEMs with CMS) + the composite-kem CMS binding | `EnvelopedData` driven by the §2.4 composite KEM | **No new crypto needed** — OpenSSL's CMS KEMRI path is provider-generic (auto-routes any `EVP_PKEY_encapsulate`-capable key to `KEMRI`) and our composite KEM already exposes the full KEM interface + SPKI encoders. The gap is a KEMRI round-trip **test** and **recipient-cert issuance** (a KEM key can't self-sign; issue the cert with a signing key). 3.5+ floor matches composite's. |
| **Dual / parallel hybrid X.509** — `draft-truskovsky-lamps-pq-hybrid-x509`, `draft-sun-lamps-hybrid-scheme`, ITU-T X.509 "catalyst" (`subjectAltPublicKeyInfo` / `altSignature*`) | Two independent signatures in one certificate | The *other* hybrid-cert philosophy vs. our single composite signature; architecturally adjacent |

Each candidate above is tracked as a GitHub issue for later implementation (see
[Tracking](#tracking)).

**Out of scope** (different transport, not an OpenSSL-provider concern): RFC 10042
(PQ/T hybrid KEX for SSH — same primitives, SSH wire), RFC 9370 (IKEv2 multiple
key exchanges). **Informational anchors:** RFC 9958 (PQC for Engineers),
`draft-ietf-pquip-hybrid-signature-spectrums` (taxonomy), NIST SP 800-227 / SP
800-56C (combiner guidance).

### Tracking

Planned issues in `baentsch/hybrid-provider` (upstream-bound work is tracked here,
never filed against oqsprovider/openssl). Numbers backfilled once filed:

| Issue | Scope |
|---|---|
| [#108](https://github.com/baentsch/hybrid-provider/issues/108) CMS KEMRI (RFC 9629) for composite ML-KEM | `EnvelopedData` round-trip test + recipient-cert issuance; KDF/key-wrap pinning for cross-impl interop |
| [#109](https://github.com/baentsch/hybrid-provider/issues/109) Composite ML-DSA signatures in CMS SignedData | Verify/extend `hybrid_cms_test.c` to the composite keytype (`draft-ietf-lamps-cms-composite-sigs`), attr + `-noattr` |
| [#110](https://github.com/baentsch/hybrid-provider/issues/110) X-Wing hybrid KEM | New strongly-binding KEM family (`draft-connolly-cfrg-xwing-kem`) + draft KAT vectors |
| [#111](https://github.com/baentsch/hybrid-provider/issues/111) Dual / parallel hybrid X.509 certificates | Scope decision + prototype for `subjectAltPublicKeyInfo` / catalyst-style dual-sig certs |
| [#112](https://github.com/baentsch/hybrid-provider/issues/112) Runtime "define-a-hybrid" config mechanism | cnf-declared experimental hybrids for arbitrary component pairs (operation-only; private IDs optional; §3.4) |

---

## References

- [RFC 10024](https://datatracker.ietf.org/doc/rfc10024/) — PQ/T Hybrid Key Agreement for TLS 1.3 (ex `draft-ietf-tls-ecdhe-mlkem`)
- [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) (v19)
- [draft-ietf-lamps-pq-composite-kem](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/) (v18)
- [draft-rosomakho-tls-ecdhe-mlkem512](https://datatracker.ietf.org/doc/draft-rosomakho-tls-ecdhe-mlkem512/)
- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [RFC 9629](https://datatracker.ietf.org/doc/rfc9629/) — Using KEMs with CMS
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)
</content>
</invoke>
