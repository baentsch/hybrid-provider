# Using the hybrid provider

How to load the provider, call the hybrid algorithms, mix components from
different providers, and configure component sourcing. For the algorithm
inventory and build instructions see the [README](README.md); for the
architecture see [design.md](design.md).

## Loading and calling

Load the provider alongside the default provider:

```c
OSSL_PROVIDER_load(libctx, "default");
OSSL_PROVIDER_set_default_search_path(libctx, "/path/to/hybrid.so/dir");
OSSL_PROVIDER_load(libctx, "hybrid");

/* KEM */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "X25519MLKEM768", NULL);

/* Signature */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "p256_mldsa44", NULL);

/* Composite signature (only when built with -DHYBRID_COMPOSITE) */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(libctx, "mldsa44_ecdsa_p256", NULL);
```

Application code selects the provider by property query (`?provider=hybrid`) once
it is loaded.

## Mixing sub-algorithms from different providers

The hybrid provider fetches sub-algorithms through the EVP layer, so they can
come from any loaded provider. For example, to compose X25519 from the default
provider with ML-KEM-768 from
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider):

```c
OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

/* Load all three providers */
OSSL_PROVIDER_load(libctx, "default");    /* provides X25519 */
OSSL_PROVIDER_load(libctx, "oqsprovider"); /* provides ML-KEM-768 */
OSSL_PROVIDER_set_default_search_path(libctx, "/path/to/hybrid.so/dir");
OSSL_PROVIDER_load(libctx, "hybrid");     /* composes them */

/* Generate a hybrid keypair — the hybrid provider will internally call
 * EVP_PKEY_Q_keygen for X25519 (resolved by default provider) and
 * ML-KEM-768 (resolved by oqsprovider) */
EVP_PKEY *key = NULL;
EVP_PKEY_CTX *gctx = EVP_PKEY_CTX_new_from_name(libctx,
                          "X25519MLKEM768", "provider=hybrid");
EVP_PKEY_keygen_init(gctx);
EVP_PKEY_keygen(gctx, &key);

/* Encapsulate / decapsulate as usual */
EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new_from_pkey(libctx, key, "provider=hybrid");
EVP_PKEY_encapsulate_init(ectx, NULL);
/* ... */
```

The hybrid provider itself never touches the raw cryptography — it only
orchestrates the sub-algorithms via EVP, making it agnostic to which provider
implements them.

## Configuration

The hybrid provider is configured **exclusively through an `openssl.cnf`**, never
by loading it with `openssl -provider hybrid` on the command line. All of its
component-steering keys — `pq-propquery`, `classic-propquery`,
`component-providers`, `component-path` — live in the provider's config section
and have **no command-line equivalent**. Loading the module with `-provider
hybrid` gives it none of these keys, so it cannot compose anything, and the
private component context that sources Frodo/BIKE/HQC (below) never gets built.
Application code selects the provider by property query (`?provider=hybrid`) once
the cnf has activated it.

Two distinct limitations sit behind this, with different lifespans:

- **The private component context** (`component-providers` / `component-path`,
  below) is cnf-only and is what forces the Frodo/BIKE/HQC tests through a cnf.
  It exists solely because
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) advertises the
  *same* TLS group names as this provider, so the two can't coexist in one
  application context. **Once
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) drops its
  hybrid combinations (see design.md "Future work"), leaving it to supply only
  the base FrodoKEM/BIKE/HQC KEMs, that collision — and this requirement —
  disappears:** all three providers can then be loaded on the command line and
  those groups become ordinary CLI-usable groups.
- **Independent per-component steering** (`pq-propquery` / `classic-propquery`,
  below) stays cnf-only, but that is an OpenSSL TLS-plumbing constraint (only a
  single `-propquery` is exposed on the TLS path), not an
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) one, and M8
  does not change it. It only matters when you need to source the PQ and classic
  halves from *different* providers; the common case (let each component resolve
  normally, or force one provider globally with `-propquery`) needs no cnf.

### Selecting component providers (`pq-propquery` / `classic-propquery`)

The hybrid provider reads two optional keys from its config section to steer
which provider supplies each sub-algorithm, independently of how the hybrid
algorithm itself is selected:

```ini
[hybrid_sect]
module            = /path/to/hybrid.so
activate          = 1
pq-propquery      = ?provider=oqsprovider   # ML-KEM / ML-DSA component
classic-propquery = ?provider=default       # X25519 / EC component
```

Each defaults to the key's normal property query when unset, so behaviour is
unchanged without them. Because they come from configuration, they also take
effect in TLS (where only one property query is otherwise exposed) — no OpenSSL
core change required. `hybrid_config_test` verifies that each key independently
governs its component.

### Private component context (`component-providers` / `component-path`)

Some PQ bases (FrodoKEM, BIKE, HQC) exist only in
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider), which also
registers its **own** competing hybrid TLS groups (`p256_frodo640aes`, …) under
the same names. Loading
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) into the
application context would therefore collide with the hybrid provider's groups. To
avoid this, the hybrid provider can build a **private component library context**
and source its PQ base from there:

```ini
[hybrid_sect]
module              = /path/to/hybrid.so
activate            = 1
component-providers = default oqsprovider   # loaded into the provider's OWN ctx
component-path      = /path/to/modules       # where to find oqsprovider.so
```

The application context then loads only `default` + `hybrid`, so the Frodo/BIKE/
HQC hybrid groups resolve unambiguously to the hybrid provider while their PQ
components come from
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider) privately.
`component-path` is required so the provider can locate the component modules in
its private context. This is verified in-process by `hybrid_compctx_test` and
over separate-process `openssl` `s_server`/`s_client` handshakes (both
directions, against a pure-[oqsprovider](https://github.com/open-quantum-safe/oqs-provider)
peer) by `test/hybrid_scenarios.sh tls-compctx`.

### Ceding to the default provider (`cede-to-default`)

Some of this provider's algorithms are also implemented by the OpenSSL default
provider. Re-implementing them exists only so the two can be compared for
interoperability; in real operation duplicating them serves no purpose.

Therefore, **by default the provider cedes**: at load time it inspects the
default provider in the same library context and withdraws every algorithm the
default provider already serves — from both the algorithm tables (so
`EVP_*_fetch` without a mandatory `provider=` no longer resolves them here) and
the TLS group / signature-algorithm capabilities. What remains is exactly the
set the default provider lacks.

The match is by **any identifier the default provider may share with us —
algorithm name, TLS code point or OID** — not a fixed algorithm list, so it is
open-ended by design: it covers whatever the default provider serves today (the
standardized hybrid KEM groups) and whatever it may serve in a future OpenSSL
(for instance native composite signatures). When the default provider is not
loaded alongside this one, or serves none of our identifiers (e.g. an OpenSSL
whose default provider has no post-quantum algorithms), nothing is withdrawn.

Ceding is switchable off when you *do* want both implementations present under
the same identifiers and disambiguated by property query (e.g. `provider=hybrid`
vs `provider=default`) — the mode the interoperability tests use. Turn it off via
the config-section key or the environment variable (the env var, when set, wins):

```ini
[hybrid_sect]
module          = /path/to/hybrid.so
activate        = 1
cede-to-default = no          # keep the default provider's algorithms too (coexist)
```

```sh
HYBRID_CEDE_TO_DEFAULT=0 ./your-app     # same effect, no config edit
```

Accepted booleans: `1`/`0`, `yes`/`no`, `on`/`off`, `true`/`false`. `hybrid_cede_test`
verifies both states across the whole inventory; detection only ever affects
identifiers the default provider actually serves, so anything unique to this
provider is never withdrawn.

## Only operable algorithms are advertised

A hybrid combines a classical and a PQ component, each fetched from whatever
provider supplies it (default, oqsprovider, …). The hybrid provider advertises a
TLS group or signature scheme **only when both components are actually fetchable
in the library context it is loaded into** — otherwise libssl could negotiate an
algorithm that then fails mid-handshake ("no suitable key share" / "no suitable
signature algorithm"). So, for example, the Frodo/BIKE/HQC groups and the
Falcon/MAYO/SNOVA/OV/MQOM signatures appear in the advertised lists only when
oqsprovider is present to supply their PQ base; the ML-KEM/ML-DSA-based hybrids
are advertised whenever the default provider (3.5+) or oqsprovider can supply
that component. Each algorithm is advertised under its own fixed code point, so a
dropped one never shifts another's value.

Set `HYBRID_LOG=1` to have the provider print, to stderr, each advertisement it
drops and why (component not fetchable, or the per-enumeration cap reached):

```sh
HYBRID_LOG=1 ./your-app
```
