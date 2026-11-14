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

The hybrid provider's settings — `alg<N>-propquery`, `component-providers`,
`component-path`, `cede-to-default` — live in its section of an `openssl.cnf`
and have **no command-line equivalent** (only `cede-to-default` also has an
environment override, see [Environment variables](#environment-variables)).

The provider still works without a cnf. Loaded on the command line (`openssl …
-provider default -provider oqsprovider -provider hybrid`, or by any application
that calls `OSSL_PROVIDER_load`), it fetches each component from the providers
the application loaded, with no per-component steering and no private component
context. Load order does not matter: components are looked up on first use. What
needs the cnf is choosing *which* provider serves each component, and isolating
the components in a private context (both below). Application code selects the
provider by property query (`?provider=hybrid`) either way.

Two coexistence constraints sit behind this, with different lifespans:

- **The private component context** (`component-providers` / `component-path`,
  below) is cnf-only and is what routes the Frodo/BIKE/HQC tests through a cnf. It
  is needed because two providers cannot both advertise the *same* TLS group name
  in one application context, and both this provider and
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) expose the
  Frodo/BIKE/HQC group names; we source the PQ base through a private context so
  the two can coexist. **Once
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) cedes its
  hybrid combinations (see design.md "Future work"), leaving it to supply only
  the base FrodoKEM/BIKE/HQC KEMs, the name overlap — and this requirement —
  disappears:** all three providers can then be loaded on the command line and
  those groups become ordinary CLI-usable groups.
- **Independent per-component steering** (`alg1-propquery` / `alg2-propquery`,
  below) stays cnf-only, but that is an OpenSSL TLS-plumbing constraint (only a
  single `-propquery` is exposed on the TLS path), not an
  [oqsprovider](https://github.com/open-quantum-safe/oqs-provider) one, and M8
  does not change it. It only matters when you need to source the two component
  halves from *different* providers; the common case (let each component resolve
  normally, or force one provider globally with `-propquery`) needs no cnf.

### Selecting component providers (`alg1-propquery` / `alg2-propquery` / …)

The hybrid provider reads one optional key per component from its config section
to steer which provider supplies each sub-algorithm, independently of how the
hybrid algorithm itself is selected:

```ini
[hybrid_sect]
module         = /path/to/hybrid.so
activate       = 1
alg1-propquery = provider=default        # component 1 (e.g. X25519 / EC)
alg2-propquery = provider=oqsprovider    # component 2 (e.g. ML-KEM / ML-DSA)
```

**Strict `provider=` vs preference `?provider=`.** These are ordinary OpenSSL
property queries. With `provider=<name>`, a component that provider cannot serve
is not found, and the hybrid algorithms built on it are not offered. That is the
visible, safe outcome. With `?provider=<name>` the name is only a preference: if
that provider cannot serve the component, OpenSSL silently takes it from any
provider that can, and the cnf no longer says which implementation runs. Use the
strict form when the choice of provider matters (FIPS boundaries, a specific
hardware or library backend, demos that claim provenance).

**Unset keys: which provider wins?** With no `alg<N>-propquery`, a hybrid looks
up its component with the hybrid key's own property query, normally empty. (The
composite family differs: its default is `provider=default`.) When several loaded
providers serve that component (e.g. ML-KEM-768 from both default and
wolfProvider), OpenSSL documents the choice as unspecified: see the "Note on
naming clashes" in [provider(7)](https://docs.openssl.org/master/man7/provider/).
Current OpenSSL keeps providers sorted by name and returns the first match, so in
practice the provider whose name (as given in the cnf's providers section) sorts
first alphabetically wins, whatever order the cnf lists them in. A global
`default_properties` setting in the cnf is merged into every lookup and can
change the result. Do not rely on either behaviour: if it matters which provider
serves a component, pin it with a strict `alg<N>-propquery = provider=<name>`.

The mapping is **positional** — `alg1-propquery` steers the first component
(`alg1`), `alg2-propquery` the second — so for a PQ/PQ row, whose `alg1` is
itself post-quantum, there is no "classical"/"PQ" assumption baked into the key
names. There is one key per component up to the component bound
(`alg3-propquery` steers the third component of the 3-component HQC KEM groups,
`alg4-propquery` a fourth). Each defaults to the key's normal property query when
unset, so behaviour is unchanged without them. Because they come from
configuration, they also take effect in TLS (where only one property query is
otherwise exposed) — no OpenSSL core change required. `hybrid_config_test`
verifies that each key independently governs its component.

Any provider that serves the component through the public EVP API works as the
source — not just default or
[oqsprovider](https://github.com/open-quantum-safe/oqs-provider). For example,
[wolfProvider](https://github.com/wolfSSL/wolfProvider) (built with
`--enable-mlkem`) serves ML-KEM-512/768/1024, so its ML-KEM can supply the PQ
half of a hybrid:

```ini
[hybrid_sect]
module         = /path/to/hybrid.so
activate       = 1
alg1-propquery = provider=default     # classical half: X25519 from default
alg2-propquery = provider=wolfprov    # PQ half: ML-KEM-768 from wolfProvider
```

`X25519MLKEM768` then composes X25519 (default) with ML-KEM-768 (wolfProvider),
and the composed key interoperates byte-for-byte with wolfProvider's *native*
`X25519MLKEM768` group (verified by the cross-provider matrix — see
[TESTING.md](TESTING.md) and
[provider-interop-results.md](provider-interop-results.md)). Note the query name
is `wolfprov`, not the module name `libwolfprov.so`: a `provider=` query matches
the name a provider registers under, which for wolfProvider differs from its
module file.

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
its private context.

Without `component-providers` the components come from the application's own
context, and the `alg<N>-propquery` keys steer there just the same. Use the
private context only when a component provider also offers the *same* hybrid
algorithms itself (as stock oqsprovider does); otherwise the application
context is simpler and has none of the failure modes below.

#### Failure modes (read before deploying)

`component-providers` is **all-or-nothing**, and OpenSSL reports none of these
failures by default:

| cnf mistake | effect |
|---|---|
| a listed provider cannot be loaded (misspelled name, module missing, wrong `component-path`) | **the hybrid provider does not activate at all**; every hybrid algorithm is gone, not just the ones using that provider |
| `component-providers = default` (the single word `default`) | **the cnf's whole `providers` section fails to parse**: the hybrid provider does not activate, and neither does any provider listed after it. If `hybrid` comes first, the process may end up with no providers at all, because a cnf that activates providers also turns off OpenSSL's automatic fallback to the default provider |
| the key itself misspelled (e.g. `componet-providers`) | ignored: components come from the application context, so algorithms needing a provider that is only in the intended private context are missing |
| a strict `alg<N>-propquery` naming a provider that cannot serve that component | the algorithms using that component are not offered |
| a preference `?provider=` naming such a provider | **no error at all**: the component silently comes from another provider |

Why it is this silent: OpenSSL ignores a provider that fails to activate from a
cnf and carries on, even with `config_diagnostics = 1`. The first symptom is
usually the application rejecting a group or algorithm name, e.g. nginx's
`[emerg] SSL_CTX_set1_curves_list("…") failed`. To see the actual cause,
register the provider without `activate = 1` and load it explicitly with
`OSSL_PROVIDER_load(libctx, "hybrid")`. The error queue then names it:
`component-providers: cannot load "<name>" (search path: …)`.

The single-word `default` problem is an OpenSSL cnf rule, not something this
provider can catch, since the parse fails before the provider runs. When a
provider-section value matches the name of a cnf section, OpenSSL treats it as a
reference to that section, and `default` is always the name of the cnf's
implicit top section. Write the list with more than one entry, or add a trailing
comma (`component-providers = default,`).

Checks after any change: `openssl list -providers` must list `hybrid`,
and `openssl list -tls-groups` (or `-kem-algorithms` / `-signature-algorithms`)
must show the algorithms you expect.

This is verified in-process by `hybrid_compctx_test` and
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

A hybrid combines two components — typically a classical and a PQ one, each
fetched from whatever provider supplies it (default, oqsprovider, …). The hybrid
provider advertises a TLS group or signature scheme **only when both components
are actually fetchable in the library context it is loaded into** — otherwise libssl could negotiate an
algorithm that then fails mid-handshake ("no suitable key share" / "no suitable
signature algorithm"). So, for example, the Frodo/BIKE/HQC groups and the
Falcon/MAYO/SNOVA/OV/MQOM signatures appear in the advertised lists only when
oqsprovider is present to supply their PQ base; the ML-KEM/ML-DSA-based hybrids
are advertised whenever the default provider (3.5+) or oqsprovider can supply
that component. Each algorithm is advertised under its own fixed code point, so a
dropped one never shifts another's value.

Set `HYBRID_LOG=caps` to have the provider print, to stderr, each advertisement
it drops and why (component not fetchable, or the per-enumeration cap reached):

```sh
HYBRID_LOG=caps ./your-app
```

## Which provider served it (`HYBRID_LOG=ops`)

With `HYBRID_LOG=ops` the provider prints one line to stderr per operation it
runs (`keygen`, `encapsulate`, `decapsulate`, `sign`, `verify`), naming the
provider that **actually** served each component, in slot order (`alg1`
first):

```
hybrid: keygen HQCKEM192MLKEM768X25519: X25519@default MLKEM768@wolfprov hqc3@oqsprovider
hybrid: encapsulate p384_mlkem768: EC:P-384@default MLKEM768@wolfprov
hybrid: sign p256_mldsa44: EC:P-256@default MLDSA44@default
```

That answers two questions a cnf alone cannot:

- **Which provider served each component.** The line reports the provider that
  ran the component operation, not the property query that was asked for. With
  a preference `?provider=` steering, or none, this is the only way to know.
- **Whether the hybrid provider ran the algorithm at all.** A line is written
  only when this provider ran the operation. If another provider serves the same
  name (for instance the default provider's native `X25519MLKEM768` when
  cede-to-default is off), there is no line. OpenSSL may even split one
  algorithm across providers: generate the key here, then export it to another
  provider's KEM for encapsulation. The lines show that too.

A TLS 1.3 handshake over a hybrid KEM group gives `keygen` and `decapsulate` on
the client and `encapsulate` on the server. Nothing secret is logged: only
algorithm, component and provider names. The
[curl/nginx integration](integrations/curl-nginx-3alg/USAGE.md) uses these lines
to validate every handshake.

`HYBRID_LOG` values: unset, empty or `0` is off; `caps` and `ops` select a
category and combine with commas (`caps,ops`); any other value (e.g. `1`)
enables all categories. The variable is read on every log call, so it can be
set per process. Some servers clear the environment of their worker processes
(nginx, for example, needs `env HYBRID_LOG;` in its config).

## Environment variables

The provider reads two environment variables, both detailed in the sections
above: `HYBRID_CEDE_TO_DEFAULT` at load time, `HYBRID_LOG` whenever it logs. (Benchmark/test knobs — `BENCH_*`, `HYBRID_BENCH_GUARD_ONLY`,
`COMPOSITE_TRAD_PROPQ` — are documented in [TESTING.md](TESTING.md) instead.)

| Variable | Effect | Details |
|---|---|---|
| `HYBRID_CEDE_TO_DEFAULT` | Boolean; overrides the `cede-to-default` config key. `0`/`no`/`off`/`false` keeps the default provider's algorithms present alongside the hybrid provider's own (coexist mode). Set wins over config. | [Ceding to the default provider](#ceding-to-the-default-provider-cede-to-default) above |
| `HYBRID_LOG` | Diagnostic lines to stderr. `caps`: each advertisement dropped and why. `ops`: per operation, the provider that actually served each component. Comma-combinable; `1` (any other value) = all; unset/empty/`0` = off. | [Only operable algorithms are advertised](#only-operable-algorithms-are-advertised), [Which provider served it](#which-provider-served-it-hybrid_logops) above |

`OPENSSL_MODULES` (OpenSSL's standard module-search-path variable, not specific to
this provider) locates `hybrid.so` when it is not on the default path.
