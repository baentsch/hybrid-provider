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
