# One hybrid group from three providers

Besides replacing oqsprovider's hybrids (see [README.md](README.md)), the image
shows that one hybrid KEM group can be composed from **three different crypto
providers at once**, purely through `openssl.cnf`. The headline group is the
draft-preussmattsson **`HQCKEM192MLKEM768X25519`** (TLS code point `0xfe44`,
provisional), whose components each come from a different provider:

| component  | logical slot | provider            |
|------------|--------------|---------------------|
| X25519     | `alg1`       | OpenSSL **default** |
| ML-KEM-768 | `alg2`       | **wolfProvider**    |
| HQC-192    | `alg3`       | **oqsprovider**     |

## How the config does it

The shipped [`openssl.cnf`](openssl.cnf) is the plain drop-in: the
application context loads only `default + hybrid`, and the hybrid provider
builds its **own private component context** from `component-providers`
(`default oqsprovider`), taking each component from whichever of them has it.
So by default the headline group already combines three algorithms, from two
providers: X25519 and ML-KEM-768 from default, HQC-192 from oqsprovider.

The three-provider proof is `HYP_STEERING=strict`, the default for `selftest`.
The entrypoint then writes the active config (`/tmp/hyp/openssl-active.cnf`)
with wolfProvider added to the component providers and one provider pinned per
component slot, by a property query each:

```ini
component-providers = default oqsprovider wolfprov
...
alg1-propquery = provider=default
alg2-propquery = provider=wolfprov
alg3-propquery = provider=oqsprovider
```

A pin `provider=<name>` makes a group disappear if the named provider can't
serve its component (`?provider=<name>` would only be a preference). The slots
are positional: `alg2` pins the second component of *every* group, so with
wolfProvider (ML-KEM only) strict steering leaves only the ML-KEM-based groups.
`HYP_MLKEM_PROVIDER` picks the provider for `alg2`; see
[USAGE.md](USAGE.md#environment-variables).

## Proving which provider served each component

`connect.sh` connects with curl and `openssl s_client`, one group at a time, and
reads the hybrid provider's own per-operation log (`HYBRID_LOG=ops`) on both
ends of the handshake:

```sh
docker run --rm hyp-3alg selftest
```

```
[OK  ] HQCKEM192MLKEM768X25519
         curl=HQCKEM192MLKEM768X25519  s_client=HQCKEM192MLKEM768X25519  server=HQCKEM192MLKEM768X25519  log=HQCKEM192MLKEM768X25519
         comps: X25519@default MLKEM768@wolfprov hqc3@oqsprovider   (client keygen+decaps; server encaps: same)
```

Under strict steering every component must come from its pinned provider, or
the group fails. Details: [USAGE.md](USAGE.md#validating-with-connectsh). If the
wolfProvider module is missing at run time, the entrypoint sources ML-KEM-768
from the default provider instead (still three algorithms, from two providers).

## wolfProvider: lean build and drift guard

wolfProvider is built by `build-wolfprovider-lean.sh`, which compiles wolfSSL +
wolfProvider against the **one shared OpenSSL**, unlike wolfProvider's own
`scripts/build-wolfprovider.sh`, a CI harness that clones and builds a *second*,
pinned OpenSSL. To stay faithful to upstream's tested wolfSSL configuration
without silently drifting, the script **pins** wolfSSL's `./configure`
flags/CFLAGS and then **asserts at build time** that those pins still equal the
values in wolfProvider's `scripts/utils-wolfssl.sh`; any upstream change fails
the build with a diff. (The wolfSSL *version* is pinned for reproducibility,
since upstream floats it to "latest release", and must be ≥ `v5.9.2-stable` for
ML-KEM with wolfProvider `master`.)

## Version pins

| component    | pin | reason |
|--------------|-----|--------|
| OpenSSL      | `openssl-3.6.5` | one build known-good for all providers; wolfProvider needs ≥ 3.6.0 for ML-KEM |
| liboqs       | `UPSTREAM`: 0.16.0 (release) or `main`, with `-DOQS_ENABLE_KEM_HQC=ON` | HQC under the level name `hqc3` since 0.16.0 |
| oqsprovider  | `UPSTREAM`: 0.12.0 (release) or `main` | registers the **standalone** `hqc3` KEM (`enable_kem`) since 0.12.0 (oqs-provider PR 787) |
| wolfProvider | `master` (+ wolfSSL `v5.9.4-stable`), `--enable-mlkem` | supplies ML-KEM-768 as `MLKEM768`; wolfSSL flags pinned + drift-checked against upstream |
| nginx / curl | released | unchanged downstream software |

The `UPSTREAM` choice is explained in [README.md](README.md#build).
