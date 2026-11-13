# curl ↔ nginx over a 3-provider hybrid KEM (downstream integration demo)

This integration proves that the **hybrid-provider** works in real downstream TLS
software — a currently-released **curl** and **nginx** — purely as an
`openssl.cnf` plugin, and that one hybrid KEM group can be composed from **three
different crypto providers at once**.

The handshake negotiates the draft-preussmattsson group
**`HQCKEM192MLKEM768X25519`** (TLS codepoint `0xfe44`), whose three components are
each served by a different provider:

| component  | logical slot | provider           |
|------------|--------------|--------------------|
| X25519     | `alg1`       | OpenSSL **default**|
| ML-KEM-768 | `alg2`       | **wolfProvider**   |
| HQC-192    | `alg3`       | **oqsprovider**    |

The selection is expressed only in `openssl.cnf` (`component-providers` +
`alg1/2/3-propquery`); no application, library, or build change is involved.

> **This file is the build guide.** For running and exploring the resulting
> image (environment variables, the trace mode, interactive use, the scripts and
> config files), see **[USAGE.md](USAGE.md)**.

## Prerequisites

- Docker (BuildKit; Docker 23+).
- Network access during build (clones OpenSSL, liboqs, oqsprovider, wolfSSL,
  wolfProvider; downloads nginx + curl).
- ~15 GB free disk for the build cache and images, and a fair amount of CPU time
  — it compiles OpenSSL, liboqs (the full NIST on-ramp set), wolfSSL, three
  providers, curl and nginx from source.

## Build

Build context **must be the repo root** — the image compiles hybrid-provider
from the working tree:

```sh
# default image (proves the negotiated group)
docker build -f integrations/curl-nginx-3alg/Dockerfile -t hp-3alg .
```

That is the only command needed; then see [USAGE.md](USAGE.md) to run it.

### Optional: trace-enabled image

To additionally trace *which provider served each component* at run time, build a
second image with OpenSSL's tracing compiled in (off by default — a single
conditional word on the OpenSSL `./config` line):

```sh
docker build -f integrations/curl-nginx-3alg/Dockerfile --build-arg ENABLE_TRACE=1 -t hp-3alg-trace .
```

### Build arguments

All versions are `ARG`s at the top of the `Dockerfile` and can be overridden with
`--build-arg`, e.g. `--build-arg NGINX_VERSION=1.29.0`. The notable one is
`ENABLE_TRACE` (`0`/`1`, default `0`).

## Relationship to the upstream oqs-demos Dockerfiles

The `Dockerfile` is intentionally close to open-quantum-safe/oqs-demos'
`nginx` + `curl` Dockerfiles; blocks are marked `### === oqs-demos ===` (kept)
vs `### +++ ADDED: … +++` (the hybrid delta). The additions are: one shared
OpenSSL install (so nginx/curl/providers share a libcrypto), the wolfProvider
and hybrid-provider builds, and the demo configs/entrypoint. The only *functional*
difference from a stock oqs-demos stack is `openssl.cnf` (see
`diff openssl-stock.cnf openssl.cnf`).

### wolfProvider: lean build + drift guard

wolfProvider is built by `build-wolfprovider-lean.sh`, which compiles wolfSSL +
wolfProvider against the **one shared OpenSSL** — unlike wolfProvider's own
`scripts/build-wolfprovider.sh`, which is a CI harness that clones and builds a
*second*, pinned OpenSSL. To stay faithful to upstream's tested wolfSSL
configuration without silently drifting, the script **pins** wolfSSL's
`./configure` flags/CFLAGS and then **asserts at build time** that those pins
still equal the values in wolfProvider's `scripts/utils-wolfssl.sh`; any upstream
change fails the build with a diff. (The wolfSSL *version* is pinned by us for
reproducibility — upstream floats it to "latest release" — and must be
≥ `v5.9.2-stable` for ML-KEM with wolfProvider `master`.)

## Version pins (and why they deviate from oqs-demos)

| component     | pin            | reason |
|---------------|----------------|--------|
| OpenSSL       | `openssl-3.6.5`| one build known-good for all providers; wolfProvider needs ≥3.6.0 for ML-KEM |
| liboqs        | `main` + `-DOQS_ENABLE_KEM_HQC=ON` | only recent liboqs ships HQC enabled under the `hqc3` identifier |
| oqsprovider   | `main`         | only `main` registers the **standalone** `hqc3` KEM (`enable_kem`); stable releases are HQC-hybrid-only / bit-named |
| wolfProvider  | `master` (+ wolfSSL `v5.9.4-stable`), `--enable-mlkem` | supplies ML-KEM-768 as `MLKEM768`; wolfSSL flags pinned + drift-checked against upstream |
| nginx / curl  | released       | unchanged downstream software |

A stable oqsprovider cannot supply a standalone HQC KEM, so the 3-alg HQC
handshake requires oqsprovider `main`. If the wolfProvider build is unavailable
at run time, the entrypoint automatically sources ML-KEM-768 from oqsprovider
instead (still a full 3-alg handshake) — see [USAGE.md](USAGE.md).

## Files

| file | purpose |
|------|---------|
| `Dockerfile` | multi-stage build of the shared OpenSSL + all providers + nginx + curl |
| `openssl.cnf` / `openssl-stock.cnf` | the hybrid config and the stock baseline; their `diff` is the whole functional change |
| `nginx.conf` | TLS 1.3 server offering only `HQCKEM192MLKEM768X25519` |
| `entrypoint.sh` | default container command — runs and asserts the proof |
| `tls-trace.sh` | opt-in provenance tracer (used with `HP_TRACE=1`) |
| `noconf.sh` | opt-in test: what still works with the `openssl.cnf` removed (CLI-only activation) |
| `build-wolfprovider-lean.sh` | lean wolfSSL+wolfProvider build + the drift guard |
