# Using the curl ↔ nginx 3-provider demo image

This is the user guide for the image built per [README.md](README.md). It explains
what the image does, how to run it, the environment variables and scripts, how to
read the output, and how to poke at it interactively.

## What the image is

A single, self-contained image that runs **both** sides of a TLS 1.3 handshake —
an nginx server and a curl client — and proves they negotiate the
draft-preussmattsson hybrid KEM group **`HQCKEM192MLKEM768X25519`**, whose three
components are supplied by three different OpenSSL providers (X25519 ← default,
ML-KEM-768 ← wolfProvider, HQC-192 ← oqsprovider), composed by hybrid-provider
through `openssl.cnf` alone. It is a **demonstration/validation image**, not a
production server.

## Quick start

```sh
docker run --rm hp-3alg
```

The container runs the proof and exits. **Exit code 0 = PASS**: curl and nginx
completed the handshake over `HQCKEM192MLKEM768X25519`. Non-zero = the expected
group was not negotiated (the output shows why). Nothing listens after it exits;
it is a one-shot self-test, not a long-running service.

## Reading the output

The run prints these sections in order:

1. **component → provider map** — the three components and the provider each is
   steered to.
2. **config-only proof** — `diff` of `openssl-stock.cnf` vs `openssl.cnf`: the
   entire functional change is that one `[hybrid_sect]` stanza.
3. **group availability without / with the plugin** — the group is absent from
   `openssl list -tls-groups` under the stock config and present under the hybrid
   config.
4. **curl -v** — the real client handshake; look for
   `SSL connection using TLSv1.3 / … / HQCKEM192MLKEM768X25519`, then the HTTP 200
   body.
5. **openssl s_client** — an independent cross-check printing
   `Negotiated TLS1.3 group: HQCKEM192MLKEM768X25519`.
6. **nginx debug log** — server-side handshake confirmation.
7. **RESULT** — `PASS`/`FAIL`.

## Environment variables

| variable | values | effect |
|----------|--------|--------|
| `HP_MLKEM_PROVIDER` | `wolfprov` (default) / `default` | which provider supplies the ML-KEM-768 component (any provider in `component-providers` that serves it). If `wolfprov` and the wolfProvider module is missing, the entrypoint auto-falls back to `default`: still all 3 algorithms, from 2 providers. A provider that cannot serve ML-KEM-768 makes the run FAIL; the steering is strict. The oqsprovider build in this image registers no standalone ML-KEM-768, so `oqsprovider` is not a valid value. |
| `HP_TRACE` | `0` (default) / `1` | when `1`, also run `tls-trace.sh` to show which provider served each component. Meaningful only on an image built with `--build-arg ENABLE_TRACE=1` (otherwise it prints how to rebuild). |

Examples:

```sh
# source ML-KEM-768 from the default provider instead of wolfProvider
docker run --rm -e HP_MLKEM_PROVIDER=default hp-3alg

# provenance trace (requires the ENABLE_TRACE=1 image)
docker run --rm -e HP_TRACE=1 hp-3alg-trace
```

## Provenance trace: what crypto really operates

On the trace-enabled image, `HP_TRACE=1` runs one handshake with OpenSSL tracing
and `tls-trace.sh` analyses it, printing a table that cross-checks the cnf's
intent against what actually happened:

```
COMPONENT  FETCH-NAME   CNF-STEER    RESOLVED     MATCH
X25519     X25519       default      default      OK
ML-KEM-768 MLKEM768     wolfprov     wolfprov     OK
HQC-192    hqc3         oqsprovider  oqsprovider  OK
```

The evidence comes from OpenSSL `QUERY` trace lines showing each component being
fetched in the hybrid provider's *private* (non-default) library context under
its `provider=…` property query.

## Exploring interactively

Drop into a shell to run the tools yourself:

```sh
docker run --rm -it hp-3alg bash
```

Useful layout inside the image:

| path | what |
|------|------|
| `/opt/pq` | the shared OpenSSL install (prefix); `bin/openssl`, `bin/curl` |
| `/opt/pq/lib64/ossl-modules` | provider modules: `hybrid.so`, `oqsprovider.so`, `wolfprov.so` |
| `/opt/pq/ssl/openssl.cnf` | the active hybrid config (also `OPENSSL_CONF`) |
| `/opt/pq/ssl/openssl-stock.cnf` | the stock baseline (for the diff) |
| `/opt/pq/demo/` | demo CA + server cert/key (classical ECDSA P-256) |
| `/opt/nginx` | nginx prefix; `sbin/nginx`, `conf/nginx-demo.conf` |

Some things to try:

```sh
# which providers/groups are active under the hybrid config
openssl list -providers
openssl list -tls-groups | tr ':' '\n' | grep HQCKEM

# re-run just the proof, or just the trace (if server is up on 4433)
entrypoint.sh
tls-trace.sh 4433

# start the server yourself and connect manually
nginx -p /opt/nginx -c conf/nginx-demo.conf &
openssl s_client -connect 127.0.0.1:4433 -groups HQCKEM192MLKEM768X25519 \
    -CAfile /opt/pq/demo/CA.crt -tls1_3
curl -v --curves HQCKEM192MLKEM768X25519 --cacert /opt/pq/demo/CA.crt https://127.0.0.1:4433/
```

## Changing the provider split

The split is pure configuration. Edit the `alg*-propquery` lines in
`/opt/pq/ssl/openssl.cnf` (or mount your own over it) to re-route any component
to any loaded provider — e.g. `alg2-propquery = provider=default` sources
ML-KEM-768 from the default provider. The providers available to the components
are those listed in `component-providers` (loaded into the hybrid provider's
private context). No rebuild is needed.

The demo uses the strict form `provider=<name>`: if that provider cannot serve
the component, the group disappears and the run fails. The preference form
`?provider=<name>` would instead fall back silently to any provider that has
the component, so the provider that actually serves it would no longer be the
one the cnf names.

## The scripts

| script | when it runs | what it does |
|--------|--------------|--------------|
| `entrypoint.sh` | default `CMD` | builds the active config (honouring `HP_MLKEM_PROVIDER`), starts nginx, runs curl + `openssl s_client`, asserts the negotiated group; optionally invokes the tracer when `HP_TRACE=1` |
| `tls-trace.sh` | via `HP_TRACE=1`, or manually with a port arg | runs one traced handshake + key-share keygen and reports which provider served each component |
| `noconf.sh` | manually: `docker run --rm hp-3alg noconf.sh` | removes `openssl.cnf`, then asserts what each tool can still do with command-line provider activation alone (see [Without openssl.cnf](#without-opensslcnf)) |
| `build-wolfprovider-lean.sh` | **build time only** | compiles wolfSSL + wolfProvider against the shared OpenSSL and asserts the pinned wolfSSL flags against wolfProvider upstream (not used at run time) |

## Without openssl.cnf

```sh
docker run --rm hp-3alg noconf.sh
```

removes the config from `OPENSSLDIR`, unsets `OPENSSL_CONF`, and asserts the
outcome per tool (exit 0 = every row behaved as listed):

| tool | without the cnf | how / why |
|------|-----------------|-----------|
| `openssl` (`s_client`, `s_server`, `list`, …) | **yes**, full `HQCKEM192MLKEM768X25519` | `-provider-path /opt/pq/lib64/ossl-modules -provider default -provider oqsprovider -provider wolfprov -provider hybrid`; works on both ends of a handshake |
| curl | **partial** | `curl --engine hybrid` loads that one provider plus `default` into curl's own library context; hybrid groups built from default components work (the test derives one, e.g. `SecP256r1MLKEM512`), but the HQC group does not: no oqsprovider is in curl's context to supply HQC-192 (`failed setting curves list`) |
| nginx | **no** | no directive loads a provider (`ssl_engine` handles ENGINEs only, and `env OPENSSL_CONF` takes effect too late); it refuses to start: `[emerg] SSL_CTX_set1_curves_list("HQCKEM192MLKEM768X25519") failed`. A cnf is required, though `OPENSSL_CONF` can point at any path |

Without the cnf there is no `component-providers` / `alg<N>-propquery`, so every
component is fetched from the application context with no per-component
steering. With several providers serving ML-KEM-768 (default and
wolfProvider), the provider that serves it is not pinned.

## Caveats

- TLS codepoint `0xfe44` for `HQCKEM192MLKEM768X25519` is **provisional / private-use**
  (draft-preussmattsson), not an IANA assignment — fine for this closed
  client+server demo, not for interop with other stacks.
- The server certificate is a throwaway classical ECDSA P-256 cert; the KEM group
  is independent of the certificate signature algorithm.
- This image is for demonstration and validation only.
