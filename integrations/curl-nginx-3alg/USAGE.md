# curl ↔ nginx demo image: reference

This is the reference for the image built per [README.md](README.md): what the
servers offer, the validation scripts and how to read their output, the
environment variables, and interactive use. For a first walkthrough, start
with the README.

## What the image is

A self-contained image with two **nginx TLS 1.3 servers**: one under the hybrid
config (port 4433), where hybrid-provider serves the hybrid KEM groups, and one
under the stock config (port 4434), where oqsprovider serves its own. Two
client scripts check them:

- `interop.sh`: every group both servers offer, in all four client/server
  pairings (see [Interop with oqsprovider's own hybrids](#interop-with-oqsproviders-own-hybrids)).
- `connect.sh`: every group of the hybrid server, with curl and
  `openssl s_client`, including which provider served each component (see
  [Validating with connect.sh](#validating-with-connectsh)). Its headline group
  combines three providers; see [THREE-PROVIDERS.md](THREE-PROVIDERS.md).

It is a **demonstration/validation image**, not a production server.

## Quick start

```sh
# servers: run until the container is stopped
docker run -d --name hyp -p 4433:4433 -p 4434:4434 hyp-3alg

docker exec hyp interop.sh       # hybrid-provider vs oqsprovider, four pairings
docker exec hyp connect.sh       # hybrid server, with per-component provenance
docker exec hyp connect.sh HQCKEM192MLKEM768X25519   # or just some groups

docker logs -f hyp      # server log: one line per request with the negotiated group
docker stop hyp && docker rm hyp
```

One-shot runs (for CI) start the servers, run one check and exit with its result:

```sh
docker run --rm hyp-3alg selftest   # connect.sh
docker run --rm hyp-3alg interop    # interop.sh
```

## What the server offers

At start the entrypoint derives the group list from what is actually loaded:
every TLS group available under the hybrid config minus those OpenSSL offers
without any cnf. Nothing is hardcoded. Two things deliberately keep groups out:

- **Ceded groups.** Groups the default provider already serves natively are
  left to it (cede-to-default), so they are not part of this demo.
- **Steering** (`HYP_STEERING`, below). `alg<N>-propquery` is positional:
  `alg2` names the provider for the second component of *every* group. The
  default `max` only prefers it, so all 44 groups are offered. `strict` (the
  default for `selftest`) pins it to wolfProvider, which only has ML-KEM; that
  leaves the 10 ML-KEM-based groups.

The startup output shows the component steering, the `diff` between the stock
and the hybrid `openssl.cnf` (the entire functional change), and the offered
groups. A `*` marks names the stock cnf also offers (oqsprovider's own hybrids);
here the hybrid provider serves them.

Every handshake is logged in nginx's `kem` access-log format, to stdout and to
`/opt/nginx/logs/kem-access.log`:

```
uri=/kem/HQCKEM192MLKEM768X25519?id=7936cd0b2af6 curve=HQCKEM192MLKEM768X25519 protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 client=127.0.0.1 time=...
```

The response body also carries `negotiated=<group>` (nginx's `$ssl_curve`), so
any client can see the server's view of the handshake.

## Validating with connect.sh

For each group, `connect.sh` offers only that group and checks the negotiated
group from independent sources:

| source | evidence |
|--------|----------|
| `curl` | curl's own `SSL connection using TLSv1.3 / … / <group>` |
| `s_client` | `Negotiated TLS1.3 group: <group>` from `openssl s_client` |
| `server` | nginx's `$ssl_curve`, echoed in the response body |
| `log` | nginx's access-log line for this exact request (matched by a random request id); `n/a` when the client runs outside the server's container |

It also checks which provider served each component, from the hybrid
provider's own log (`HYBRID_LOG=ops`, see the main
[USAGE.md](../../USAGE.md#which-provider-served-it-hybrid_logops)). Each line
names the provider that **actually** ran each component:

| side | lines |
|------|-------|
| client | curl's key-share `keygen` and `decapsulate` |
| server | nginx's `encapsulate` for this handshake (read from `/tmp/hyp/server.log`; `n/a` from another container) |

```
[OK  ] HQCKEM192MLKEM768X25519
         curl=HQCKEM192MLKEM768X25519  s_client=HQCKEM192MLKEM768X25519  server=HQCKEM192MLKEM768X25519  log=HQCKEM192MLKEM768X25519
         comps: X25519@default MLKEM768@wolfprov hqc3@oqsprovider   (client keygen+decaps; server encaps: same)
```

A missing line means the hybrid provider did not run that side, so the lines
also prove that the hybrid provider served the group itself. Components are
listed in slot order (`alg1` first) and compared with the `alg<N>-propquery`
pins:
- **`HYP_STEERING=strict`:** a component from any other provider is a FAIL.
- **`max`:** a preference that was not honoured is noted and the group is
  reported as `OK*`, e.g. `alg2 preferred wolfprov, served by oqsprovider` for
  the Frodo/BIKE/HQC groups, which wolfProvider cannot serve.

A group is OK when every available source reports exactly the offered group and
the provenance lines are present and consistent with the pins. The server must
keep `HYBRID_LOG` enabled (the entrypoint sets `ops`); with it off, the server
side cannot be proven and every group fails.

## Environment variables

| variable | values | used by | effect |
|----------|--------|---------|--------|
| `HYP_STEERING` | `max` (default) / `strict` (default for `selftest`) | server, client | `max`: `alg2-propquery = ?provider=<ML-KEM provider>`, a preference; every group whose components exist (44 here); a component served by another provider is reported (`OK*`). `strict`: `provider=` pin; only groups whose second component that provider serves (10 here), and every component must come from its pinned provider. |
| `HYP_MLKEM_PROVIDER` | `wolfprov` (default) / `default` | server, client | which provider `alg2` names (any provider in `component-providers` that serves ML-KEM). If `wolfprov` and its module is missing, it falls back to `default` and drops `wolfprov` from `component-providers`. The oqsprovider build here has no standalone ML-KEM, so `oqsprovider` would offer no ML-KEM groups. |
| `HYP_SERVER_GROUPS` | group list (`:` or space separated) | server | offer exactly these instead of the derived list |
| `HYP_PORT` | port (default `4433`) | server, client | listen / connect port |
| `HYP_OQS_PORT` | port (default `4434`), `0` = off | server, `interop.sh` | the second nginx, under the stock cnf, where oqsprovider serves its own hybrids (see [Interop with oqsprovider's own hybrids](#interop-with-oqsproviders-own-hybrids)) |
| `HYP_HOST` | host (default `127.0.0.1`) | client | server to connect to; the certificate is verified as `localhost` |
| `HYBRID_LOG` | `ops` (set by the entrypoint) | server | the hybrid provider's per-operation log that `connect.sh` reads; keep `ops` in it |

A client in another container must use the same `HYP_STEERING` /
`HYP_MLKEM_PROVIDER` as the server, so that it can offer the same groups:

```sh
docker run --rm --network container:hyp hyp-3alg connect.sh
```

## Exploring interactively

```sh
docker exec -it hyp bash            # into the running server container
docker run --rm -it hyp-3alg bash   # or a fresh one without a server
```

| path | what |
|------|------|
| `/opt/pq` | the shared OpenSSL install (prefix); `bin/openssl`, `bin/curl` |
| `/opt/pq/lib64/ossl-modules` | provider modules: `hybrid.so`, `oqsprovider.so`, `wolfprov.so` |
| `/opt/pq/ssl/openssl.cnf` | the hybrid config as shipped (also `OPENSSL_CONF`) |
| `/tmp/hyp/openssl-active.cnf` | the config in use, after `HYP_STEERING` / `HYP_MLKEM_PROVIDER` |
| `/tmp/hyp/server-groups`, `/tmp/hyp/nginx.conf` | the offered groups and the generated nginx config |
| `/tmp/hyp/oqs-server-groups`, `/tmp/hyp/nginx-oqs.conf` | the same for the oqsprovider interop server (port 4434) |
| `/opt/pq/ssl/openssl-stock.cnf` | the stock baseline (for the diff) |
| `/opt/pq/demo/` | demo CA + server cert/key (classical ECDSA P-256) |
| `/opt/nginx` | nginx prefix; `conf/nginx-demo.conf` is the template |

```sh
export OPENSSL_CONF=/tmp/hyp/openssl-active.cnf
openssl list -providers
openssl s_client -connect 127.0.0.1:4433 -groups HQCKEM192MLKEM768X25519 \
    -CAfile /opt/pq/demo/CA.crt -tls1_3
curl -v --curves HQCKEM192MLKEM768X25519 --cacert /opt/pq/demo/CA.crt https://localhost:4433/
```

## Interop with oqsprovider's own hybrids

The image also runs a **second nginx on port 4434 under the stock cnf**: default
plus oqsprovider, no hybrid provider, so there oqsprovider serves its own hybrid
groups. It offers the groups both stacks serve, derived at start (e.g. 38 by
default and 8 with `HYP_STEERING=strict`, in an image built against `main`). `interop.sh` connects with
curl in all four pairings, offering one group at a time:

```sh
docker run -d --name hyp -p 4433:4433 -p 4434:4434 hyp-3alg
docker exec hyp interop.sh                         # every shared group
docker exec hyp interop.sh p384_hqc3 x25519_mlkem512   # or just some

docker run --rm hyp-3alg interop   # one-shot, exits with the result
```

```
group                    hyb>hyb   hyb>oqs   oqs>hyb   oqs>oqs
p384_hqc3                OK        OK        OK        OK
x25519_mlkem512          OK        OK        OK        OK
```

`hyb` is the hybrid cnf (the hybrid provider serves the group), `oqs` the stock
cnf (oqsprovider serves it); columns are client>server. `hyb>hyb` and `oqs>oqs`
are baselines; `hyb>oqs` and `oqs>hyb` show that the two implementations of the
same group name are interchangeable on the wire. Each OK also checks that the
hybrid provider ran on exactly the `hyb` sides (its `HYBRID_LOG=ops` lines), and
that the serving nginx logged the request.

Switching stacks is only a different `OPENSSL_CONF`; curl and nginx are
unchanged:

```sh
# client on the hybrid provider, server on oqsprovider
OPENSSL_CONF=/tmp/hyp/openssl-active.cnf curl --curves p384_hqc3 \
    --cacert /opt/pq/demo/CA.crt https://localhost:4434/
# client on oqsprovider, server on the hybrid provider
OPENSSL_CONF=/opt/pq/ssl/openssl-stock.cnf curl --curves p384_hqc3 \
    --cacert /opt/pq/demo/CA.crt https://localhost:4433/
```

`n/a` means oqsprovider cannot negotiate the group even with itself (its
`oqs>oqs` baseline fails), so its pairings can't be judged. Typically it lists
the group but does not enable it for TLS: `openssl list -tls-groups` shows
implemented groups, not negotiable ones (e.g. the BIKE-L1 hybrids in
oqsprovider 0.12.0). `n/a` is not a failure; a failing `hyb>hyb` always is.

A failing cross pairing (`hyb>oqs`, `oqs>hyb`) with both baselines OK usually
means the two stacks assign **different TLS code points** to the same name:
each server then sees a key share it doesn't recognize (`no suitable key share`
in its log).

Which liboqs and oqsprovider the image contains is a build choice
(`UPSTREAM`, see [README.md](README.md#build)), and `interop.sh`
prints it first (from `/opt/pq/demo/upstream.txt`):

- **`release`** (default): the latest release pair known to match this
  provider's catalogue. Every shared group should pass in all four pairings.
- **`main`**: both main branches. Failing cross pairings then show what the
  next oqsprovider release will change, before it ships.

## Changing the provider split

The split is pure configuration. Edit the `alg*-propquery` lines in
`/opt/pq/ssl/openssl.cnf` (or mount your own over it) to re-route a component
slot to any loaded provider, e.g. `alg2-propquery = provider=default` sources the
second component from the default provider. The providers available to the
components are those listed in `component-providers` (loaded into the hybrid
provider's private context). No rebuild is needed.

The strict form `provider=<name>` makes a group disappear when that
provider cannot serve its component. The preference form `?provider=<name>`
falls back silently to any provider that has the component, so the cnf no
longer pins which provider served it (`HYP_STEERING=max`, the default).

## The scripts

| script | when it runs | what it does |
|--------|--------------|--------------|
| `entrypoint.sh` | container entrypoint | `server` (default): builds the active config, derives the group list, runs nginx in the foreground, plus the oqsprovider interop nginx on `HYP_OQS_PORT` in the background. `selftest`: server in the background plus `connect.sh`, exit with its result. `interop`: both servers in the background plus `interop.sh`, exit with its result. Anything else is run as given (`noconf.sh`, `bash`, …). |
| `connect.sh` | `docker exec <container> connect.sh [GROUP...]` | client validation as described above |
| `interop.sh` | `docker exec <container> interop.sh [GROUP...]` | the four-pairing interop check against oqsprovider's own hybrids (see [Interop with oqsprovider's own hybrids](#interop-with-oqsproviders-own-hybrids)) |
| `hyp-env.sh` | sourced by both | shared paths, the active config, and the group derivation |
| `noconf.sh` | `docker run --rm hyp-3alg noconf.sh` | removes `openssl.cnf`, then asserts what each tool can still do with command-line provider activation alone (see [Without openssl.cnf](#without-opensslcnf)) |
| `build-wolfprovider-lean.sh` | **build time only** | compiles wolfSSL + wolfProvider against the shared OpenSSL and asserts the pinned wolfSSL flags against wolfProvider upstream (not used at run time) |

## Without openssl.cnf

```sh
docker run --rm hyp-3alg noconf.sh
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

- The HQC groups' TLS code points (e.g. `0xfe44` for `HQCKEM192MLKEM768X25519`)
  are **provisional / private-use** (draft-preussmattsson), not IANA assignments:
  fine for this closed client+server setup, not for interop with other stacks.
- The server certificate is a throwaway classical ECDSA P-256 cert; the KEM group
  is independent of the certificate signature algorithm.
- This image is for demonstration and validation only.
