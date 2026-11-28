# curl ↔ nginx: hybrid-provider as a drop-in for oqsprovider's hybrids

This Docker image runs released **curl** and **nginx** against two OpenSSL
configurations that differ only in `openssl.cnf`:

- **stock** (`openssl-stock.cnf`): default + oqsprovider. oqsprovider serves its
  own hybrid KEM groups, as in a normal OQS setup.
- **hybrid** (`openssl.cnf`): default + hybrid-provider. hybrid-provider serves
  the same group names, using oqsprovider (and others) only as component
  sources underneath.

`interop.sh` checks every group both configurations serve, in all four
client/server pairings, and shows that the two implementations are
interchangeable on the wire. The same image also composes one hybrid group from
three providers at once; see [THREE-PROVIDERS.md](THREE-PROVIDERS.md).

## Build

From the **repo root** (the image compiles hybrid-provider from the working tree):

```sh
docker build -f integrations/curl-nginx-3alg/Dockerfile -t hyp-3alg .
```

`UPSTREAM` picks which liboqs and oqsprovider to build:

| `UPSTREAM` | liboqs | oqsprovider | use |
|---|---|---|---|
| `release` (default) | 0.16.0 | 0.12.0 | the latest release pair known to match hybrid-provider's catalogue (names, OIDs, TLS code points): `interop.sh` should pass |
| `main` | `main` | `main` | preview of the next releases: `interop.sh` flags groups whose code points they change |

```sh
docker build --build-arg UPSTREAM=main -f integrations/curl-nginx-3alg/Dockerfile -t hyp-3alg-main .
```

The build needs Docker with BuildKit, network access, about 15 GB of free disk
for the build cache and roughly 10 minutes of CPU time: it compiles OpenSSL,
liboqs, wolfSSL, three providers, curl and nginx from source. The resulting
image is about 70 MB (release) or 85 MB (main). More build options are under
[Build details](#build-details).

## Try it

Start the container; it runs two nginx servers, one per configuration:

```sh
docker run -d --name hyp hyp-3alg
docker exec -it hyp bash
```

The shell opens with a short overview: which server runs on which port, the
command to see the config change, how to run the interop check, and links to
the docs. `demo-help` shows it again. You're the unprivileged user `demo`, who
also runs the servers; `docker exec -u root -it hyp bash` gives a root shell.

(By default the hybrid server offers every group hybrid-provider can compose,
including the Frodo, BIKE and HQC hybrids. `-e HYP_STEERING=strict` instead pins
components to specific providers, for the three-provider proof, and offers
fewer; see [THREE-PROVIDERS.md](THREE-PROVIDERS.md).)

### Where the configs are, and who uses which

| file in the image | config | source in this directory |
|---|---|---|
| `/opt/pq/ssl/openssl-stock.cnf` | **stock**: default + oqsprovider | `openssl-stock.cnf` |
| `/opt/pq/ssl/openssl.cnf` | **hybrid**, as shipped; also the image's default `OPENSSL_CONF` | `openssl.cnf` |
| `/tmp/hyp/openssl-active.cnf` | **hybrid, as in use**, written at container start: identical to `openssl.cnf` by default; with `HYP_STEERING=strict` it adds wolfProvider and the three-provider pins | (generated) |

| program | `OPENSSL_CONF` | serves / offers the hybrid groups via |
|---|---|---|
| nginx on port **4433** | `/tmp/hyp/openssl-active.cnf` | hybrid-provider |
| nginx on port **4434** | `/opt/pq/ssl/openssl-stock.cnf` | oqsprovider |
| curl in `interop.sh` | `openssl-active.cnf` for `hyb`, `openssl-stock.cnf` for `oqs`, per pairing | either |
| curl and `openssl s_client` in `connect.sh` | `/tmp/hyp/openssl-active.cnf` | hybrid-provider |
| curl, `openssl` typed in your shell | `/opt/pq/ssl/openssl.cnf`, unless you set it | hybrid-provider (same as the 4433 server, by default) |

The nginx configs the entrypoint generates are next to the active one:
`/tmp/hyp/nginx.conf` (4433) and `/tmp/hyp/nginx-oqs.conf` (4434).

**1. See the configuration difference.** It's the whole change:

```sh
diff -u /opt/pq/ssl/openssl-stock.cnf /opt/pq/ssl/openssl.cnf
```

```diff
 [prov_sect]
 default     = default_sect
-oqsprovider = pq_sect
+hybrid      = pq_sect

 [default_sect]
 activate = 1

 [pq_sect]
-module   = /opt/pq/lib64/ossl-modules/oqsprovider.so
+module   = /opt/pq/lib64/ossl-modules/hybrid.so
 activate = 1
+component-providers = default oqsprovider
+component-path      = /opt/pq/lib64/ossl-modules
```

Load `hybrid` instead of `oqsprovider`, and tell it which providers to take the
hybrids' components from. oqsprovider is still there, but only underneath, as
a component source; the application never sees it. The active config the
server uses is the same file (`diff -u /opt/pq/ssl/openssl-stock.cnf
/tmp/hyp/openssl-active.cnf` shows the same four lines).

**2. Run the interop check.**

```sh
interop.sh                          # every group both configs serve
interop.sh p384_hqc3 x448_mlkem768  # or just some
interop.sh -v p384_hqc3             # plus, per pairing, what each side used
```

```
built against: UPSTREAM=release liboqs=0.16.0 (5a1a854) oqsprovider=0.12.0 (7e9d095) openssl=openssl-3.6.5

group                    hyb>hyb   hyb>oqs   oqs>hyb   oqs>oqs
p384_hqc3                OK        OK        OK        OK
x448_mlkem768            OK        OK        OK        OK
...
RESULT: 146 OK, 0 FAIL (0 of them cross-implementation), 6 n/a of 152 handshakes
```

Columns are client>server: `hyb>hyb` and `oqs>oqs` are the baselines, the other
two are cross-implementation. Each OK also checks that hybrid-provider ran on
exactly the `hyb` sides. `n/a` means oqsprovider can't negotiate the group even
with itself (e.g. the BIKE-L1 hybrids in 0.12.0). With `-v`, each pairing
also shows, for client and server, the stack and config, the group that side
actually negotiated, and which provider served it:

```
           hyb>oqs client: hyb stack (openssl-active.cnf)  group=p384_hqc3  via hybrid-provider: EC:P-384@default hqc3@oqsprovider
                   server: oqs stack (openssl-stock.cnf, port 4434)  group=p384_hqc3  via oqsprovider (its own hybrid; no hybrid provider loaded)
```

More in
[USAGE.md](USAGE.md#interop-with-oqsproviders-own-hybrids).

**3. Switch stacks by hand.** Same curl, only `OPENSSL_CONF` changes:

```sh
# hybrid-provider client -> oqsprovider server
OPENSSL_CONF=/tmp/hyp/openssl-active.cnf curl --curves p384_hqc3 \
    --cacert /opt/pq/demo/CA.crt https://localhost:4434/
# oqsprovider client -> hybrid-provider server
OPENSSL_CONF=/opt/pq/ssl/openssl-stock.cnf curl --curves p384_hqc3 \
    --cacert /opt/pq/demo/CA.crt https://localhost:4433/
```

Each server answers with the group it negotiated, e.g.
`negotiated=p384_hqc3 protocol=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384`.

**4. Second source for ML-KEM: wolfProvider.** hybrid-provider takes each
component from whichever provider the config names, so the ML-KEM half doesn't
have to come from OpenSSL's default provider. `HYP_STEERING=wolfprov` adds two
lines to the active config:

```diff
-component-providers = default oqsprovider
+component-providers = default oqsprovider wolfprov
+alg2-propquery = ?provider=wolfprov
```

```sh
docker run -d --name hyp2 -e HYP_STEERING=wolfprov hyp-3alg
docker exec hyp2 interop.sh -v x25519_mlkem512 | grep 'hyb>oqs client'
#   ... via hybrid-provider: X25519@default MLKEM512@wolfprov
docker run --rm -e HYP_STEERING=wolfprov hyp-3alg interop    # one-shot: 146 OK, 0 FAIL
```

Every ML-KEM half is then served by wolfProvider, and the result against
oqsprovider is the same as by default (146 OK, 0 FAIL, 6 n/a on the release
build). `?provider=` is a preference: groups whose second component isn't
ML-KEM (Frodo, BIKE, HQC) take it from oqsprovider as before. Two limits in
this image, causes not yet determined:

- the default provider must stay in `component-providers`: without it,
  wolfProvider's ML-KEM can't be fetched in hybrid-provider's component context;
- preferring wolfProvider for the classical half as well (`alg1-propquery`)
  works for P-256/384/521, X25519 and X448, but makes the three brainpool
  hybrids fail.

Leave the shell and stop the containers with `docker rm -f hyp hyp2`.

Without a shell: `docker run --rm hyp-3alg interop` runs
the same check one-shot and exits with its result.

## Files

| file | purpose |
|------|---------|
| `Dockerfile` | multi-stage build: one shared OpenSSL, liboqs, oqsprovider, wolfProvider, hybrid-provider, curl, nginx |
| `openssl.cnf` / `openssl-stock.cnf` | the hybrid config and the stock baseline; their `diff` is the whole functional change |
| `nginx.conf` | nginx template; the entrypoint fills in the offered groups and port per server, and the response names the negotiated group |
| `entrypoint.sh` | container entrypoint: `server` (default, both nginx servers), `selftest` and `interop` (one-shot), or any other command |
| `interop.sh` | the four-pairing interop check against oqsprovider's own hybrids |
| `connect.sh` | per-group check against the hybrid server: negotiated group from four sources, plus which provider served each component on both ends |
| `hyp-env.sh` | shared paths, active config and group derivation for the scripts |
| `noconf.sh` | opt-in test: what still works with `openssl.cnf` removed (command-line activation only) |
| `demo-help` | the overview an interactive shell opens with: ports, the config diff command, how to run the checks, doc links |
| `shell-welcome.sh`, `profile-path.sh` | installed as `/etc/bash/hyp-welcome.sh` (prints `demo-help` once per interactive shell) and `/etc/profile.d/hyp-path.sh` (keeps the demo's `PATH` in login shells) |
| `build-wolfprovider-lean.sh` | build time only: lean wolfSSL + wolfProvider build and drift guard |
| [USAGE.md](USAGE.md) | reference: environment variables, scripts, output, interactive use |
| [THREE-PROVIDERS.md](THREE-PROVIDERS.md) | the three-provider group, wolfProvider build, version pins |

## Build details

All versions are `ARG`s at the top of the `Dockerfile` and can be overridden
with `--build-arg`, e.g. `--build-arg NGINX_VERSION=1.29.0`.

- **`UPSTREAM`** (above). `LIBOQS_TAG` / `OQSPROVIDER_TAG`, if set, override the
  pick for that component (any branch or tag). The refs actually built, with
  their commits, are recorded in the image at `/opt/pq/demo/upstream.txt`, and
  `interop.sh` prints them. When a new release pair is verified to match, bump
  `LIBOQS_RELEASE` / `OQSPROVIDER_RELEASE`.
- **`ENABLE_TRACE=1`** builds OpenSSL with tracing (`OPENSSL_TRACE=…`). Not
  needed to see which provider served a component: hybrid-provider logs that
  itself (`HYBRID_LOG=ops`).

  ```sh
  docker build -f integrations/curl-nginx-3alg/Dockerfile --build-arg ENABLE_TRACE=1 -t hyp-3alg-trace .
  ```

The `Dockerfile` is intentionally close to open-quantum-safe/oqs-demos' `nginx`
and `curl` Dockerfiles. Blocks are marked `### === oqs-demos ===` (kept) or
`### +++ ADDED: … +++` (the hybrid delta). The additions are one shared OpenSSL
install (so nginx, curl and all providers share a libcrypto), the wolfProvider
and hybrid-provider builds, and the demo configs and scripts. Static libraries
are left out of the runtime image. Version pins and their reasons are in
[THREE-PROVIDERS.md](THREE-PROVIDERS.md#version-pins).
