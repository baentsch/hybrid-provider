# =============================================================================
# hybrid-provider downstream proof: curl <-> nginx TLS 1.3 handshake over the
# draft-preussmattsson 3-component group HQCKEM192MLKEM768X25519 (0xfe44),
# with each component sourced from a DIFFERENT provider:
#
#     X25519      <- OpenSSL default provider
#     ML-KEM-768  <- wolfProvider
#     HQC-192     <- oqsprovider
#
# composed by hybrid-provider through nothing but openssl.cnf.
#
# This file is intentionally kept as close as possible to the upstream
# open-quantum-safe/oqs-demos "nginx" and "curl" Dockerfiles. Blocks taken
# verbatim (modulo the version pins below) are marked
#     ### === oqs-demos ===
# and the hybrid-provider delta is marked
#     ### +++ ADDED: hybrid-provider demo +++
# so a reviewer can confirm the functional change is confined to config.
#
# Build (context = repo root):   docker build -f integrations/curl-nginx-3alg/Dockerfile -t hyp-3alg .
#   against liboqs/oqsprovider main instead of their latest matching releases:
#                                docker build --build-arg UPSTREAM=main -f ... -t hyp-3alg-main .
# Run the proof:                 docker run --rm hyp-3alg
# =============================================================================

ARG ALPINE_VERSION=3.21

### === oqs-demos: version ARGs ===
# Pins changed from the oqs-demos defaults, with reasons:
#  * OPENSSL 3.6.x  : one build known-good for ALL providers. wolfProvider
#                     requires >= 3.6.0 for its ML-KEM (PQC) support; 3.6 also
#                     gives the default provider native X25519 + ML-KEM.
#  * liboqs/oqsprovider: UPSTREAM picks the pair (see below). Both choices
#                     register the *standalone* HQC KEM under the level name
#                     `hqc3` (enable_kem) that the 3-alg group composes
#                     (liboqs >= 0.16.0, oqsprovider >= 0.12.0, oqs-provider #787).
ARG OPENSSL_TAG=openssl-3.6.5
### +++ ADDED: which liboqs/oqsprovider to build +++
#   UPSTREAM=release (default)  the latest release pair known to match this
#                               provider's algorithm catalogue (names, OIDs,
#                               TLS code points): interop.sh should pass.
#   UPSTREAM=main               both main branches: shows what the next
#                               releases will change, e.g. moved code points
#                               (interop.sh then flags the affected groups).
# LIBOQS_TAG / OQSPROVIDER_TAG, if set, override the pick for that component.
ARG UPSTREAM=release
ARG LIBOQS_RELEASE=0.16.0
ARG OQSPROVIDER_RELEASE=0.12.0
ARG LIBOQS_TAG=
ARG OQSPROVIDER_TAG=
ARG NGINX_VERSION=1.28.0
ARG CURL_VERSION=8.14.0
### +++ ADDED: wolfProvider (supplies the ML-KEM-768 component) +++
ARG WOLFPROVIDER_TAG=master

### +++ ADDED (opt-in, OFF by default): build OpenSSL with OSSL_TRACE support so
### a handshake can be traced down to each per-component EVP fetch/provider.
### Enable with:  docker build --build-arg ENABLE_TRACE=1 ...  +++
ARG ENABLE_TRACE=0

ARG INSTALLDIR=/opt/pq
ARG NGINX_PREFIX=/opt/nginx

# -----------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS builder
ARG OPENSSL_TAG
ARG UPSTREAM
ARG LIBOQS_RELEASE
ARG OQSPROVIDER_RELEASE
ARG LIBOQS_TAG
ARG OQSPROVIDER_TAG
ARG NGINX_VERSION
ARG CURL_VERSION
ARG WOLFPROVIDER_TAG
ARG ENABLE_TRACE
ARG INSTALLDIR
ARG NGINX_PREFIX

### === oqs-demos: build toolchain (+ bash/perl/linux-headers for wolfSSL) ===
RUN apk update && apk --no-cache add \
    build-base linux-headers libtool automake autoconf make cmake ninja \
    git wget pcre2-dev perl bash

ENV MODULES=${INSTALLDIR}/lib64/ossl-modules
ENV PATH=${INSTALLDIR}/bin:${PATH}

### === oqs-demos: fetch sources (ADDED: liboqs/oqsprovider refs from UPSTREAM,
### recorded in ${INSTALLDIR}/demo/upstream.txt for interop.sh to report) ===
WORKDIR /opt
RUN case "${UPSTREAM}" in \
        release) L="${LIBOQS_TAG:-${LIBOQS_RELEASE}}"; O="${OQSPROVIDER_TAG:-${OQSPROVIDER_RELEASE}}" ;; \
        main)    L="${LIBOQS_TAG:-main}";              O="${OQSPROVIDER_TAG:-main}" ;; \
        *)       echo "UPSTREAM must be 'release' or 'main' (got '${UPSTREAM}')" >&2; exit 1 ;; \
    esac && \
    git clone --depth 1 --branch ${OPENSSL_TAG}      https://github.com/openssl/openssl.git && \
    git clone --depth 1 --branch "$L"                https://github.com/open-quantum-safe/liboqs && \
    git clone --depth 1 --branch "$O"                https://github.com/open-quantum-safe/oqs-provider.git && \
    mkdir -p ${INSTALLDIR}/demo && \
    printf 'UPSTREAM=%s\nliboqs=%s (%s)\noqsprovider=%s (%s)\nopenssl=%s\n' \
        "${UPSTREAM}" "$L" "$(git -C liboqs rev-parse --short HEAD)" \
        "$O" "$(git -C oqs-provider rev-parse --short HEAD)" "${OPENSSL_TAG}" \
        >${INSTALLDIR}/demo/upstream.txt && \
    wget -q nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && tar -zxf nginx-${NGINX_VERSION}.tar.gz && rm nginx-${NGINX_VERSION}.tar.gz && \
    wget -q https://curl.se/download/curl-${CURL_VERSION}.tar.gz && tar -zxf curl-${CURL_VERSION}.tar.gz && rm curl-${CURL_VERSION}.tar.gz

### +++ ADDED: build ONE shared OpenSSL install that every provider links +++
# (the oqs-demos nginx Dockerfile builds OpenSSL *inside* nginx via
# --with-openssl; we install it once, shared, so nginx, curl and all three
# provider modules share a single libcrypto — the prerequisite for loading
# providers into downstream apps.)
WORKDIR /opt/openssl
RUN LDFLAGS="-Wl,-rpath,${INSTALLDIR}/lib64" \
    ./config shared $( [ "${ENABLE_TRACE}" = "1" ] && echo enable-trace ) --prefix=${INSTALLDIR} && \
    make -j"$(nproc)" && make install_sw install_ssldirs && \
    { [ -d ${INSTALLDIR}/lib64 ] || ln -s lib ${INSTALLDIR}/lib64 ; } && \
    { [ -d ${INSTALLDIR}/lib ]   || ln -s lib64 ${INSTALLDIR}/lib ; }

### === oqs-demos: liboqs (ADDED: -DOQS_ENABLE_KEM_HQC=ON for HQC) ===
WORKDIR /opt/liboqs/build
RUN cmake -G"Ninja" \
    -DOQS_DIST_BUILD=ON \
    -DBUILD_SHARED_LIBS=OFF \
    -DOQS_ENABLE_KEM_HQC=ON \
    -DCMAKE_INSTALL_PREFIX="${INSTALLDIR}" .. && \
    ninja -j"$(nproc)" && ninja install

### === oqs-demos: oqs-provider ===
WORKDIR /opt/oqs-provider
RUN cmake -DCMAKE_BUILD_TYPE=Release \
          -DOPENSSL_ROOT_DIR="${INSTALLDIR}" \
          -DCMAKE_PREFIX_PATH="${INSTALLDIR}" \
          -S . -B build && \
    cmake --build build && \
    cp build/lib/oqsprovider.so "${MODULES}/"

### +++ ADDED: wolfProvider (ML-KEM-768 source), LEAN build against the one
### shared OpenSSL — no second OpenSSL compile. The helper pins wolfSSL's
### configure flags/tag and asserts them against wolfProvider's own build script
### (fails the build on upstream drift). The provider registers under the name
### "wolfprov"; OSSL_PROVIDER_load looks for "wolfprov.so", so we symlink it. +++
COPY integrations/curl-nginx-3alg/build-wolfprovider-lean.sh /tmp/build-wolfprovider-lean.sh
RUN WOLFPROVIDER_TAG="${WOLFPROVIDER_TAG}" INSTALLDIR="${INSTALLDIR}" MODULES="${MODULES}" \
        bash /tmp/build-wolfprovider-lean.sh

### +++ ADDED: hybrid-provider (the composer) built from this repo's sources +++
COPY . /opt/hybrid-provider
WORKDIR /opt/hybrid-provider
RUN cmake -S . -B build-docker -DOPENSSL_ROOT_DIR="${INSTALLDIR}" && \
    cmake --build build-docker --target hybrid-provider -j"$(nproc)" && \
    cp build-docker/hybrid.so "${MODULES}/"

### === oqs-demos (curl Dockerfile): build curl against the shared OpenSSL ===
WORKDIR /opt/curl-${CURL_VERSION}
RUN env LDFLAGS="-Wl,-rpath,${INSTALLDIR}/lib64" \
        ./configure --prefix="${INSTALLDIR}" \
                    --with-ssl="${INSTALLDIR}" \
                    --without-libpsl && \
    make -j"$(nproc)" && make install

### === oqs-demos (nginx Dockerfile): build nginx with SSL ===
# ADDED vs oqs-demos: link the *shared* OpenSSL (--with-cc-opt/--with-ld-opt)
# instead of --with-openssl, so nginx uses the same libcrypto the providers do.
WORKDIR /opt/nginx-${NGINX_VERSION}
RUN ./configure --prefix="${NGINX_PREFIX}" \
        --with-http_ssl_module --with-debug --without-http_gzip_module \
        --with-cc-opt="-I${INSTALLDIR}/include" \
        --with-ld-opt="-L${INSTALLDIR}/lib64 -Wl,-rpath,${INSTALLDIR}/lib64" && \
    make -j"$(nproc)" && make install

### +++ ADDED: classical ECDSA P-256 CA + server cert (KEM group is independent
### of the cert signature algorithm, so no PQ-sig wiring is needed) +++
WORKDIR ${INSTALLDIR}/demo
RUN OPENSSL_CONF=/dev/null openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout CA.key -out CA.crt -nodes -days 3650 -subj "/CN=hp-demo-ca" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" && \
    OPENSSL_CONF=/dev/null openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout server.key -out server.csr -nodes -subj "/CN=localhost" && \
    printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > ext.cnf && \
    OPENSSL_CONF=/dev/null openssl x509 -req -in server.csr -CA CA.crt -CAkey CA.key \
        -CAcreateserial -out server.crt -days 3650 -extfile ext.cnf && \
    rm -f server.csr ext.cnf

### +++ ADDED: install the demo configs (the ONLY functional difference between
### a stock oqs-demos stack and this one lives in openssl.cnf) +++
COPY integrations/curl-nginx-3alg/openssl.cnf        ${INSTALLDIR}/ssl/openssl.cnf
COPY integrations/curl-nginx-3alg/openssl-stock.cnf  ${INSTALLDIR}/ssl/openssl-stock.cnf
COPY integrations/curl-nginx-3alg/nginx.conf         ${NGINX_PREFIX}/conf/nginx-demo.conf
### +++ ADDED: long-running server (entrypoint.sh) + client validator
### (connect.sh), sharing paths/config via hyp-env.sh +++
COPY integrations/curl-nginx-3alg/hyp-env.sh          ${INSTALLDIR}/bin/hyp-env.sh
COPY integrations/curl-nginx-3alg/entrypoint.sh      ${INSTALLDIR}/bin/entrypoint.sh
COPY integrations/curl-nginx-3alg/connect.sh         ${INSTALLDIR}/bin/connect.sh
### +++ ADDED: interop with oqsprovider's own hybrids (second nginx, interop.sh) +++
COPY integrations/curl-nginx-3alg/interop.sh         ${INSTALLDIR}/bin/interop.sh
### +++ ADDED (opt-in): what works WITHOUT openssl.cnf (`docker run … noconf.sh`) +++
COPY integrations/curl-nginx-3alg/noconf.sh          ${INSTALLDIR}/bin/noconf.sh
RUN chmod +x ${INSTALLDIR}/bin/entrypoint.sh ${INSTALLDIR}/bin/connect.sh ${INSTALLDIR}/bin/interop.sh ${INSTALLDIR}/bin/noconf.sh

# -----------------------------------------------------------------------------
### +++ ADDED: drop static libraries before the runtime stage copies the
### install tree; nothing links against them after this point:
###   liboqs.a              oqsprovider links it statically, so nothing loads
###                         it at run time (40-70 MB depending on UPSTREAM)
###   libcrypto.a, libssl.a everything here links the shared OpenSSL (~14 MB)
###   libcurl.a             the curl binary is already built +++
RUN for l in liboqs.a libcrypto.a libssl.a libcurl.a; do \
        rm -f "${INSTALLDIR}/lib/$l" "${INSTALLDIR}/lib64/$l"; \
    done

### === oqs-demos: slim runtime stage ===
FROM alpine:${ALPINE_VERSION}
ARG INSTALLDIR
ARG NGINX_PREFIX
RUN apk update && apk --no-cache add pcre2 bash

COPY --from=builder ${INSTALLDIR}   ${INSTALLDIR}
COPY --from=builder ${NGINX_PREFIX} ${NGINX_PREFIX}

ENV INSTALLDIR=${INSTALLDIR}
ENV NGINX_PREFIX=${NGINX_PREFIX}
ENV PATH=${INSTALLDIR}/bin:${NGINX_PREFIX}/sbin:${PATH}
ENV LD_LIBRARY_PATH=${INSTALLDIR}/lib64
# nginx (built --with-openssl replacement) needs OPENSSL_CONF set explicitly.
ENV OPENSSL_CONF=${INSTALLDIR}/ssl/openssl.cnf

EXPOSE 4433 4434
# server (default): nginx in the foreground (+ the oqsprovider interop server
# on 4434); selftest: one-shot CI run; interop: one-shot interop.sh run;
# any other command (noconf.sh, bash, ...) is run as given.
ENTRYPOINT ["entrypoint.sh"]
CMD ["server"]
