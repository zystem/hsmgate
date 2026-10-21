# hsmgate with the OpenSC PKCS#11 module (a SmartCard-HSM through the host's pcscd). cgo is needed by the PKCS#11 binding, so the binary is dynamic.
# The final image is distroless: glibc, the CA certificates and nothing else (no shell, no package manager, none of the 97 packages of a Debian image that the service never uses);
# the OpenSC module and the libraries it needs are copied into it from a Debian stage. Base images are pinned by digest (Renovate updates them).
FROM golang:1.26.10-bookworm@sha256:ee3901c61e423732605a51f1b8157c849ec01194ea0a274213b5202b2c11e7bf AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# a position-independent executable with the relocations made at start and then read-only (ASLR for the whole program, no writable GOT)
RUN CGO_ENABLED=1 go build -buildmode=pie -trimpath -buildvcs=false -ldflags "-s -w -linkmode=external -extldflags '-Wl,-z,relro,-z,now' -X main.version=${VERSION}" -o /out/hsmgate ./cmd/hsmgate

# the module of OpenSC and what it needs (the PC/SC client library is loaded by OpenSC with dlopen, so ldd does not show it), with the same paths, into /rootfs;
# the core of glibc comes from the final image
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS libs
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# (the versions of the packages are not pinned on purpose: the base is pinned by digest, the packages are the current security updates of it)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends opensc-pkcs11 libpcsclite1 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /rootfs \
 && cp --parents -L /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 /rootfs/ \
 && for lib in $(ldd /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so /usr/lib/x86_64-linux-gnu/libpcsclite.so.1 | awk '/=>/ {print $3}' | sort -u); do \
      case "$lib" in */libc.so.6|*/libm.so.6|*/libdl.so.2|*/libpthread.so.0|*/librt.so.1) ;; *) cp --parents -L "$lib" /rootfs/ ;; esac; \
    done \
 && test -s /rootfs/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so && test -s /rootfs/usr/lib/x86_64-linux-gnu/libpcsclite.so.1 && test -n "$(find /rootfs -name 'libopensc.so*' -print -quit)" && test -n "$(find /rootfs -name 'libcrypto.so*' -print -quit)"

FROM gcr.io/distroless/base-debian12@sha256:7f0c72cd138b442ae0deeb69c08b1acf5525439ba251a49ad93c320a061567e5
COPY --from=libs /rootfs/ /
COPY --from=build /out/hsmgate /usr/local/bin/hsmgate
LABEL org.opencontainers.image.source="https://github.com/zystem/hsmgate" \
      org.opencontainers.image.description="hsmgate: a policy-checked network door in front of a key token (Transit API, optional KMS-JSON API)" \
      org.opencontainers.image.licenses="MIT"
USER 10001:10001
EXPOSE 8443
# a TCP connect to the listener: it never touches the token (a locked token is a state of the service, not a failure of the container)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/hsmgate", "ping", "-addr", "127.0.0.1:8443"]
ENTRYPOINT ["/usr/local/bin/hsmgate"]
CMD ["serve", "-config", "/etc/hsmgate/hsmgate.yaml"]
