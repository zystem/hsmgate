# hsmgate with the OpenSC PKCS#11 module (a SmartCard-HSM through the host's pcscd). cgo is needed by the PKCS#11 binding, so the binary is dynamic.
# Base images are pinned by digest (Renovate updates them).
FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=${VERSION}" -o /out/hsmgate ./cmd/hsmgate

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# only the PKCS#11 module and the PC/SC client library (OpenSC loads libpcsclite with dlopen; it is only "recommended" by the package): pcscd runs on the host, its socket is mounted
RUN apt-get update && apt-get install -y --no-install-recommends opensc-pkcs11 libpcsclite1 ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin hsmgate
COPY --from=build /out/hsmgate /usr/local/bin/hsmgate
USER 10001:10001
EXPOSE 8443
# a TCP connect to the listener: it never touches the token (a locked token is a state of the service, not a failure of the container)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/hsmgate", "ping", "-addr", "127.0.0.1:8443"]
ENTRYPOINT ["/usr/local/bin/hsmgate"]
CMD ["serve", "-config", "/etc/hsmgate/hsmgate.yaml"]
