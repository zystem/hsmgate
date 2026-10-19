# hsmgate with the OpenSC PKCS#11 module (a SmartCard-HSM through pcscd). cgo is needed by the PKCS#11 binding, so the binary is dynamic.
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /out/hsmgate ./cmd/hsmgate

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends opensc-pkcs11 pcscd ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin hsmgate
COPY --from=build /out/hsmgate /usr/local/bin/hsmgate
USER 10001
ENTRYPOINT ["/usr/local/bin/hsmgate"]
CMD ["serve", "-config", "/etc/hsmgate/hsmgate.yaml"]
