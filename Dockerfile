# syntax=docker/dockerfile:1.7

# ---- build ----
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod ./
# No external dependencies yet, so no go.sum.
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/frameio-relay \
    ./cmd/frameio-relay

# ---- runtime ----
# distroless/static provides ca-certificates and runs as uid 65532 (nonroot).
# No shell, no package manager, tiny attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/frameio-relay /usr/local/bin/frameio-relay

# Data volumes:
#   /data       persistent — tokens.json + relay-state.json (must be writable)
#   /downloads  persistent — downloaded media lives here
VOLUME ["/data", "/downloads"]

# Webhook receiver port. Frame.io posts to the public URL you put behind
# :9000 (Tailscale Funnel, Cloudflare Tunnel, etc).
EXPOSE 9000

ENTRYPOINT ["/usr/local/bin/frameio-relay"]
CMD [ \
  "-tokens=/data/tokens.json", \
  "-state=/data/relay-state.json", \
  "-out=/downloads", \
  "-webhook-addr=:9000", \
  "-poll=300s" \
]
