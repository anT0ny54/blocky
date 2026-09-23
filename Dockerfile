# Build the tiny stdlib-only public DoH guard, then add it to the pinned Blocky image.
FROM --platform=$BUILDPLATFORM golang:1.26.2-alpine AS guard-build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src
COPY doh-gateway/guard.go doh-gateway/guard_test.go ./

ENV CGO_ENABLED=0
ENV GO111MODULE=off

RUN go test ./guard.go ./guard_test.go
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags='-s -w' -o /guard ./guard.go

# Pin the Blocky runtime to the reviewed v0.35.0 release.
FROM spx01/blocky:v0.35.0

COPY config.yml /app/config.yml
COPY --from=guard-build /guard /app/guard

# SnapDeploy exposes only the guarded public DoH listener.
EXPOSE 4001

# The guard launches Blocky on loopback and owns the public listener.
ENTRYPOINT ["/app/guard"]

# Align the public guard with the MosDNS reference values.
ENV GUARD_RATE=15 \
    GUARD_BURST=40 \
    GUARD_MAX_GLOBAL_CONNS=160 \
    GUARD_MAX_IP_CONNS=24 \
    GUARD_MAX_DNS_MESSAGE=4096 \
    GUARD_IDLE_TIMEOUT=120s

# Preserve a lightweight DNS-only healthcheck against Blocky's loopback resolver.
HEALTHCHECK --start-period=1m --timeout=3s CMD ["/app/guard", "healthcheck"]
