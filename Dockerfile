# Build the tiny stdlib-only public DoH guard, then add it to the pinned Blocky image.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.23 AS guard-build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src
COPY doh-gateway/guard.go doh-gateway/guard_test.go ./

ENV CGO_ENABLED=0

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

# Keep the public guard conservative for the 0.25 vCPU deployment.
ENV GUARD_RATE=1.6666667 \
    GUARD_BURST=80 \
    GUARD_MAX_GLOBAL_CONNS=64 \
    GUARD_MAX_IP_CONNS=16 \
    GUARD_MAX_IP_STATES=4096 \
    GUARD_MAX_CONCURRENT_REQS=32 \
    GUARD_MAX_DNS_MESSAGE=4096 \
    GUARD_MAX_RESPONSE_BYTES=4096 \
    GUARD_MAX_QUERIES_PER_CONN=256 \
    GUARD_IDLE_TIMEOUT=120s \
    GOMEMLIMIT=80MiB \
    BLOCKY_GOMEMLIMIT=288MiB

# Preserve a lightweight DNS-only healthcheck against Blocky's loopback resolver.
HEALTHCHECK --start-period=1m --timeout=3s CMD ["/app/guard", "healthcheck"]
