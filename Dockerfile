# Build the tiny stdlib-only public DoH guard, then add it to the pinned Blocky image.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.23 AS guard-build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src
COPY doh-gateway/guard.go doh-gateway/guard_test.go ./

# GOTOOLCHAIN=local keeps the build on the pinned toolchain (no network download).
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

RUN go test -count=1 ./guard.go ./guard_test.go
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags='-s -w' -o /guard ./guard.go

# Pin the Blocky runtime to the reviewed v0.35.0 release.
FROM spx01/blocky:v0.35.0

COPY config.yml /app/config.yml
COPY --from=guard-build /guard /app/guard

# Tuned for SnapDeploy's 512 MB RAM / 0.25 vCPU instance. The two heap targets
# (48 + 320 MiB) are soft limits that leave ~140 MiB of the 512 MB for stacks,
# native memory, buffers and the container itself.
#   GUARD_RATE / GUARD_BURST   per-client sustained req/s and burst (real client
#                              taken from GUARD_CLIENT_IP_HEADER behind the proxy)
#   GUARD_CLIENT_IP_HEADER     forwarding header honoured only when the TCP peer
#                              is a private/loopback/CGNAT address (the platform
#                              proxy); public peers can never spoof it
ENV GUARD_RATE=10 \
    GUARD_BURST=100 \
    GUARD_CLIENT_IP_HEADER=X-Forwarded-For \
    GUARD_MAX_GLOBAL_CONNS=512 \
    GUARD_MAX_IP_CONNS=16 \
    GUARD_MAX_IP_STATES=16384 \
    GUARD_MAX_CONCURRENT_REQS=64 \
    GUARD_MAX_QUERIES_PER_CONN=1024 \
    GUARD_IDLE_TIMEOUT=60s \
    GOMAXPROCS=1 \
    GOMEMLIMIT=48MiB \
    BLOCKY_GOMEMLIMIT=320MiB

# SnapDeploy exposes only the guarded public DoH listener.
EXPOSE 4001

# The guard launches Blocky on loopback and owns the public listener.
ENTRYPOINT ["/app/guard"]

# Preserve a lightweight DNS-only healthcheck against Blocky's loopback resolver.
HEALTHCHECK --start-period=1m --timeout=3s CMD ["/app/guard", "healthcheck"]
