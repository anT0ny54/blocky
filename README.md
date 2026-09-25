# Blocky for SnapDeploy

A small public DNS-over-HTTPS (DoH) service built around Blocky and a lightweight Go gateway, tuned for a **512 MB RAM / 0.25 vCPU** SnapDeploy instance.

## Runtime layout

```text
Internet / SnapDeploy proxy
          |
          v
   :4001  Go DoH guard
          |
          v
   127.0.0.1:4002  Blocky HTTP/DoH
          |
          +--> 127.0.0.1:5300  Blocky DNS healthcheck only
          |
          +--> 3 HaGeZi DoH upstreams
```

The runtime image is `spx01/blocky:v0.35.0`. Only port **4001** is public. Blocky's HTTP and DNS listeners are loopback-only and must not be published by the deployment.

The gateway accepts only `GET` and `POST` requests on `/dns-query` (plus a static `200` for `GET /` so platform wake/readiness probes succeed). It validates the DoH body size and content type, enforces connection and bounded in-flight request concurrency, forwards only the normalized DNS request to Blocky over loopback, validates successful DNS responses, buffers and length-normalizes the response, and never follows backend redirects.

## Resource profile

The public guard deliberately has **no token bucket or request-rate limiter**. Abuse protection is instead bounded by connections, concurrent work, per-client concurrent work, request size, response size, keep-alive reuse, backend deadlines, and a bounded source-state table.

| Setting | Default | Purpose |
| :--- | ---: | :--- |
| `GUARD_CLIENT_IP_HEADER` | `X-Forwarded-For` | Forwarding header honored only for internal/CGNAT peers; empty disables it |
| `IP_CONN_LIMIT` | `32` | Per-source concurrent connections for direct clients |
| `GUARD_MAX_GLOBAL_CONNS` | `512` | Aggregate connection ceiling |
| `GUARD_MAX_CONCURRENT_REQS` | `32` | Aggregate gateway/backend in-flight request ceiling |
| `GUARD_MAX_CONCURRENT_REQS_PER_IP` | `8` | Per-client in-flight request ceiling; IPv6 is grouped by `/64` |
| `GUARD_MAX_IP_STATES` | `16384` | Bounded source-state slots |
| `GUARD_MAX_QUERIES_PER_CONN` | `1024` | Keep-alive reuse ceiling; the last allowed query is answered, then the connection closes |
| `GUARD_MAX_DNS_MESSAGE` | `4096` (code) | Maximum DNS request wire size |
| `GUARD_MAX_RESPONSE_BYTES` | `65535` (code) | Maximum public DoH response body size |
| `SERVER_TIMEOUT` | `6` seconds | Guard-to-Blocky query deadline; accepts seconds or Go duration syntax |
| `GUARD_IDLE_TIMEOUT` | `60s` | Public HTTP idle connection timeout |
| `GOMAXPROCS` | `1` | Matches the 0.25 vCPU allocation |
| `GOMEMLIMIT` | `48MiB` | Go heap target for the guard |
| `BLOCKY_GOMEMLIMIT` | `320MiB` | Go heap target for Blocky |
| `caching.maxItemsCount` | `20000` | Bounded DNS cache entries |
| `caching.prefetching` | `false` | Avoids extra upstream traffic |

`GOMEMLIMIT` is a soft Go runtime heap target, not a hard container-memory cap. The combined 368 MiB heap targets leave headroom for stacks, native/runtime memory, buffers, the filesystem, and the container environment.

Rejected direct-client policy/validation requests are disconnected rather than answered, while the internal platform proxy receives explicit `400`, `404`, `429`, or `502` status codes. Backend failures are always explicit `502 Bad Gateway` responses.

## DNS path and leak prevention

Normal client DNS queries take this path only:

```text
client -> HTTPS -> SnapDeploy proxy -> Go guard -> loopback HTTP -> Blocky -> HTTPS -> HaGeZi
```

Blocky's public DNS/HTTP listeners are bound to `127.0.0.1`, so they are not directly reachable from the Internet. The only configured recursive upstreams are:

- `https://root.hagezi.org/dns-query`
- `https://wurzn.hagezi.org/dns-query`
- `https://juuri.hagezi.org/dns-query`

The bootstrap configuration resolves those three names over **DoH to their fixed published IPv4 addresses**, rather than using `/etc/resolv.conf`, Cloudflare, Google, or another unrelated plaintext resolver. This removes the previous bootstrap DNS path outside the intended upstream set.

Blocky's `random` upstream strategy selects one resolver per query and tries another on failure, preserving failover while keeping exactly the three configured HaGeZi upstreams.

The container healthcheck queries only `127.0.0.1:5300`; that DNS listener is loopback-only.

## Forwarded client IP handling

Behind the SnapDeploy proxy, the TCP peer is expected to be an internal address. When `GUARD_CLIENT_IP_HEADER` is enabled, the guard accepts the forwarding header only from such peers, parses it from the right, and selects the first public address. Client-injected entries on the left are therefore not used. Public peers cannot activate this header path.

The forwarded client address is used only for per-client concurrency accounting and the loopback `X-Forwarded-For` header sent to Blocky.

## Build

The guard is built as a CGO-free, stripped static binary on the build platform and copied into the pinned Blocky runtime image. The build stage uses an exact Go patch release.

```sh
docker buildx build --platform linux/amd64 -t blocky-snapdeploy .
```

For ARM builds, BuildKit supplies the target architecture and variant and the guard is cross-compiled without target-architecture emulation during the build step.

The standalone guard tests/build use the two source files directly, so a repository `go.mod` is not required.

## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not used in 15 minutes) |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not used in 15 minutes) |

## ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:

- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

## License

See [`LICENSE`](LICENSE).
