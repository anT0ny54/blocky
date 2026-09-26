# Blocky for SnapDeploy

A small public DNS-over-HTTPS (DoH) service built around Blocky and a lightweight Go gateway, tuned for a **512 MB RAM / 0.25 vCPU** SnapDeploy instance. The public surface is DoH-only; Blocky's DNS/HTTP listeners remain loopback-only.

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

The gateway accepts only RFC 8484-style `GET` and `POST` requests on `/dns-query`. `GET /healthz` and `HEAD /healthz` perform a cheap TCP reachability check against Blocky's loopback HTTP listener; `GET /` remains a static wake/readiness compatibility response. The gateway validates DoH body size and content type, enforces accept-time connection and bounded in-flight concurrency, forwards only the normalized DNS request to Blocky over loopback, validates successful DNS responses, buffers and length-normalizes the response, and never follows backend redirects.

## Resource profile

The public guard deliberately has **no token bucket or request-rate limiter**. Abuse protection is instead bounded by connections, concurrent work, per-client concurrent work, request size, response size, keep-alive reuse, backend deadlines, and a bounded source-state table.

| Setting | Default | Purpose |
| :--- | ---: | :--- |
| `GLOBAL_CONN_LIMIT` | `256` | Accept-time aggregate TCP connection ceiling; enough headroom for many client IPs while request work remains bounded |
| `IP_CONN_LIMIT` | `64` | Per-source concurrent connection ceiling; shared clients behind one public IP share this pool |
| `DOH_MAX_BODY_BYTES` | `4096` | Maximum decoded DoH DNS request size for GET/POST |
| `UPSTREAM_MAX_CONNS` | `8` | Maximum simultaneous guard -> Blocky loopback connections |
| `SERVER_TIMEOUT` | `6s` | Blocky external-upstream query deadline (`upstreams.timeout`) |
| `GUARD_RESPONSE_TIMEOUT` | `8s` | Maximum time the public guard waits for Blocky before returning `502` |
| `GUARD_MAX_CONCURRENT_REQS` | `16` | Aggregate in-flight work ceiling; backend traffic is still bounded by 8 loopback connections |
| `GUARD_MAX_CONCURRENT_REQS_PER_IP` | `8` | Per-client in-flight work ceiling |
| `GUARD_MAX_IP_STATES` | `512` | Bounded source-state slots; normalized to at most 2× the global connection limit and 65,535 |
| `GUARD_MAX_QUERIES_PER_CONN` | `1024` | Keep-alive reuse ceiling; the final allowed query is answered, then the connection closes |
| `GUARD_MAX_RESPONSE_BYTES` | `65535` (code) | Maximum buffered DoH response body |
| `GUARD_BACKEND_DIAL_TIMEOUT` | `1s` | Loopback backend dial deadline; also used by `/healthz` |
| `GUARD_IDLE_TIMEOUT` | `60s` | Public HTTP idle connection timeout |
| `GOMAXPROCS` | `1` | Matches the 0.25 vCPU allocation |
| `GOMEMLIMIT` | `64MiB` | Soft Go heap target for the public guard |
| `BLOCKY_GOMEMLIMIT` | `288MiB` | Soft Go heap target for Blocky |
| `caching.maxItemsCount` | `8192` | Bounded DNS cache entry count |
| `caching.prefetching` | `false` | Avoids extra upstream traffic and cache churn |

`GOMEMLIMIT` is a soft Go runtime heap target, not a hard container-memory cap. The combined 352 MiB heap targets leave roughly 160 MiB for stacks, runtime/native memory, buffers, the filesystem, and the container environment. The supervisor explicitly replaces inherited `GOMEMLIMIT`/`GOMAXPROCS` values for the Blocky child so Blocky receives its intended 288 MiB / 1-CPU profile.

There is deliberately no second per-request token bucket in the application. On the shared `containers.snapdeploy.app` domain, SnapDeploy itself limits one source IP to 100 requests/minute and blocks higher-volume clients for 10 minutes; the guard therefore focuses on bounded concurrency and memory instead of duplicating that edge rate limiter. The 256-connection ceiling, 512-state table, 16-request aggregate ceiling, 8-request per-source ceiling, and 8-connection backend pool provide room for many source IPs without letting a single slow upstream workload consume the entire container. [SnapDeploy FAQ](https://snapdeploy.dev/docs/faq) and [Scaling](https://snapdeploy.dev/docs/scaling)

Rejected direct-client policy/validation requests are disconnected rather than answered, while a trusted platform proxy receives explicit `400`, `404`, `429`, `502`, or health `503` status codes. A normal client disconnect is not treated as an upstream failure; backend timeouts, invalid DNS responses, oversized responses, and premature backend termination become explicit `502 Bad Gateway` responses.

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

Blocky's `random` upstream strategy selects one resolver per query and can retry with another on failure, preserving failover while keeping exactly the three configured HaGeZi upstreams. The Blocky-side upstream deadline is **6 seconds**, while the public guard allows up to **8 seconds** for Blocky to return and validate the final response.

The container healthcheck queries only `127.0.0.1:5300`; that DNS listener is loopback-only.

## Forwarded client IP handling

Behind the SnapDeploy proxy, the TCP peer is expected to be an internal/private address. When `GUARD_CLIENT_IP_HEADER` is enabled, the guard parses the header from the right and uses the first public address it can certify from that trusted proxy chain. Client-injected entries on the left are therefore not selected; public peers cannot activate this header path. The connection/accounting key is only this trusted client identity (or the direct peer when no trusted forwarding header is present), so arbitrary `Host` values cannot create separate source state.

For HTTP/2/keep-alive traffic, a platform edge connection may carry many real users. Those users share the global socket budget but are separated for request accounting by the forwarded client IP. IPv6 client identities are grouped by `/64`.

The forwarded client address is used only for per-client concurrency accounting and the normalized loopback `X-Forwarded-For` header sent to Blocky. The source-state table uses 16 shards so the 512-entry default does not fragment into tiny four-entry buckets, avoiding avoidable rejection of otherwise admissible source IPs under a many-client workload.

## Health and failure behavior

The public health endpoint is `GET`/`HEAD /healthz`. It performs only a bounded TCP dial to Blocky's loopback HTTP listener and returns `200` when Blocky's listener is reachable, otherwise `503`. It has no separate rate bucket and still inherits the global accept-time connection ceiling. The container healthcheck separately probes Blocky's loopback DNS listener at `127.0.0.1:5300`.

## SnapDeploy deployment note

SnapDeploy's current Scaling documentation permits automated traffic on the shared domain but prohibits proxies, VPN panels, tunnels, and similar relay services. Because this project exposes a public DNS-over-HTTPS gateway, review the current SnapDeploy Terms/Acceptable Use Policy before deploying or publishing it. [SnapDeploy Scaling](https://snapdeploy.dev/docs/scaling)

The guard buffers successful DoH responses and validates DNS framing before writing `200 OK`. A prematurely terminated or malformed backend response therefore cannot escape as a truncated successful response.

Blocky v0.35.0 does not expose a per-cache-entry byte-size setting; `caching.maxItemsCount: 8192` is therefore the primary cache bound. The deployment does not claim a direct Blocky equivalent of a `CACHE_MAX_ENTRY_BYTES=4096` setting.

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
