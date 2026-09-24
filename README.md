# Blocky for SnapDeploy

A small public DNS-over-HTTPS (DoH) service built around Blocky and a lightweight Go gateway, tuned for a **512 MB RAM / 0.25 vCPU** SnapDeploy instance.

## Runtime layout

The container runs two processes:

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
          +--> HaGeZi DoH upstreams (IPv4 egress)
```

The runtime image is `spx01/blocky:v0.35.0`. Only port **4001** is public. Blocky's HTTP and DNS listeners are loopback-only and must not be published by the deployment.

The gateway accepts only `GET` and `POST` requests on `/dns-query` (plus a static `200` for `GET /` so platform wake/readiness probes succeed), validates the DNS wire message size and content type, applies connection/request/rate limits, forwards to Blocky over loopback, validates successful DNS responses before returning them, and bounds the response body. Normal browser-side request cancellation is ignored rather than synthesized into an upstream failure.

## Resource and abuse-protection defaults

The public guard is the first layer before Blocky receives a query. The strict-DoH profile uses both a per-client token bucket and an aggregate global token bucket. Both are independent of the HTTP `Host` header, so changing `Host` cannot create another quota bucket.

Behind the SnapDeploy proxy every user connects from the proxy's internal address. When `GUARD_CLIENT_IP_HEADER` is set, the guard reads the real client from that header **only if the TCP peer is a private, loopback, link-local or CGNAT address**. It walks the header from the right and takes the first public address, so entries injected by a client on the left are never used. Public peers cannot spoof it, and a missing or malformed header falls back to the peer address. IPv6 clients are tracked per `/64`.

| Setting | Default | Purpose |
| :--- | ---: | :--- |
| `DOH_RATE_LIMIT` | `12` | Sustained requests per second per client |
| `DOH_RATE_BURST` | `200` | Burst capacity per client |
| `GLOBAL_RATE_LIMIT` | `80` | Aggregate sustained requests per second |
| `GLOBAL_RATE_BURST` | `200` | Aggregate burst capacity |
| `GUARD_CLIENT_IP_HEADER` | `X-Forwarded-For` (Dockerfile) | Forwarding header honoured for internal peers; empty disables |
| `IP_CONN_LIMIT` | `32` | Per-source concurrent connections (not applied to the internal proxy peer) |
| `GUARD_MAX_GLOBAL_CONNS` | `512` | Aggregate connection ceiling |
| `GUARD_MAX_CONCURRENT_REQS` | `64` | Gateway/backend concurrency ceiling |
| `GUARD_MAX_IP_STATES` | `16384` | Bounded client-state slots |
| `GUARD_MAX_QUERIES_PER_CONN` | `1024` | Keep-alive reuse ceiling; the last query is answered, then the connection closes |
| `GUARD_MAX_DNS_MESSAGE` | `4096` (code) | Maximum DNS request wire size |
| `GUARD_MAX_RESPONSE_BYTES` | `65535` (code) | Maximum public DoH response body size |
| `SERVER_TIMEOUT` | `6` seconds | Guard-to-Blocky query deadline; accepts seconds or Go duration syntax |
| `GUARD_IDLE_TIMEOUT` | `60s` | Public HTTP idle connection timeout |
| `GOMAXPROCS` | `1` | Matches the 0.25 vCPU allocation |
| `GOMEMLIMIT` | `48MiB` | Go heap target for the guard |
| `BLOCKY_GOMEMLIMIT` | `320MiB` | Go heap target for Blocky |
| `caching.maxItemsCount` | `20000` | Bounded DNS cache entries |
| `caching.prefetching` | `false` | Avoid extra upstream traffic |

For compatibility with older deployments, `GUARD_RATE`, `GUARD_BURST`, `GUARD_MAX_IP_CONNS`, and `GUARD_BACKEND_TIMEOUT` remain accepted as fallback environment names; the strict-DoH names above take precedence.

Refused requests are handled differently by peer type. A direct client is disconnected without a response for policy/rate/validation rejections. Backend failures (`502 Bad Gateway`) are explicit for both direct and proxied clients, so strict DoH clients can retry or report the lookup failure. The internal proxy receives normal status codes (`429` with `Retry-After`, `400`, `404`, or `502`) and keeps the connection.

`GOMEMLIMIT` is a soft Go runtime heap target, not a hard container-memory cap. The combined 368 MiB heap targets leave headroom for stacks, native/runtime memory, buffers, the filesystem, and the container environment.

Blocky's own resolver-chain rate limiter is disabled because the public guard already limits requests before the loopback hop. Keeping a second limiter there would apply a second quota to the gateway-to-Blocky connection instead of the original client.

If Blocky or the guard exits, the container exits non-zero so the platform restarts it.

## Blocky configuration

`config.yml` is the only Blocky configuration file. It uses Blocky's v0.35.0 schema modeline for editor validation.

The default upstream set is the three HaGeZi **Full Protection** DoH endpoints:

- `https://root.hagezi.org/dns-query`
- `https://wurzn.hagezi.org/dns-query`
- `https://juuri.hagezi.org/dns-query`

The three endpoints are configured with `random` upstream selection, IPv4-only outbound connections, and a 2-second Blocky upstream timeout. The guard's `SERVER_TIMEOUT=6` is the outer gateway-to-Blocky query deadline. This repository uses Blocky rather than MosDNS, so there is no MosDNS sequential-failover deadline or persisted MosDNS probe-state file in this archive.

## Healthcheck

Docker invokes `/app/guard healthcheck`. The helper sends a small DNS query to Blocky's loopback DNS listener at `127.0.0.1:5300` and verifies the response transaction ID and successful DNS response status.

This avoids making the public DoH listener itself the container healthcheck target.

## Build

The guard is built as a CGO-free, stripped static binary on the build platform and copied into the pinned Blocky runtime image. The build stage uses an exact Go patch release so the build toolchain does not drift underneath the project.

```sh
docker buildx build --platform linux/amd64 -t blocky-snapdeploy .
```

For ARM builds, BuildKit supplies the target architecture and variant and the guard is cross-compiled without target-architecture emulation during the build step.

## Scope

This repository is limited to the Blocky + DoH gateway deployment. The list below is informational and is not part of the runtime configuration.

## Public endpoints

High-performance DNS using HaGeZi Multi Pro + TIF blocklists.

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` (Recommended; sleeps after 15 minutes idle) |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` (Recommended; sleeps after 15 minutes idle) |

# ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## License

See [`LICENSE`](LICENSE).
