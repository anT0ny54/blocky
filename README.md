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

The gateway accepts only `GET` and `POST` requests on `/dns-query`, validates the DNS wire message size and content type, applies connection/request limits, forwards to Blocky over loopback, and bounds the response body before returning it.

## Resource and abuse-protection defaults

The public guard is the first layer before Blocky receives a query. Its rate bucket is keyed by the **client source IP**, so arbitrary `Host` headers cannot create independent buckets and bypass the intended per-client quota.

| Setting | Default | Purpose |
| :--- | ---: | :--- |
| `GUARD_RATE` | `100/60s` (1.6667/s) | Sustained requests per source IP |
| `GUARD_BURST` | `80` | Initial burst capacity |
| `GUARD_MAX_IP_CONNS` | `16` | Per-source concurrent connection ceiling |
| `GUARD_MAX_GLOBAL_CONNS` | `64` | Aggregate connection ceiling |
| `GUARD_MAX_CONCURRENT_REQS` | `32` | Gateway/backend concurrency ceiling |
| `GUARD_MAX_IP_STATES` | `4096` | Bounded source-state slots |
| `GUARD_MAX_QUERIES_PER_CONN` | `256` | Keep-alive/query reuse ceiling |
| `GUARD_MAX_DNS_MESSAGE` | `4096` | Maximum DNS request wire size |
| `GUARD_MAX_RESPONSE_BYTES` | `4096` | Maximum public DoH response body size |
| `GUARD_IDLE_TIMEOUT` | `120s` | Public HTTP idle connection timeout |
| `GOMEMLIMIT` | `80MiB` | Go heap target for the guard |
| `BLOCKY_GOMEMLIMIT` | `288MiB` | Go heap target for Blocky |
| `caching.maxItemsCount` | `8192` | Bounded DNS cache entries |
| `caching.prefetching` | `false` | Avoid extra upstream traffic |

`GOMEMLIMIT` is a soft Go runtime heap target, not a hard container-memory cap. The combined 368 MiB heap targets leave headroom for stacks, native/runtime memory, buffers, the filesystem, and the container environment.

Blocky's own resolver-chain rate limiter is disabled because the public guard already limits requests before the loopback hop. Keeping a second limiter there would apply a second quota to the gateway-to-Blocky connection instead of the original client.

## Blocky configuration

`config.yml` is the only Blocky configuration file. It uses Blocky's v0.35.0 schema modeline for editor validation.

The default upstream set is the three HaGeZi **Full Protection** DoH endpoints:

- `https://root.hagezi.org/dns-query`
- `https://wurzn.hagezi.org/dns-query`
- `https://juuri.hagezi.org/dns-query`

The three endpoints are configured with `random` upstream selection, IPv4-only outbound connections, and a 2-second upstream timeout. HaGeZi currently documents these hosts as Full Protection servers. See the [HaGeZi DNS server documentation](https://github.com/hagezi/dns-servers).

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

This repository is intentionally limited to the Blocky + DoH gateway deployment. Unrelated public DNS advertisements, proxy projects, donation information, and other service listings are not part of the runtime configuration.

## License

See [`LICENSE`](LICENSE).

## 🌐 Free DNS Services

High-performance DNS utilizing HaGeZi Blocklists (Multi Pro + TIF).

| Blocklist | DNS-over-HTTPS (DoH) |
| :--- | :--- |
| Multi Pro + TIF | `https://freedns.koyeb.app/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dns-pi.vercel.app/api/doh/dns-query` (Recommended) |
| Multi Pro + TIF | `https://dnssix.netlify.app/api/doh/dns-query` |
| Multi Pro + TIF | `https://dns-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not use in 15 minute) |
| Multi Pro + TIF | `https://doh-93aca.containers.snapdeploy.app/dns-query` (Recommended, but will sleep if not use in 15 minute) |

---

# ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:
- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`
