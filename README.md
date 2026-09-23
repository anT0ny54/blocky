# Blocky for SnapDeploy

A minimal public DNS-over-HTTPS (DoH) service built for small SnapDeploy instances, targeting **512 MB RAM / 0.25 vCPU**.

## Runtime

- Container image: `spx01/blocky:v0.35.0`
- Public HTTP listener: `4001`
- DoH path: `/dns-query`
- DNS listener: loopback-only `127.0.0.1:5300` for the container healthcheck; DNS is not publicly exposed and port `53` is not used
- Outbound connections: IPv4 only
- Upstreams: three HaGeZi full-protection DoH resolvers
- Cache: bounded to 4096 entries
- Prefetching: disabled to avoid unnecessary upstream traffic
- Per-client rate limiting: enabled
- Query logging: disabled
- Prometheus metrics: disabled
- Statistics collection: disabled

The Go guard owns the public DoH listener on port `4001` and forwards only normalized DoH traffic to Blocky on loopback port `4002`. Keep the deployment's reverse proxy restricted to the intended DoH route and do not publish either loopback listener.

## Moderate resource and anti-abuse defaults

The public guard and Blocky's own per-client limiter are aligned with the more-moderate MosDNS reference profile used for small 512 MB / 0.25 vCPU deployments. The higher burst allowance is intended to tolerate normal browser DNS startup bursts while retaining bounded abuse protection.

| Setting | Default | Equivalent/reference |
| :--- | ---: | :--- |
| `GUARD_RATE` | `10/s` | MosDNS `DOH_RATE_LIMIT=10` |
| `GUARD_BURST` | `24` | MosDNS `DOH_RATE_BURST=24` |
| `GUARD_MAX_IP_CONNS` | `12` | MosDNS `IP_CONN_LIMIT=12` |
| `GUARD_MAX_GLOBAL_CONNS` | `96` | MosDNS `GLOBAL_CONN_LIMIT=96` |
| `GUARD_MAX_CONCURRENT_REQS` | `64` | Gateway concurrency ceiling; Blocky has no separate global request-rate knob |
| `GUARD_MAX_IP_STATES` | `512` | MosDNS `DOH_RATE_MAX_IPS=512` |
| Blocky `rateLimit.rate` | `10/s` | Same client rate profile |
| Blocky `rateLimit.burst` | `24` | Same client burst profile |
| `caching.maxItemsCount` | `4096` | MosDNS `CACHE_SIZE=4096` |
| `GOMEMLIMIT` | `256MiB` | Main Blocky/guard Go process target |

The guard runs before Blocky and rejects excess connections/requests before DNS parsing or backend work. `GOMEMLIMIT` is a soft Go heap target rather than a hard container-memory cap.

## Free DNS Services

The following public DoH endpoints were listed with this project. Availability, filtering policy, hosting, and uptime are controlled by their respective operators/deployments.

| Endpoint | Notes |
| :--- | :--- |
| `https://freedns.koyeb.app/dns-query` | Public DoH endpoint |
| `https://dns-pi.vercel.app/api/doh/dns-query` | Public DoH endpoint |
| `https://dnssix.netlify.app/api/doh/dns-query` | Public DoH endpoint |
| `https://dns-93aca.containers.snapdeploy.app/dns-query` | SnapDeploy-hosted endpoint; may sleep when idle |
| `https://doh-93aca.containers.snapdeploy.app/dns-query` | SnapDeploy-hosted endpoint; may sleep when idle |

For the filtering backend used by this repository, the configured HaGeZi resolvers are:

- `https://root.hagezi.org/dns-query`
- `https://wurzn.hagezi.org/dns-query`
- `https://juuri.hagezi.org/dns-query`

See the [HaGeZi DNS server documentation](https://github.com/hagezi/dns-servers) for current resolver details.

## Configuration

The service uses `config.yml` as its single Blocky configuration file. The YAML schema comment at the top of the file enables editor validation against Blocky's configuration schema.

The configuration deliberately separates the public DoH listener from Blocky's internal HTTP listener and the DNS healthcheck listener: the guard serves public DoH on port `4001`, Blocky listens for HTTP only on `127.0.0.1:4002`, and DNS is available only on `127.0.0.1:5300`.

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
