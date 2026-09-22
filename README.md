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

The public HTTP listener is intentionally used for DoH. Keep the deployment's reverse proxy restricted to the intended DoH route and do not publish the loopback DNS listener.

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

# ⚡ Bandwidth Hero Server

A lightweight image optimization proxy designed to slash bandwidth usage and accelerate web browsing.

Bandwidth Hero Server fetches remote images, compresses them on the fly, and delivers optimized versions to the client. This significantly reduces data consumption while improving page load performance.

🖥️ **Live Demo:** [Bandwidth Hero](https://bhserv.netlify.app/).

## Supporting the Project

If you find this project useful, donations are appreciated:
- **Bitcoin**: `1HntwKxyqGCfnSGvGLMUTRAqLnTvLarAQP`

