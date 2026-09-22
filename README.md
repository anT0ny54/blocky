# Blocky for SnapDeploy

A minimal public DNS-over-HTTPS (DoH) service built for small SnapDeploy instances, targeting **512 MB RAM / 0.25 vCPU**.

## Runtime

- Container image: `spx01/blocky:latest`
- HTTP listener: `4000`
- DoH path: `/dns-query`
- Outbound connections: IPv4 only
- DNS-over-53: intentionally not enabled for SnapDeploy
- Upstreams: three HaGeZi full-protection DoH resolvers
- Cache: bounded to 4096 entries
- Prefetching: disabled to avoid unnecessary upstream traffic
- Per-client rate limiting: enabled
- Query logging: disabled
- Prometheus metrics: disabled; the public port is reserved for DoH

## Free DNS Services

The following public DoH endpoints were listed with this project. Availability, filtering policy, hosting, and uptime are controlled by their respective operators/deployments.

| Endpoint | Notes |
| :--- | :--- |
| `https://freedns.koyeb.app/dns-query` | Public DoH endpoint |
| `https://dns-pi.vercel.app/api/doh/dns-query` | Public DoH endpoint |
| `https://dnssix.netlify.app/api/doh/dns-query` | Public DoH endpoint |
| `https://dns-93aca.containers.snapdeploy.app/dns-query` | SnapDeploy-hosted endpoint; may sleep when idle |

For the filtering backend used by this repository, the configured HaGeZi resolvers are:

- `https://root.hagezi.org/dns-query`
- `https://wurzn.hagezi.org/dns-query`
- `https://juuri.hagezi.org/dns-query`

See the [HaGeZi DNS server documentation](https://github.com/hagezi/dns-servers) for current resolver details.

## Configuration

The service uses `config.yml` as its single Blocky configuration file. The YAML schema comment at the top of the file enables editor validation against Blocky's configuration schema.


## License

See [`LICENSE`](LICENSE).
