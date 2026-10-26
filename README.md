# heimdall

Per-service latency, jitter and loss measurement from a home router (CPE), with
cloud-side anomaly detection and cause classification.

## Layout

```
probe/      Go module: heimdall-probe (runs on the CPE) and, later, heimdall-reflector
catalog/    measurement targets by category, plus regional packs
cloud/      Python ingest, detection and analysis code
terraform/  AWS and Cloudflare infrastructure
grafana/    local Grafana with dashboards as code
zyee/       Zyxel Execution Environment packaging
scripts/    router and maintenance helpers
docs/       design notes and runbook
```

## Build

Requires Go 1.26.

```sh
make test         # unit tests
make lint         # go vet, staticcheck, gofmt
make build        # bin/linux-armv7, bin/linux-arm64, bin/host
```

Binaries are static (`CGO_ENABLED=0`), so they run on the CPE without any
system libraries. `linux-armv7` is the primary CPE build.

## Run

```sh
heimdall-probe check -config /misc/heimdall/config.yaml    # validate, list targets
heimdall-probe run   -config /misc/heimdall/config.yaml    # measure until SIGINT/SIGTERM
heimdall-probe run -stdout                                  # built-in defaults, samples on stdout
```

`configs/router.example.yaml` documents every option. Samples go to a
size-capped rotating JSONL file under `/var/tmp/heimdall` (tmpfs on the CPE).

## Catalog

`catalog/targets.yaml` lists services by usage category (streaming, gaming,
video calls, voice, messaging, browsing, social, cloud and work).
`catalog/regions/<name>.yaml` adds regional services and is selected with
`catalog.regions`. Each host becomes a target `<service>/<host>` that is
resolved through the system resolver, the same path LAN clients use, and
re-resolved every five minutes. While the current address stays in the
answer the target keeps it; when it disappears a `dst_change` event records
the move.

```sh
heimdall-probe check -config /misc/heimdall/config.yaml -resolve
```

resolves every host once and shows the chosen address, the number of
answers and the lookup time, and flags addresses the route guard blocks.

## Measurements

Catalog services are measured three ways on the same address unless they
list their own `protocols`:

| kind | what | default interval | `rtt_ms` |
|---|---|---|---|
| `icmp` | echo request | 1 s | echo round trip |
| `tcp` | connect to :443, then RST | 10 s | SYN to SYN-ACK |
| `http` | HTTPS GET on a fresh connection, no redirects | 60 s | start to first response byte |

HTTP samples keep `connect_ms`, `tls_ms`, `ttfb_ms`, `total_ms`, status
code, protocol and, where response headers reveal it, the CDN and PoP.

DNS is probed per layer every 30 s: the local forwarder (`local`), each of
its upstreams (`upstream`), an optional cache-busting `uncached` layer and
DoH resolvers reached directly (`doh`). Whoami TXT names (`identity`)
reveal which resolver answers for the system path; samples on that path
carry it as `resolver_id`, as do `dst_change` events.

## Self-test

```sh
heimdall-probe selftest          # human-readable
heimdall-probe selftest -json    # machine-readable
```

It reports the default route and WAN interface, routes through other
interfaces that are excluded from probing, IPv6 availability, the effective
DNS upstreams (reconstructed from the running dnsmasq's configuration), live
lookups through each DNS layer, and which ICMP socket mode is available.
