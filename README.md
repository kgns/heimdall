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

## Self-test

```sh
heimdall-probe selftest          # human-readable
heimdall-probe selftest -json    # machine-readable
```

It reports the default route and WAN interface, routes through other
interfaces that are excluded from probing, IPv6 availability, the effective
DNS upstreams (reconstructed from the running dnsmasq's configuration), live
lookups through each DNS layer, and which ICMP socket mode is available.
