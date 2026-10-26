# heimdall

Per-service latency, jitter and loss measurement from a home router (CPE), with
cloud-side anomaly detection and cause classification.

## Layout

```
probe/      Go module: heimdall-probe (runs on the CPE) and, later, heimdall-reflector
catalog/    measurement targets by category, plus regional packs
cloud/      Python ingest, detection and analysis code
terraform/  AWS and Cloudflare infrastructure
grafana/    Grafana image: Athena data source and dashboards as code
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
system libraries. Use `linux-arm64` on CPEs with a 64-bit kernel, even when
their userland is 32-bit: Go has assembly for AES, SHA and the P-256 curve
only on 64-bit ARM, and without it TLS handshakes cost tens of milliseconds
of CPU that would be measured as network time. `linux-armv7` is for 32-bit
kernels.

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

Context collectors record what can explain a latency change:

| kind | what | default interval |
|---|---|---|
| `wan` | rx/tx bits and packets per second, drops and errors of the default-route interface | 1 s |
| `cpu` | CPU states, load, and UDP/TCP/ICMP error counter deltas from `/proc/net/snmp` | 1 s |
| `lan` | ping to each LAN client, with its bridge port and Wi-Fi or wired medium | 5 s |
| `dnshealth` | PID, memory and container memory limit/OOM count of dnsmasq and dnscrypt-proxy | 30 s |
| `clock` | SNTP offset of the local clock; the clock is never changed | 60 s |

LAN clients are identified by an HMAC of their MAC address keyed with a
salt stored in `collectors.lan.salt_file`; hostnames are not recorded.

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

## Dashboards

Grafana runs on ECS Fargate (`terraform/grafana.tf`) at
https://heimdall.kgns.dev/, behind Cloudflare. Log in as `admin`; the
password is in the SSM SecureString `/heimdall/grafana/admin_password`:

```sh
aws ssm get-parameter --profile kgns --region eu-central-1 \
  --name /heimdall/grafana/admin_password --with-decryption \
  --query Parameter.Value --output text
```

The dashboards are generated from `grafana/gen_dashboards.py`:

```sh
python3 grafana/gen_dashboards.py    # rewrites grafana/dashboards/*.json
```

Commit the JSON with the generator. `terraform apply` rebuilds and pushes
the image (`scripts/grafana-image`, needs Docker with buildx) whenever a
file under `grafana/` changes, and the service then rolls to the new task.
Grafana keeps no state between tasks: users, preferences and edits made in
the UI are lost on every deploy, so change dashboards in the generator.

| dashboard | answers |
|---|---|
| overview | is a problem general or limited to some services? Per-service summary, latency relative to each destination's own median, ISP hops |
| service | what happens on one service's paths? Per-destination RTT and loss, HTTPS phases, edges, failures, destination changes |
| network | access network, DNS, LAN and probe health |

The record's address is set by `heimdall-dnssync` (`terraform/dnssync.tf`)
because the task's public IP changes on each deploy. The name is a direct
child of the zone: Cloudflare's Universal SSL certificate covers only
`kgns.dev` and `*.kgns.dev`, so a proxied name under `lat.kgns.dev` gets no
edge certificate.
