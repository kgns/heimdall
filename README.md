# heimdall

Per-service latency, jitter and loss measurement from a home router (CPE), with
cloud-side anomaly detection and cause classification.

## Layout

```
probe/      Go module: heimdall-probe (runs on the CPE), heimdall-reflector and heimdall-client
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
make build-client # bin/client/heimdall-client-{darwin-arm64,darwin-amd64,linux-amd64}
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

With `resolver.mode: isp` the probe resolves through the ISP's resolvers
directly instead of the CPE's resolver. A DNS service the user chose, such
as a privacy resolver without the user's location, makes CDNs pick distant
servers; the ISP's view of its service should not depend on that. The
user's own DNS path is still measured as `dns` layers, next to `isp` and
`isp_uncached` layers for the ISP's resolvers. Their addresses come from
`resolver.isp_files`: pppd's session database (`/var/run/pppd*.tdb`),
which keeps the DNS servers the ISP sent during PPP negotiation even when
the CPE is set to other servers, or a resolv.conf written by the PPP or
DHCP client; else from `resolver.isp_servers`. `start` and `heartbeat`
samples carry `resolver_mode` and `isp_resolvers`.

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
| `lan` | ping burst to each LAN client, with its bridge port, medium and Wi-Fi context | 5 s |
| `flow` | every TCP and QUIC handshake of a LAN client, split into LAN and WAN parts (see [LAN clients](#lan-clients)) | per connection |
| `wifi_sta` | per Wi-Fi client: signal, noise, PHY rates, retries, power save, from `wl`, the mesh topology or, on a MediaTek extender, `iwpriv` | 10 s |
| `wifi_radio` | per radio: channel, busy and interference shares (`chanim_stats`), frame and retry counters | 10 s |
| `mesh_node` | per EasyMesh node (the CPE, extenders): address, mode, parent and backhaul | 10 s |
| `dnshealth` | PID, memory and container memory limit/OOM count of dnsmasq and dnscrypt-proxy | 30 s |
| `clock` | SNTP offset of the local clock; the clock is never changed | 60 s |

LAN clients are identified by an HMAC of their MAC address keyed with a
salt stored in `collectors.lan.salt_file`; hostnames are not recorded.

DNS is probed per layer every 30 s: the local forwarder (`local`), each of
its upstreams (`upstream`), an optional cache-busting `uncached` layer and
DoH resolvers reached directly (`doh`). Whoami TXT names (`identity`)
reveal which resolver answers for the system path; samples on that path
carry it as `resolver_id`, as do `dst_change` events.

## LAN clients

The CPE sits between every LAN client and the internet, so it can split each
connection a client opens into the part on the home network and the part on
the internet without anything installed on the client. The flow collector
(`collectors.flows`, `internal/collectors/flows`) reads the LAN bridge
through a packet socket with a kernel filter that keeps only handshake
packets, TLS ClientHellos and DNS answers to clients. For each TCP
connection:

```
client          CPE (br0)          server
  SYN  ──────────► t0 ───────────────►
       ◄────────── t1 ◄─────────── SYN-ACK      wan_ms = t1 - t0
  ACK  ──────────► t2                           lan_ms = t2 - t1
```

QUIC is measured the same way from its long-header packets; its `lan_ms`
includes the client's handshake processing, so LAN analysis uses TCP only.
The flow accelerator moves established flows off the CPU after a few
packets, but the handshake still passes through it. Each `flow` sample
carries the client ID (the same salted MAC hash as `lan`), the service from
the catalog's `domains` (named from the SNI, or the DNS answer the CPE gave
the client), `wan_ms`, `lan_ms`, and where the client is attached: bridge
port, mesh node, band and signal. `collectors.flows.names` sets how much of
the destination leaves the CPE:

| `names` | reported |
|---|---|
| `category` | the usage category only |
| `service` | the catalog service (default) |
| `raw` | also the server name and address, and the client's address and port; for prototypes on your own network only |

The Wi-Fi collector (`collectors.wifi`, Broadcom `wl`) adds per-station and
per-radio statistics, and reads the EasyMesh topology the CPE writes to
`/tmp/zy1905.json` for the clients of mesh extenders. An extender reports
the signal it receives from a client, which reads about 20 dB below what
the client itself sees, so extender clients are judged by link rate rather
than signal. With `collectors.lan.hostnames` the probe adds each client's DHCP hostname
(`client_name`) from the CPE's lease file, for dashboards on your own
network. LAN pings are sent in bursts (`collectors.lan.burst`): a Wi-Fi
client in power save answers the first only after it wakes for a beacon,
and the sample keeps the best of the rest.

### Mesh extender probe

For a client behind a mesh extender, the CPE's LAN figure is the Wi-Fi
hop to the extender and the backhaul together. A probe on the extender
itself (a MediaTek Zyxel WX5600 here, `configs/extender.example.yaml`)
measures what only the extender sees:

- the hop between the extender and each client: the client's part of
  every TCP handshake the extender bridges. `collectors.flows.position:
  bridge` captures on the bridge's ports, because forwarded frames never
  reach the bridge device. The CPE's LAN figure for the same client minus
  this hop is what the backhaul and the extender add;
- its stations and radios through `iwpriv` (`collectors.wifi.driver:
  mtk`): signal per receive chain, power save, rates, traffic, and the
  radio's failure and retransmission shares. The radio counters cover only
  the frames the driver's CPU path sends, so shares of fewer than 50
  frames are left out;
- the backhaul: a ping to the CPE every second (target `uplink`, service
  `backhaul`).

It uploads as its own device and names its CPE in `site`. Its detector
raises the incidents of its clients from its own readings and backhaul
incidents; the CPE lists the extender in `detect.delegated_nodes` and
raises no client incident for those clients. The notifier posts the
extender's incidents under the CPE's name. The probe needs the CPE's
client-ID salt, so that both probes name a client alike, and runs from
`/tmp`, which is RAM, so it is gone after the extender reboots:

```sh
scripts/rt sh 'lxc-attach -n heimdall -- cat /opt/heimdall/etc/lan.salt' > configs/local/wx5600-ap-17479.salt
scripts/new-device-token wx5600-ap-17479     # once; add the device to var.devices
cp configs/extender.example.yaml configs/local/extender.yaml
(cd probe && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o ../bin/linux-extender-arm64/heimdall-probe ./cmd/heimdall-probe)
export HEIMDALL_ROUTER=root@192.168.1.2 HEIMDALL_SSH_SOCK=~/.ssh/heimdall-extender.sock \
  HEIMDALL_REMOTE=/tmp/heimdall HEIMDALL_ARCH=extender-arm64 HEIMDALL_CONFIG=configs/local/extender.yaml
scripts/rt connect && scripts/rt deploy && scripts/rt start
```

The binary goes to `bin/linux-extender-arm64` so that `bin/linux-arm64`,
which the reflector instance is built from, is left alone.

### heimdall-client

`heimdall-client` measures from a laptop for a limited time, to check the
CPE's view of the same machine. It pings the CPE and connects to it over
TCP every second, opens TCP connections to the services the CPE measures,
reads the laptop's own Wi-Fi link on macOS, and uploads as its own device.
Each TCP sample carries the local address and port, so the dashboard and
the daily analysis match it with the CPE's record of the same connection.

```sh
scripts/new-device-token mbp-kgns     # once; add the device to var.devices
mkdir -p ~/.config/heimdall && cp mbp-kgns.token ~/.config/heimdall/token && chmod 600 ~/.config/heimdall/token
./heimdall-client-darwin-arm64 -device mbp-kgns -duration 30m
```

It needs no root: macOS allows unprivileged ICMP sockets. Remove the
quarantine flag of a downloaded binary with `xattr -d com.apple.quarantine`.
`-no-upload` prints the samples instead.

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
the image (`scripts/push-image`, needs Docker with buildx) whenever a
file under `grafana/` changes, and the service then rolls to the new task.
Grafana keeps no state between tasks: users, preferences and edits made in
the UI are lost on every deploy, so change dashboards in the generator.

| dashboard | answers |
|---|---|
| overview | is a problem general or limited to some services? Per-service summary, latency relative to each destination's own median, ISP hops |
| service | what happens on one service's paths? Per-destination RTT and loss, HTTPS phases, edges, failures, destination changes |
| network | access network, DNS, LAN and probe health |
| LAN clients | is it the home network or the internet? Per client LAN and WAN parts, signal, retries, radio airtime, Wi-Fi events, and the heimdall-client cross-check |
| topology | where is the time spent? A graph from every client through its mesh node and the CPE to the ISP and the internet, with each client's LAN round trip and WAN part (coloured by LAN p90 once it opened 5 connections, else by ping), the extender's own hop to its clients and its backhaul, a table of all clients, and the home network's incidents from both probes with duration and cause |

The record's address is set by `heimdall-dnssync` (`terraform/dnssync.tf`)
because the task's public IP changes on each deploy. The name is a direct
child of the zone: Cloudflare's Universal SSL certificate covers only
`kgns.dev` and `*.kgns.dev`, so a proxied name under `lat.kgns.dev` gets no
edge certificate.

## Reflector and cloud probe

`terraform/reflector.tf` runs one t4g.micro in eu-central-1 with an Elastic
IP (`reflector.lat.kgns.dev`). It has two services:

- `heimdall-reflector`: a STAMP session-reflector (RFC 8762, UDP 862), a TCP
  port 443 that accepts and closes, and the authoritative server for
  `w.lat.kgns.dev`. Any name under that zone answers with the address of the
  resolver that asked (TXT `"ns" "<address>"`, plus `"ecs" "<prefix>"` when
  the resolver sends an EDNS client subnet; A for IPv4 resolvers).
- `heimdall-probe` as device `aws-euc1` (`configs/aws.yaml`). It measures the
  same catalog from AWS as a control: if a service gets worse from both
  places, the problem is the service; if only from the CPE, it is the access
  network or the ISP's path.

On the CPE, the `aws-reflector` target measures STAMP next to ICMP and TCP.
STAMP samples (`kind = 'udp_echo'`) carry the one-way delays (`fwd_ms`,
`rev_ms`, which include the clock offset), the reflector's turnaround
(`proc_ms`), the forward hop count, and `lost_up` / `lost_down`. These
count the requests and the replies lost since the previous reply.
`dns.identity.zone` and `dns.uncached_zone` both use `w.lat.kgns.dev`, so
every identity answer is current and the uncached layer times the full
resolver path.

The instance installs its binaries and configuration from the artifacts
bucket at boot. Run `make build-arm64` before `terraform apply`: a changed
binary, catalog or config replaces the instance, which keeps its address.
Logs go to the CloudWatch log group `/heimdall/reflector`, and Session
Manager gives a shell. There is no SSH.

## Discovery and traceroutes

Catalog services can name discoverers that find the servers their traffic
really goes to. The probe measures these as targets
`<service>/<discoverer>/<n>`, and samples carry `extra.endpoint`.

| discoverer | source | measured with |
|---|---|---|
| `youtube_cache` | `redirector.googlevideo.com/report_mapping`, cluster name mapped to `rr<n>---sn-*.googlevideo.com` | icmp, tcp |
| `netflix_oca` | the fast.com API: Open Connect appliances for this line | icmp, tcp |
| `steam_sdr` | Steam SDR config: relay POPs nearest to `discovery.lat/lon` | icmp |
| `gamelift` | `gamelift-ping.<region>.api.aws` UDP 7770 beacons | udp |
| `discord_voice` | `latency.discord.media/rtc`: nearest voice regions | tcp |
| `stun` | the service's `stun` servers from the catalog | stun |

ICMP traceroutes (`kind = 'trace'`, `extra.hops`) cover every destination
in turn, so each one is traced about every 30 minutes.

## Detection and alerts

The probe detects anomalies itself (`internal/detect`). Each (target, kind,
destination) series learns an hour-long baseline. Sustained deviations
become `anomaly_start` / `anomaly_end` events. These are grouped into
incidents (`incident_start` / `incident_update` / `incident_end`) with a
scope and a likely cause:

- `access_network`: the ISP hops, or a large share of all services at once
- `path`: one service
- `destination_change`: a service shortly after DNS moved it
- `dns_latency`: DNS resolution slowed down
- `tls_blocked`: TCP connects but TLS fails, typical of SNI filtering

LAN clients are watched the same way, through the LAN part of their own
TCP handshakes (`flow/<client>` series). A client whose LAN part rises
above its baseline opens a `client` incident; when several clients rise at
once, at least two and half of the recently active ones, a `home`
incident covers them. The cause comes from where the clients are attached:

- `roaming`: the client moved between radios or nodes in the last 10 minutes
- `weak_signal` (clients of the CPE, -75 dBm or weaker), `retransmissions`
  (20% or more), `channel_busy` (radio 60% or more busy)
- `extender` / `weak_link_extender`: behind a mesh extender, with a link
  rate below 50 Mbit/s for the latter
- `wired_lan`, or `lan_latency` when the Wi-Fi readings show nothing
- for `home`: `extender` when all affected clients share one, `channel_busy`,
  or `lan_wide`

On the extender's probe, its own clients are judged by its own readings:
`roaming`, `weak_signal`, `radio_retransmissions` (its radio retransmits
20% or more), `wired_lan` or `lan_latency`, and `extender_wide` for
several of them at once. Its ping to the CPE opens `backhaul` incidents.

Client, home and backhaul incidents carry each client's context (node,
band, signal, retries, radio busy share) and link to the topology
dashboard.

Narrow incidents (one service, one client, DNS) are often blips of a few
minutes. The probe marks an incident as confirmed with an
`incident_confirmed` event once it has lasted `detect.confirm_after` (10
minutes); access and home incidents are confirmed at their start. Every
incident event carries `confirmed`.

The ingest Lambda passes incident events to `heimdall-notifier`
(`terraform/notify.tf`). The notifier keeps incidents in the DynamoDB
table `heimdall-incidents`. For a single-service incident on the CPE, it
checks whether the AWS control probe has the same service open, which tells
whether the problem is on the service's side or on the ISP's path. It posts
only confirmed incidents, and their updates and ends. It skips an incident
with the same scope, cause and services as one posted in the last six
hours, so a condition that keeps coming back, or a blocked service that
reopens after each probe restart, is posted once. Every incident, posted
or not, stays in the table and in the samples. The notifier posts to Slack
once the webhook URL is stored:

```sh
aws ssm put-parameter --profile kgns --region eu-central-1 --type SecureString \
  --name /heimdall/slack/webhook_url --value 'https://hooks.slack.com/services/...'
```

## Daily analysis

`heimdall-analytics` (`terraform/analytics.tf`) runs at 00:30 UTC for the
previous UTC day. It writes the tables `daily_service` (percentiles, jitter,
busy-hour inflation), `daily_compare` (degraded hours, attributed to the ISP
side or the service side using the AWS control), `ip_asn` (RIPEstat origin
AS of traceroute hops) and `path_borders` (where each path leaves the ISP,
the next AS, and the latency added at that border). For LAN clients it
writes `daily_client` (LAN and WAN parts, pings, signal, retries, roams),
`daily_client_service` (a client's WAN part next to the CPE's own TCP probe
of the same service) and `daily_crosscheck` (heimdall-client connections
matched with the CPE's split). It also writes a `summary` JSON per day
under `derived/` in the raw bucket, with flagged clients. The Grafana
dashboard "heimdall / daily analysis" shows them. To run past days:

```sh
terraform apply -var 'analytics_backfill=["2026-10-26"]'
```

## Daily report

After each daily analysis, `heimdall-report` (`terraform/report.tf`) runs.
It gives the day's summary, with the previous six days as a trend, to a
language model. The default is Kiro CLI in headless mode (`kiro-cli chat
--no-interactive`, no tools trusted), which uses the API key stored in SSM
under `/heimdall/kiro/api_key` and the model in `var.report_model`
(`claude-sonnet-5.5`). The Lambda is a container image
(`cloud/report.Dockerfile`, ECR `heimdall-report`) because it carries the
Kiro CLI binaries. Setting `report_writer = "bedrock"` with a Bedrock model
ID calls Bedrock instead.

The report is stored as `derived/report/dt=<day>/<device>.md` and posted
to Slack. If the model cannot be reached, a plain report built from the
same numbers is stored and posted instead.

```sh
scripts/report ex7501-home 2026-10-26
```

## ZyEE package

`zyee/` builds a ZyEE Deployment Unit, so the probe runs on the router as a
managed Execution Environment instead of a hand-started process:

```sh
make build-host build-arm64
zyee/build.sh        # -> dist/heimdall_<version>_arm_cortex-a7.ipk
```

The package installs:

- `/opt/heimdall/bin/heimdall-probe`
- the catalog
- `/opt/heimdall/etc/config.yaml`, from `configs/zyee.example.yaml`, or
  `configs/local/zyee.yaml` when present
- the device's upload token

The token makes the `.ipk` a secret, so serve it only on the LAN and only
while installing. `/sbin/heimdall.sh` supervises the probe and restarts it
if it exits. `/bin/start.sh` starts it at boot, because the firmware ignores
AutoStart. The label is `arm_cortex-a7`, the only architecture the router's
opkg accepts, but the binary is the static arm64 build.

To install:

1. In the router's web UI, create an Execution Environment named
   `heimdall`.
2. Stop a hand-started probe (`scripts/rt stop`). Two probes with the same
   device ID would mix their samples.
3. Serve `dist/` over plain HTTP on the LAN, for example with
   `python3 -m http.server -d dist 8080`.
4. Install the Deployment Unit with the URL
   `http://<lan-host>:8080/heimdall_<version>_arm_cortex-a7.ipk`, a unique
   UUID (for example `7e0a-a000-a417-e002`) and the Execution Environment
   `heimdall`. Keep the file name as built: zyeed checks that it starts with
   `heimdall_`.
5. Activate the Execution Unit if the probe does not start. The firmware
   does not start a newly installed unit by itself; after a reboot,
   `/bin/start.sh` does.

To upgrade, build a new package and update or reinstall the Deployment
Unit the same way. The LAN salt (`/opt/heimdall/etc/lan.salt`) is not part
of the package, so client IDs survive upgrades.

The probe logs to `/tmp/heimdall/probe.log` inside the container, which on
the host is `/tmp/heimdall/probe.log` too: the container shares the host's
`/tmp` and network. It reads `wl` and the mesh topology from there, and
captures on `br0` with the raw socket access it already has for ICMP. Its
samples arrive in Athena as before.
