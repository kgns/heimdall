// Package config loads and validates the probe configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// DefaultPath is where the probe looks for its configuration on the CPE.
const DefaultPath = "/misc/heimdall/config.yaml"

// AutoGateway makes a target follow the default route's next hop.
const AutoGateway = "gateway"

// Config is the full probe configuration.
type Config struct {
	Device      string      `yaml:"device"`
	Runtime     Runtime     `yaml:"runtime"`
	Scheduler   Scheduler   `yaml:"scheduler"`
	ICMP        ICMP        `yaml:"icmp"`
	TCP         TCP         `yaml:"tcp"`
	HTTP        HTTP        `yaml:"http"`
	STAMP       STAMP       `yaml:"stamp"`
	UDP         UDP         `yaml:"udp"`
	Trace       Trace       `yaml:"trace"`
	Detect      Detect      `yaml:"detect"`
	Discovery   Discovery   `yaml:"discovery"`
	DNS         DNS         `yaml:"dns"`
	Targets     []Target    `yaml:"targets"`
	Catalog     Catalog     `yaml:"catalog"`
	Output      Output      `yaml:"output"`
	SelfMetrics SelfMetrics `yaml:"self_metrics"`
	NetWatch    NetWatch    `yaml:"netwatch"`
	Collectors  Collectors  `yaml:"collectors"`
	Upload      Upload      `yaml:"upload"`
	Resolver    Resolver    `yaml:"resolver"`
}

// Resolver selects how the probe resolves the hostnames it measures.
//
// In "system" mode it uses the CPE's own resolver, the path LAN clients
// use. In "isp" mode it queries the ISP's resolvers directly, so that the
// servers it measures are the ones the ISP's DNS hands its customers, and
// a DNS service the user chose (a privacy resolver, a filtering service)
// does not move the measurements to other servers. The ISP's resolvers are
// read from ISPFiles: pppd's session databases (*.tdb), which keep the DNS
// servers the ISP sent during PPP negotiation even when the CPE uses other
// servers, or resolv.conf files written by the PPP or DHCP client. They
// fall back to ISPServers. The user's own DNS path is
// still measured by the dns probes.
type Resolver struct {
	Mode       string        `yaml:"mode"`
	ISPFiles   []string      `yaml:"isp_files"`
	ISPServers []string      `yaml:"isp_servers"`
	Timeout    time.Duration `yaml:"timeout"`
}

// Resolver modes.
const (
	ResolverSystem = "system"
	ResolverISP    = "isp"
)

// Upload sends samples to the ingest API.
type Upload struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	// TokenFile holds the device's bearer token; keep it mode 0600.
	TokenFile string        `yaml:"token_file"`
	Interval  time.Duration `yaml:"interval"`
	Timeout   time.Duration `yaml:"timeout"`
	// Buffer caps the samples held in memory while the API is unreachable;
	// the oldest are dropped first.
	Buffer        ByteSize      `yaml:"buffer"`
	MaxBatch      int           `yaml:"max_batch"`
	MaxBatchBytes ByteSize      `yaml:"max_batch_bytes"`
	Heartbeat     time.Duration `yaml:"heartbeat"`
	// DrainOnStop is how long shutdown waits to send what is buffered.
	DrainOnStop time.Duration `yaml:"drain_on_stop"`
}

// Collectors configures the context signals recorded next to the
// measurements: WAN throughput, router CPU, LAN clients, the daemons on
// the DNS path and the local clock offset.
type Collectors struct {
	WAN       Periodic  `yaml:"wan"`
	CPU       Periodic  `yaml:"cpu"`
	LAN       LAN       `yaml:"lan"`
	Flows     Flows     `yaml:"flows"`
	WiFi      WiFi      `yaml:"wifi"`
	Processes Processes `yaml:"processes"`
	Clock     Clock     `yaml:"clock"`
}

// Flows configures the passive measurement of the connections LAN clients
// open: every TCP and QUIC handshake seen on Interface is split into the
// client's LAN round trip and the server's WAN round trip. It needs
// CAP_NET_RAW and uses the LAN collector's salt for client IDs.
type Flows struct {
	Enabled   bool   `yaml:"enabled"`
	Interface string `yaml:"interface"`
	// Names selects how much of the destination is reported: "category"
	// (streaming, gaming, ...), "service" (the catalog service, such as
	// netflix) or "raw", which adds the server name, its address and the
	// client's address and port. raw is for prototypes on one's own
	// network only.
	Names string `yaml:"names"`
	// MaxPerMinute caps the flow samples; the rest are counted only.
	MaxPerMinute int `yaml:"max_per_minute"`
	// ReceiveBuffer is the socket buffer for captured packets.
	ReceiveBuffer ByteSize `yaml:"receive_buffer"`
}

// Flow name levels.
const (
	FlowNamesCategory = "category"
	FlowNamesService  = "service"
	FlowNamesRaw      = "raw"
)

// WiFi configures the Wi-Fi collector: radio and per-station statistics
// read with the Broadcom wl utility, and the mesh topology the CPE's
// EasyMesh controller writes to MeshFile.
type WiFi struct {
	Interval time.Duration `yaml:"interval"`
	// Command is the wl utility; it is looked up in PATH.
	Command  string        `yaml:"command"`
	MeshFile string        `yaml:"mesh_file"`
	Timeout  time.Duration `yaml:"timeout"`
}

// Periodic is a collector with an interval; zero disables it.
type Periodic struct {
	Interval time.Duration `yaml:"interval"`
}

// LAN configures LAN client discovery and pings. Clients are identified
// by an HMAC of their MAC address keyed with the salt in SaltFile.
type LAN struct {
	Enabled          bool          `yaml:"enabled"`
	Interval         time.Duration `yaml:"interval"`
	DiscoverInterval time.Duration `yaml:"discover_interval"`
	MaxClients       int           `yaml:"max_clients"`
	Interfaces       []string      `yaml:"interfaces"`
	SaltFile         string        `yaml:"salt_file"`
	DisappearAfter   int           `yaml:"disappear_after"`
	// UseLeases also probes clients that only appear in the DHCP lease
	// file. Leases outlive the devices that took them, so this adds
	// clients that are long gone and only ever time out.
	UseLeases bool `yaml:"use_leases"`
	// Hostnames reports the name each client gave in its DHCP request,
	// from the CPE's lease file, with the client's samples. Names often
	// identify people or devices, so this is for prototypes on one's own
	// network only.
	Hostnames bool `yaml:"hostnames"`
	// Burst is the number of echo requests sent back to back to each
	// client. A Wi-Fi client in power save holds the first until it wakes
	// for the next beacon; the later ones measure the awake round trip.
	Burst int `yaml:"burst"`
}

// Processes lists daemons to follow; zero interval disables it.
type Processes struct {
	Interval time.Duration `yaml:"interval"`
	Names    []string      `yaml:"names"`
}

// Clock configures the SNTP offset check.
type Clock struct {
	Interval time.Duration `yaml:"interval"`
	Server   string        `yaml:"server"`
	Timeout  time.Duration `yaml:"timeout"`
}

// Runtime tunes the Go runtime and process priority. Environment variables
// GOMAXPROCS and GOMEMLIMIT take precedence when set.
type Runtime struct {
	GOMAXPROCS  int      `yaml:"gomaxprocs"`
	MemoryLimit ByteSize `yaml:"memory_limit"`
	Nice        int      `yaml:"nice"`
}

// Scheduler sets the global probe budget.
type Scheduler struct {
	MaxPPS float64 `yaml:"max_pps"`
	Burst  int     `yaml:"burst"`
}

// ICMP configures the echo prober.
type ICMP struct {
	Mode        string        `yaml:"mode"`
	Interval    time.Duration `yaml:"interval"`
	Timeout     time.Duration `yaml:"timeout"`
	PayloadSize int           `yaml:"payload_size"`
}

// Target is one ICMP destination, given as exactly one of IP, Host (resolved
// through the system resolver) or Auto. With TTL set, the echo request is
// sent towards IP with that IP TTL and the target measured is the router
// where it expires, which answers with ICMP time exceeded. This reaches
// routers that ignore echo requests addressed to themselves.
//
// Protocols selects icmp, tcp and http measurements of the same address;
// it defaults to icmp. Interval applies to ICMP; TCP and HTTP use their own
// section's interval.
type Target struct {
	ID        string        `yaml:"id"`
	Category  string        `yaml:"category"`
	Service   string        `yaml:"service"`
	IP        string        `yaml:"ip"`
	Host      string        `yaml:"host"`
	Auto      string        `yaml:"auto"`
	TTL       int           `yaml:"ttl"`
	Interval  time.Duration `yaml:"interval"`
	Protocols []string      `yaml:"protocols"`
	// Port is the TCP port, defaulting to tcp.port.
	Port int `yaml:"port"`
	// Path is the HTTP request path, defaulting to "/".
	Path string `yaml:"path"`
	// UDPPort is the port of udp and stun probes.
	UDPPort int `yaml:"udp_port"`
	// Discovery names the discoverer that sets the address of a target
	// created from the catalog; such targets have no ip, host or auto.
	// DiscoveryArgs are the service's inputs to it (STUN servers).
	Discovery     string   `yaml:"-"`
	DiscoveryArgs []string `yaml:"-"`
}

// Protocol names. stamp needs a STAMP reflector (heimdall-reflector) at
// the target's address.
// udp sends a datagram to an echo service and waits for it to return; stun
// sends a STUN Binding request. Both use the target's udp_port.
const (
	ProtoICMP  = "icmp"
	ProtoTCP   = "tcp"
	ProtoHTTP  = "http"
	ProtoSTAMP = "stamp"
	ProtoUDP   = "udp"
	ProtoSTUN  = "stun"
)

var protocols = []string{ProtoICMP, ProtoTCP, ProtoHTTP, ProtoSTAMP, ProtoUDP, ProtoSTUN}

// Wants reports whether t is measured with protocol p.
func (t Target) Wants(p string) bool {
	if len(t.Protocols) == 0 {
		return p == ProtoICMP
	}
	for _, x := range t.Protocols {
		if x == p {
			return true
		}
	}
	return false
}

// TCP configures TCP connect probes.
type TCP struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Port     int           `yaml:"port"`
}

// STAMP configures two-way UDP test packets (RFC 8762) towards a
// reflector, which give one-way delays and the direction of loss.
type STAMP struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Port     int           `yaml:"port"`
}

// Detect configures on-probe anomaly and incident detection. Series need
// Warmup of history before they are judged. AccessServices are the
// services that measure the access network itself.
type Detect struct {
	Enabled        bool          `yaml:"enabled"`
	Warmup         time.Duration `yaml:"warmup"`
	AccessServices []string      `yaml:"access_services"`
	// ConfirmAfter is how long an incident of one service, one LAN client
	// or DNS must last before it is confirmed (incident_confirmed), which
	// is what the notifier posts. Access and home incidents are confirmed
	// at once.
	ConfirmAfter time.Duration `yaml:"confirm_after"`
}

// Trace configures ICMP traceroutes. One trace runs every Interval, to the
// targets in turn, so each target is traced about every Interval times the
// number of distinct destinations. Zero interval disables tracing. Traces
// need a raw ICMP socket.
type Trace struct {
	Interval time.Duration `yaml:"interval"`
	MaxHops  int           `yaml:"max_hops"`
	Probes   int           `yaml:"probes"`
	Timeout  time.Duration `yaml:"timeout"`
	Gap      time.Duration `yaml:"gap"`
}

// UDP configures the udp echo and stun probes.
type UDP struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
}

// Discovery configures the discoverers named in the catalog. Lat and Lon
// place the probe for choosing nearby relays.
type Discovery struct {
	Enabled         bool          `yaml:"enabled"`
	Interval        time.Duration `yaml:"interval"`
	Timeout         time.Duration `yaml:"timeout"`
	Lat             float64       `yaml:"lat"`
	Lon             float64       `yaml:"lon"`
	GameLiftRegions []string      `yaml:"gamelift_regions"`
}

// HTTP configures HTTPS request probes.
type HTTP struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	MaxBody  ByteSize      `yaml:"max_body"`
	// UserAgent defaults to one naming the probe and its version.
	UserAgent string `yaml:"user_agent"`
}

// DNS configures the layered DNS probes: the local forwarder, each of its
// upstreams, an optional uncached path through a wildcard zone, and DoH
// resolvers reached directly for comparison.
type DNS struct {
	Enabled  bool          `yaml:"enabled"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	// Names are queried in turn on the cached layers.
	Names     []string `yaml:"names"`
	Local     bool     `yaml:"local"`
	Upstreams bool     `yaml:"upstreams"`
	// UncachedZone, when set, is a wildcard zone; a random label under it
	// is resolved through the local forwarder on every probe, so no cache
	// on the way can answer.
	UncachedZone string      `yaml:"uncached_zone"`
	DoH          []DoHServer `yaml:"doh"`
	Identity     Identity    `yaml:"identity"`
}

// DoHServer is a DNS-over-HTTPS resolver reached at a fixed address.
type DoHServer struct {
	ID  string `yaml:"id"`
	URL string `yaml:"url"`
	IP  string `yaml:"ip"`
}

// Identity configures resolver identification through whoami TXT names,
// resolved through the local forwarder. Zone is a whoami zone that answers
// for any name (heimdall-reflector serves one); a random label under it is
// queried each time, so no cache can answer and every reply is current.
// Fixed names can be served from a cache and count only when the answer
// was evidently fetched upstream.
type Identity struct {
	Interval time.Duration `yaml:"interval"`
	Names    []string      `yaml:"names"`
	Zone     string        `yaml:"zone"`
}

// Catalog points at the service catalog and selects what to load from it.
type Catalog struct {
	// Path is the global catalog file. Empty disables the catalog.
	Path string `yaml:"path"`
	// Regions names regional packs, loaded from regions/<name>.yaml next
	// to Path.
	Regions []string `yaml:"regions"`
	// Only, when non-empty, keeps just these service IDs or categories.
	Only []string `yaml:"only"`
	// Exclude drops these service IDs or categories.
	Exclude         []string      `yaml:"exclude"`
	ResolveInterval time.Duration `yaml:"resolve_interval"`
	ResolveTimeout  time.Duration `yaml:"resolve_timeout"`
}

// MaxTargetTTL bounds TTL-limited targets to the first few hops, which is
// where per-hop baselines are meaningful.
const MaxTargetTTL = 16

// Output selects local sinks.
type Output struct {
	Stdout bool  `yaml:"stdout"`
	JSONL  JSONL `yaml:"jsonl"`
}

// JSONL is the rotating local sample file, meant for debugging.
type JSONL struct {
	Enabled     bool     `yaml:"enabled"`
	Dir         string   `yaml:"dir"`
	MaxFileSize ByteSize `yaml:"max_file_size"`
	MaxFiles    int      `yaml:"max_files"`
}

// SelfMetrics controls the probe's own resource reporting.
type SelfMetrics struct {
	Interval time.Duration `yaml:"interval"`
}

// NetWatch controls how often the default route and WAN address are
// re-read.
type NetWatch struct {
	Interval time.Duration `yaml:"interval"`
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		Runtime:   Runtime{GOMAXPROCS: 1, MemoryLimit: 48 * MiB, Nice: 10},
		Scheduler: Scheduler{MaxPPS: 100, Burst: 10},
		Catalog:   Catalog{ResolveInterval: 5 * time.Minute, ResolveTimeout: 5 * time.Second},
		ICMP:      ICMP{Mode: "auto", Interval: time.Second, Timeout: 2 * time.Second, PayloadSize: 32},
		TCP:       TCP{Interval: 10 * time.Second, Timeout: 3 * time.Second, Port: 443},
		HTTP:      HTTP{Interval: time.Minute, Timeout: 10 * time.Second, MaxBody: 32 * KiB},
		STAMP:     STAMP{Interval: time.Second, Timeout: 2 * time.Second, Port: 862},
		UDP:       UDP{Interval: 5 * time.Second, Timeout: 2 * time.Second},
		Trace:     Trace{Interval: 30 * time.Second, MaxHops: 24, Probes: 2, Timeout: 2 * time.Second, Gap: 20 * time.Millisecond},
		Detect: Detect{Enabled: true, Warmup: 15 * time.Minute, AccessServices: []string{"isp-hop", "isp-gateway"},
			ConfirmAfter: 10 * time.Minute},
		Discovery: Discovery{
			Enabled: true, Interval: time.Hour, Timeout: 20 * time.Second,
			// Istanbul.
			Lat: 41.01, Lon: 28.98,
			GameLiftRegions: []string{"eu-central-1", "eu-south-1", "il-central-1", "eu-west-1"},
		},
		DNS: DNS{
			Enabled: true, Interval: 30 * time.Second, Timeout: 3 * time.Second,
			Names: []string{"www.google.com", "www.wikipedia.org"},
			Local: true, Upstreams: true,
			DoH: []DoHServer{
				{ID: "google", URL: "https://dns.google/dns-query", IP: "8.8.8.8"},
				{ID: "cloudflare", URL: "https://cloudflare-dns.com/dns-query", IP: "1.1.1.1"},
			},
			Identity: Identity{Interval: time.Minute, Names: []string{"whoami.ds.akahelp.net", "o-o.myaddr.l.google.com"}},
		},
		Output: Output{JSONL: JSONL{
			Enabled: false, Dir: "/var/tmp/heimdall", MaxFileSize: 4 * MiB, MaxFiles: 3,
		}},
		SelfMetrics: SelfMetrics{Interval: time.Minute},
		NetWatch:    NetWatch{Interval: 10 * time.Second},
		Collectors: Collectors{
			WAN: Periodic{Interval: time.Second},
			CPU: Periodic{Interval: time.Second},
			LAN: LAN{
				Enabled: true, Interval: 5 * time.Second, DiscoverInterval: 30 * time.Second,
				MaxClients: 32, Interfaces: []string{"br*"}, DisappearAfter: 3, Burst: 1,
			},
			Flows: Flows{
				Interface: "br0", Names: FlowNamesService, MaxPerMinute: 1200, ReceiveBuffer: 512 * KiB,
			},
			WiFi:      WiFi{Command: "wl", MeshFile: "/tmp/zy1905.json", Timeout: 3 * time.Second},
			Processes: Processes{Interval: 30 * time.Second, Names: []string{"dnsmasq", "dnscrypt-proxy"}},
			Clock:     Clock{Interval: time.Minute, Server: "time.cloudflare.com", Timeout: 3 * time.Second},
		},
		Resolver: Resolver{
			Mode: ResolverSystem, Timeout: 2 * time.Second,
			ISPFiles: []string{"/var/run/pppd*.tdb", "/etc/ppp/resolv.conf", "/var/run/ppp/resolv.conf", "/tmp/resolv.conf.ppp", "/tmp/resolv.conf.auto"},
		},
		Upload: Upload{
			TokenFile: "/misc/heimdall/upload.token", Interval: 10 * time.Second, Timeout: 15 * time.Second,
			Buffer: 16 * MiB, MaxBatch: 2000, MaxBatchBytes: 3 * MiB, Heartbeat: time.Minute,
			DrainOnStop: 5 * time.Second,
		},
	}
}

// DefaultTargets is used when the configuration lists no targets. The ISP
// hops are measured with TTL-limited probes because access routers often
// drop echo requests addressed to themselves.
func DefaultTargets() []Target {
	return []Target{
		{ID: "isp-hop1", Category: "infra", Service: "isp-hop", IP: "1.1.1.1", TTL: 1},
		{ID: "isp-hop2", Category: "infra", Service: "isp-hop", IP: "1.1.1.1", TTL: 2},
		{ID: "isp-hop3", Category: "infra", Service: "isp-hop", IP: "1.1.1.1", TTL: 3},
		{ID: "cloudflare-dns", Category: "infra", Service: "cloudflare", IP: "1.1.1.1"},
		{ID: "google-dns", Category: "infra", Service: "google", IP: "8.8.8.8"},
		{ID: "quad9-dns", Category: "infra", Service: "quad9", IP: "9.9.9.9"},
	}
}

// Load reads path on top of the defaults. A missing file is an error
// unless optional is true, in which case the defaults are returned.
func Load(path string, optional bool) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			c := Default()
			c.Targets = DefaultTargets()
			return c, c.Validate()
		}
		return Config{}, err
	}
	c, err := Parse(b)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Parse decodes YAML on top of the defaults and validates the result.
// Unknown keys are rejected.
func Parse(b []byte) (Config, error) {
	c := Default()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, err
	}
	if len(c.Targets) == 0 {
		c.Targets = DefaultTargets()
	}
	return c, c.Validate()
}

// TargetInterval returns the effective probe interval of t.
func (c *Config) TargetInterval(t Target) time.Duration {
	if t.Interval > 0 {
		return t.Interval
	}
	return c.ICMP.Interval
}

// TargetPort returns the TCP port of t.
func (c *Config) TargetPort(t Target) int {
	if t.Port > 0 {
		return t.Port
	}
	return c.TCP.Port
}

// assumedUpstreams is used for budget estimates, because the number of
// forwarder upstreams is only known at runtime.
const assumedUpstreams = 2

// ProbeRate returns the configured probes per second across all targets
// and protocols, including DNS probes.
func (c *Config) ProbeRate() float64 {
	var r float64
	for _, t := range c.Targets {
		if t.Wants(ProtoICMP) {
			r += 1 / c.TargetInterval(t).Seconds()
		}
		if t.Wants(ProtoTCP) && c.TCP.Interval > 0 {
			r += 1 / c.TCP.Interval.Seconds()
		}
		if t.Wants(ProtoHTTP) && c.HTTP.Interval > 0 {
			r += 1 / c.HTTP.Interval.Seconds()
		}
		if t.Wants(ProtoSTAMP) && c.STAMP.Interval > 0 {
			r += 1 / c.STAMP.Interval.Seconds()
		}
		if (t.Wants(ProtoUDP) || t.Wants(ProtoSTUN)) && c.UDP.Interval > 0 {
			r += 1 / c.UDP.Interval.Seconds()
		}
	}
	if d := c.DNS; d.Enabled && d.Interval > 0 {
		layers := len(d.DoH)
		if d.Local {
			layers++
		}
		if d.Upstreams {
			layers += assumedUpstreams
		}
		if d.UncachedZone != "" {
			layers++
		}
		if c.Resolver.Mode == ResolverISP {
			// One layer per ISP resolver, two assumed when they are
			// discovered at runtime, and the uncached one.
			layers += max(len(c.Resolver.ISPServers), assumedUpstreams)
			if d.UncachedZone != "" {
				layers++
			}
		}
		r += float64(layers) / d.Interval.Seconds()
		if d.Identity.Interval > 0 {
			n := len(d.Identity.Names)
			if d.Identity.Zone != "" {
				n++
			}
			r += float64(n) / d.Identity.Interval.Seconds()
		}
	}
	if tr := c.Trace; tr.Interval > 0 {
		r += float64(tr.MaxHops*tr.Probes) / tr.Interval.Seconds()
	}
	// LAN pings are counted at the worst case of max_clients.
	if l := c.Collectors.LAN; l.Enabled && l.Interval > 0 {
		r += float64(l.MaxClients*max(l.Burst, 1)) / l.Interval.Seconds()
	}
	if cl := c.Collectors.Clock; cl.Interval > 0 {
		r += 1 / cl.Interval.Seconds()
	}
	return r
}

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	targetIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_./-]{0,127}$`)
	hostPattern     = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)
)

// ValidHost reports whether h is a lowercase DNS hostname with at least
// two labels.
func ValidHost(h string) bool { return len(h) <= 253 && hostPattern.MatchString(h) }

// UsableAddr reports whether a resolved or configured address can be a
// measurement target: public IPv4 unicast. Private, CGNAT, loopback and
// unspecified answers usually mean a DNS block page or a broken record.
func UsableAddr(a netip.Addr) bool {
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Validate reports every problem found, joined into one error.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Device != "" && !idPattern.MatchString(c.Device) {
		bad("device %q: use lowercase letters, digits, '.', '_' or '-'", c.Device)
	}
	if c.Runtime.GOMAXPROCS < 0 {
		bad("runtime.gomaxprocs must not be negative")
	}
	if c.Runtime.MemoryLimit != 0 && c.Runtime.MemoryLimit < 8*MiB {
		bad("runtime.memory_limit %s is below 8MiB", c.Runtime.MemoryLimit)
	}
	if c.Runtime.Nice < 0 || c.Runtime.Nice > 19 {
		bad("runtime.nice must be between 0 and 19")
	}
	if c.Scheduler.MaxPPS <= 0 {
		bad("scheduler.max_pps must be positive")
	}
	if c.Scheduler.Burst < 1 {
		bad("scheduler.burst must be at least 1")
	}
	switch c.ICMP.Mode {
	case "auto", "raw", "dgram":
	default:
		bad("icmp.mode %q: want auto, raw or dgram", c.ICMP.Mode)
	}
	if c.ICMP.Interval < 100*time.Millisecond {
		bad("icmp.interval %v is below 100ms", c.ICMP.Interval)
	}
	if c.ICMP.Timeout <= 0 || c.ICMP.Timeout > 30*time.Second {
		bad("icmp.timeout %v must be in (0, 30s]", c.ICMP.Timeout)
	}
	if c.ICMP.PayloadSize < 8 || c.ICMP.PayloadSize > 1400 {
		bad("icmp.payload_size %d must be between 8 and 1400", c.ICMP.PayloadSize)
	}

	c.validateProbes(bad)

	ids := map[string]bool{}
	for i, t := range c.Targets {
		where := fmt.Sprintf("targets[%d]", i)
		if t.ID != "" {
			where += " (" + t.ID + ")"
		}
		if !targetIDPattern.MatchString(t.ID) {
			bad("%s: id must match %s", where, targetIDPattern)
		} else if ids[t.ID] {
			bad("%s: duplicate id", where)
		}
		ids[t.ID] = true
		if t.Category == "" || t.Service == "" {
			bad("%s: category and service are required", where)
		}
		set := 0
		for _, v := range []string{t.IP, t.Host, t.Auto} {
			if v != "" {
				set++
			}
		}
		switch {
		case set > 1:
			bad("%s: set only one of ip, host or auto", where)
		case t.Host != "":
			if !ValidHost(t.Host) {
				bad("%s: host %q is not a valid lowercase hostname", where, t.Host)
			}
		case t.IP != "":
			a, err := netip.ParseAddr(t.IP)
			if err != nil || !a.Is4() {
				bad("%s: ip %q is not an IPv4 address", where, t.IP)
			} else if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() {
				bad("%s: ip %s cannot be probed", where, a)
			}
		case t.Auto == AutoGateway:
		case t.Auto != "":
			bad("%s: auto %q: only %q is supported", where, t.Auto, AutoGateway)
		case t.Discovery != "":
		default:
			bad("%s: one of ip, host or auto is required", where)
		}
		if t.TTL < 0 || t.TTL > MaxTargetTTL {
			bad("%s: ttl %d must be between 1 and %d", where, t.TTL, MaxTargetTTL)
		}
		if t.TTL != 0 && t.IP == "" {
			bad("%s: ttl needs ip, the address the probe is sent towards", where)
		}
		for _, p := range t.Protocols {
			if !slices.Contains(protocols, p) {
				bad("%s: protocol %q is not one of %v", where, p, protocols)
			}
		}
		if (t.Wants(ProtoUDP) || t.Wants(ProtoSTUN)) && (t.UDPPort < 1 || t.UDPPort > 65535) {
			bad("%s: udp and stun need udp_port", where)
		}
		if (t.TTL != 0 || t.Auto != "") && (t.Wants(ProtoTCP) || t.Wants(ProtoHTTP) || t.Wants(ProtoSTAMP) ||
			t.Wants(ProtoUDP) || t.Wants(ProtoSTUN)) {
			bad("%s: ttl and auto targets support only icmp", where)
		}
		if t.Wants(ProtoHTTP) && t.Host == "" {
			bad("%s: http needs host, which is sent as SNI and Host header", where)
		}
		if t.Port < 0 || t.Port > 65535 {
			bad("%s: port %d out of range", where, t.Port)
		}
		if t.Path != "" && !strings.HasPrefix(t.Path, "/") {
			bad("%s: path %q must start with /", where, t.Path)
		}
		if t.Interval != 0 && t.Interval < 100*time.Millisecond {
			bad("%s: interval %v is below 100ms", where, t.Interval)
		}
	}
	if r := c.ProbeRate(); r > c.Scheduler.MaxPPS {
		bad("targets need %.1f probes/s, above scheduler.max_pps %.1f", r, c.Scheduler.MaxPPS)
	}

	if j := c.Output.JSONL; j.Enabled {
		if j.Dir == "" {
			bad("output.jsonl.dir is required when enabled")
		}
		if j.MaxFileSize < 4*KiB {
			bad("output.jsonl.max_file_size %s is below 4KiB", j.MaxFileSize)
		}
		if j.MaxFiles < 1 {
			bad("output.jsonl.max_files must be at least 1")
		}
	}
	if c.Catalog.ResolveInterval < 30*time.Second {
		bad("catalog.resolve_interval must be at least 30s")
	}
	if c.Catalog.ResolveTimeout <= 0 || c.Catalog.ResolveTimeout > 30*time.Second {
		bad("catalog.resolve_timeout must be in (0, 30s]")
	}
	for _, r := range c.Catalog.Regions {
		if !idPattern.MatchString(r) {
			bad("catalog.regions: %q is not a valid region name", r)
		}
	}
	c.validateCollectors(bad)
	c.validateUpload(bad)
	switch r := c.Resolver; r.Mode {
	case ResolverSystem:
	case ResolverISP:
		if len(r.ISPFiles) == 0 && len(r.ISPServers) == 0 {
			bad("resolver: isp mode needs isp_files or isp_servers")
		}
		for _, s := range r.ISPServers {
			// ISP resolvers may have private addresses inside the ISP's
			// network; the route guard keeps out LAN addresses.
			if a, err := netip.ParseAddr(s); err != nil || !a.Is4() || !a.IsGlobalUnicast() {
				bad("resolver.isp_servers: %q is not a unicast IPv4 address", s)
			}
		}
		if r.Timeout <= 0 || r.Timeout > 10*time.Second {
			bad("resolver.timeout must be in (0, 10s]")
		}
	default:
		bad("resolver.mode %q: want %s or %s", r.Mode, ResolverSystem, ResolverISP)
	}
	if c.SelfMetrics.Interval < time.Second {
		bad("self_metrics.interval must be at least 1s")
	}
	if c.NetWatch.Interval < time.Second {
		bad("netwatch.interval must be at least 1s")
	}
	return errors.Join(errs...)
}

func (c *Config) validateProbes(bad func(string, ...any)) {
	if c.TCP.Interval < time.Second {
		bad("tcp.interval must be at least 1s")
	}
	if c.TCP.Timeout <= 0 || c.TCP.Timeout > 30*time.Second {
		bad("tcp.timeout must be in (0, 30s]")
	}
	if c.TCP.Port < 1 || c.TCP.Port > 65535 {
		bad("tcp.port %d out of range", c.TCP.Port)
	}
	if c.HTTP.Interval < 10*time.Second {
		bad("http.interval must be at least 10s")
	}
	if c.HTTP.Timeout <= 0 || c.HTTP.Timeout > 60*time.Second {
		bad("http.timeout must be in (0, 60s]")
	}
	if c.HTTP.MaxBody < 0 || c.HTTP.MaxBody > MiB {
		bad("http.max_body must be between 0 and 1MiB")
	}
	if c.STAMP.Interval < 100*time.Millisecond {
		bad("stamp.interval must be at least 100ms")
	}
	if c.STAMP.Timeout <= 0 || c.STAMP.Timeout > 30*time.Second {
		bad("stamp.timeout must be in (0, 30s]")
	}
	if c.STAMP.Port < 1 || c.STAMP.Port > 65535 {
		bad("stamp.port %d out of range", c.STAMP.Port)
	}
	if c.UDP.Interval < time.Second {
		bad("udp.interval must be at least 1s")
	}
	if dt := c.Detect; dt.Enabled && (dt.Warmup < 5*time.Minute || dt.Warmup > 6*time.Hour) {
		bad("detect.warmup must be between 5m and 6h")
	}
	if dt := c.Detect; dt.ConfirmAfter < 0 || dt.ConfirmAfter > 2*time.Hour {
		bad("detect.confirm_after must be between 0 and 2h")
	}
	if tr := c.Trace; tr.Interval != 0 {
		if tr.Interval < 10*time.Second {
			bad("trace.interval must be 0 (off) or at least 10s")
		}
		if tr.MaxHops < 1 || tr.MaxHops > 64 {
			bad("trace.max_hops must be between 1 and 64")
		}
		if tr.Probes < 1 || tr.Probes > 5 {
			bad("trace.probes must be between 1 and 5")
		}
		if tr.Timeout <= 0 || tr.Timeout > 10*time.Second {
			bad("trace.timeout must be in (0, 10s]")
		}
		if tr.Gap < 0 || tr.Gap > time.Second {
			bad("trace.gap must be between 0 and 1s")
		}
	}
	if c.UDP.Timeout <= 0 || c.UDP.Timeout > 30*time.Second {
		bad("udp.timeout must be in (0, 30s]")
	}
	if d := c.Discovery; d.Enabled {
		if d.Interval < 5*time.Minute {
			bad("discovery.interval must be at least 5m")
		}
		if d.Timeout <= 0 || d.Timeout > time.Minute {
			bad("discovery.timeout must be in (0, 1m]")
		}
		if d.Lat < -90 || d.Lat > 90 || d.Lon < -180 || d.Lon > 180 {
			bad("discovery.lat/lon out of range")
		}
		for _, r := range d.GameLiftRegions {
			if !idPattern.MatchString(r) {
				bad("discovery.gamelift_regions: %q is not a region name", r)
			}
		}
	}

	d := c.DNS
	if !d.Enabled {
		return
	}
	if d.Interval < 5*time.Second {
		bad("dns.interval must be at least 5s")
	}
	if d.Timeout <= 0 || d.Timeout > 30*time.Second {
		bad("dns.timeout must be in (0, 30s]")
	}
	if (d.Local || d.Upstreams) && len(d.Names) == 0 {
		bad("dns.names is required for the local and upstream layers")
	}
	for _, n := range d.Names {
		if !ValidHost(n) {
			bad("dns.names: %q is not a valid hostname", n)
		}
	}
	if d.UncachedZone != "" && !ValidHost(d.UncachedZone) {
		bad("dns.uncached_zone %q is not a valid zone name", d.UncachedZone)
	}
	seen := map[string]bool{}
	for i, s := range d.DoH {
		where := fmt.Sprintf("dns.doh[%d]", i)
		if !idPattern.MatchString(s.ID) || seen[s.ID] {
			bad("%s: id %q must be unique and match %s", where, s.ID, idPattern)
		}
		seen[s.ID] = true
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme != "https" || !ValidHost(u.Hostname()) {
			bad("%s: url %q must be https://<host>/<path>", where, s.URL)
		}
		a, err := netip.ParseAddr(s.IP)
		if err != nil || !UsableAddr(a) {
			bad("%s: ip %q must be a public IPv4 address", where, s.IP)
		}
	}
	if (len(d.Identity.Names) > 0 || d.Identity.Zone != "") && d.Identity.Interval < 10*time.Second {
		bad("dns.identity.interval must be at least 10s")
	}
	if d.Identity.Zone != "" && !ValidHost(d.Identity.Zone) {
		bad("dns.identity.zone %q is not a valid zone name", d.Identity.Zone)
	}
	for _, n := range d.Identity.Names {
		if !ValidHost(n) {
			bad("dns.identity.names: %q is not a valid hostname", n)
		}
	}
}

func (c *Config) validateCollectors(bad func(string, ...any)) {
	co := c.Collectors
	for name, p := range map[string]Periodic{"wan": co.WAN, "cpu": co.CPU} {
		if p.Interval != 0 && p.Interval < 500*time.Millisecond {
			bad("collectors.%s.interval must be 0 (off) or at least 500ms", name)
		}
	}
	if l := co.LAN; l.Enabled {
		if l.Interval < time.Second {
			bad("collectors.lan.interval must be at least 1s")
		}
		if l.DiscoverInterval < 5*time.Second {
			bad("collectors.lan.discover_interval must be at least 5s")
		}
		if l.MaxClients < 1 || l.MaxClients > 256 {
			bad("collectors.lan.max_clients must be between 1 and 256")
		}
		if len(l.Interfaces) == 0 {
			bad("collectors.lan.interfaces is required")
		}
		for _, p := range l.Interfaces {
			if _, err := path.Match(p, "x"); err != nil {
				bad("collectors.lan.interfaces: bad pattern %q", p)
			}
		}
		if l.DisappearAfter < 1 {
			bad("collectors.lan.disappear_after must be at least 1")
		}
		if l.Burst < 1 || l.Burst > 5 {
			bad("collectors.lan.burst must be between 1 and 5")
		}
	}
	if f := co.Flows; f.Enabled {
		if f.Interface == "" {
			bad("collectors.flows.interface is required")
		}
		switch f.Names {
		case FlowNamesCategory, FlowNamesService, FlowNamesRaw:
		default:
			bad("collectors.flows.names %q: want %s, %s or %s", f.Names, FlowNamesCategory, FlowNamesService, FlowNamesRaw)
		}
		if f.MaxPerMinute < 1 || f.MaxPerMinute > 100000 {
			bad("collectors.flows.max_per_minute must be between 1 and 100000")
		}
		if f.ReceiveBuffer < 64*KiB || f.ReceiveBuffer > 8*MiB {
			bad("collectors.flows.receive_buffer must be between 64KiB and 8MiB")
		}
	}
	if w := co.WiFi; w.Interval != 0 {
		if w.Interval < 2*time.Second {
			bad("collectors.wifi.interval must be 0 (off) or at least 2s")
		}
		if w.Command == "" {
			bad("collectors.wifi.command is required")
		}
		if w.Timeout <= 0 || w.Timeout > w.Interval {
			bad("collectors.wifi.timeout must be in (0, interval]")
		}
	}
	if p := co.Processes; p.Interval != 0 && p.Interval < 5*time.Second {
		bad("collectors.processes.interval must be 0 (off) or at least 5s")
	}
	if cl := co.Clock; cl.Interval != 0 {
		if cl.Interval < 10*time.Second {
			bad("collectors.clock.interval must be 0 (off) or at least 10s")
		}
		if !ValidHost(cl.Server) {
			if a, err := netip.ParseAddr(cl.Server); err != nil || !UsableAddr(a) {
				bad("collectors.clock.server %q must be a hostname or public IPv4 address", cl.Server)
			}
		}
		if cl.Timeout <= 0 || cl.Timeout > 10*time.Second {
			bad("collectors.clock.timeout must be in (0, 10s]")
		}
	}
}

func (c *Config) validateUpload(bad func(string, ...any)) {
	u := c.Upload
	if !u.Enabled {
		return
	}
	if p, err := url.Parse(u.URL); err != nil || p.Scheme != "https" || p.Host == "" {
		bad("upload.url %q must be https://host/path", u.URL)
	}
	if u.TokenFile == "" {
		bad("upload.token_file is required")
	}
	if u.Interval < time.Second {
		bad("upload.interval must be at least 1s")
	}
	if u.Timeout <= 0 || u.Timeout > time.Minute {
		bad("upload.timeout must be in (0, 1m]")
	}
	if u.MaxBatch < 1 || u.MaxBatch > 20000 {
		bad("upload.max_batch must be between 1 and 20000")
	}
	if u.MaxBatchBytes < 64*KiB || u.MaxBatchBytes > 12*MiB {
		bad("upload.max_batch_bytes must be between 64KiB and 12MiB")
	}
	if u.Buffer < u.MaxBatchBytes {
		bad("upload.buffer must be at least upload.max_batch_bytes")
	}
	// The buffer lives on the Go heap; leave room for everything else under
	// the soft limit, or the runtime would collect garbage continuously.
	if lim := c.Runtime.MemoryLimit; lim > 0 && u.Buffer > lim-24*MiB {
		bad("upload.buffer %s leaves less than 24MiB under runtime.memory_limit %s", u.Buffer, lim)
	}
	if u.Heartbeat < 10*time.Second {
		bad("upload.heartbeat must be at least 10s")
	}
	if u.DrainOnStop < 0 || u.DrainOnStop > time.Minute {
		bad("upload.drain_on_stop must be between 0 and 1m")
	}
}

// DeviceFromHostname derives a device ID from a hostname.
func DeviceFromHostname(h string) string {
	h = strings.ToLower(h)
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-._")
	if s == "" {
		return "cpe"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
