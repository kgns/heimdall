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
	"regexp"
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
	DNS         DNS         `yaml:"dns"`
	Targets     []Target    `yaml:"targets"`
	Catalog     Catalog     `yaml:"catalog"`
	Output      Output      `yaml:"output"`
	SelfMetrics SelfMetrics `yaml:"self_metrics"`
	NetWatch    NetWatch    `yaml:"netwatch"`
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
}

// Protocol names.
const (
	ProtoICMP = "icmp"
	ProtoTCP  = "tcp"
	ProtoHTTP = "http"
)

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
// resolved through the local forwarder.
type Identity struct {
	Interval time.Duration `yaml:"interval"`
	Names    []string      `yaml:"names"`
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
			Enabled: true, Dir: "/var/tmp/heimdall", MaxFileSize: 4 * MiB, MaxFiles: 3,
		}},
		SelfMetrics: SelfMetrics{Interval: time.Minute},
		NetWatch:    NetWatch{Interval: 10 * time.Second},
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
		r += float64(layers) / d.Interval.Seconds()
		if d.Identity.Interval > 0 {
			r += float64(len(d.Identity.Names)) / d.Identity.Interval.Seconds()
		}
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
			if p != ProtoICMP && p != ProtoTCP && p != ProtoHTTP {
				bad("%s: protocol %q is not icmp, tcp or http", where, p)
			}
		}
		if (t.TTL != 0 || t.Auto != "") && (t.Wants(ProtoTCP) || t.Wants(ProtoHTTP)) {
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
	if len(d.Identity.Names) > 0 && d.Identity.Interval < 10*time.Second {
		bad("dns.identity.interval must be at least 10s")
	}
	for _, n := range d.Identity.Names {
		if !ValidHost(n) {
			bad("dns.identity.names: %q is not a valid hostname", n)
		}
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
