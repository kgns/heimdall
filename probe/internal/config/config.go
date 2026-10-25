// Package config loads and validates the probe configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
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
	Targets     []Target    `yaml:"targets"`
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

// Target is one ICMP destination. With TTL set, the echo request is sent
// towards IP with that IP TTL and the target measured is the router where
// it expires, which answers with ICMP time exceeded. This reaches routers
// that ignore echo requests addressed to themselves.
type Target struct {
	ID       string        `yaml:"id"`
	Category string        `yaml:"category"`
	Service  string        `yaml:"service"`
	IP       string        `yaml:"ip"`
	Auto     string        `yaml:"auto"`
	TTL      int           `yaml:"ttl"`
	Interval time.Duration `yaml:"interval"`
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
		Scheduler: Scheduler{MaxPPS: 60, Burst: 10},
		ICMP:      ICMP{Mode: "auto", Interval: time.Second, Timeout: 2 * time.Second, PayloadSize: 32},
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

// ProbeRate returns the configured probes per second across all targets.
func (c *Config) ProbeRate() float64 {
	var r float64
	for _, t := range c.Targets {
		r += 1 / c.TargetInterval(t).Seconds()
	}
	return r
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

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

	ids := map[string]bool{}
	for i, t := range c.Targets {
		where := fmt.Sprintf("targets[%d]", i)
		if t.ID != "" {
			where += " (" + t.ID + ")"
		}
		if !idPattern.MatchString(t.ID) {
			bad("%s: id must match %s", where, idPattern)
		} else if ids[t.ID] {
			bad("%s: duplicate id", where)
		}
		ids[t.ID] = true
		if t.Category == "" || t.Service == "" {
			bad("%s: category and service are required", where)
		}
		switch {
		case t.IP != "" && t.Auto != "":
			bad("%s: set either ip or auto, not both", where)
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
			bad("%s: ip or auto is required", where)
		}
		if t.TTL < 0 || t.TTL > MaxTargetTTL {
			bad("%s: ttl %d must be between 1 and %d", where, t.TTL, MaxTargetTTL)
		}
		if t.TTL != 0 && t.IP == "" {
			bad("%s: ttl needs ip, the address the probe is sent towards", where)
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
	if c.SelfMetrics.Interval < time.Second {
		bad("self_metrics.interval must be at least 1s")
	}
	if c.NetWatch.Interval < time.Second {
		bad("netwatch.interval must be at least 1s")
	}
	return errors.Join(errs...)
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
