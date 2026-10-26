// Package catalog loads the service catalog, a YAML list of internet
// services grouped by usage category, and expands it into probe targets.
package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/discover"
)

// Categories are the usage categories a service may belong to.
var Categories = []string{
	"streaming", "gaming", "video_calls", "voice", "messaging",
	"browsing", "social", "cloud_work", "infra",
}

// Protocols are the measurement kinds a service may request.
var Protocols = []string{"icmp", "tcp", "http"}

// Discoverers name the mechanisms that find the servers a service really
// uses (video caches, game relays, voice regions), beyond its hostnames.
var Discoverers = slices.Sorted(maps.Keys(discover.Specs))

// File is one catalog file.
type File struct {
	Version  int       `yaml:"version"`
	Region   string    `yaml:"region"`
	Services []Service `yaml:"services"`
}

// Service is one internet service and how to reach it.
type Service struct {
	ID        string   `yaml:"id"`
	Name      string   `yaml:"name"`
	Category  string   `yaml:"category"`
	Hosts     []string `yaml:"hosts"`
	IPs       []string `yaml:"ips"`
	Discovery []string `yaml:"discovery"`
	// STUN lists host:port STUN servers of the service, for the stun
	// discoverer.
	STUN []string `yaml:"stun"`
	// Protocols defaults to icmp.
	Protocols    []string      `yaml:"protocols"`
	ICMPInterval time.Duration `yaml:"icmp_interval"`
	Enabled      *bool         `yaml:"enabled"`
	Notes        string        `yaml:"notes"`

	// Source is the file the service was loaded from.
	Source string `yaml:"-"`
}

// IsEnabled reports whether the service is switched on.
func (s Service) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

// DefaultProtocols apply to services that do not list their own: every
// service is measured at the network (ICMP), transport (TCP) and
// application (HTTPS) level, so the three can be compared.
var DefaultProtocols = []string{"icmp", "tcp", "http"}

// EffectiveProtocols returns the protocols the service is measured with.
func (s Service) EffectiveProtocols() []string {
	if len(s.Protocols) == 0 {
		return DefaultProtocols
	}
	return s.Protocols
}

// Wants reports whether the service requests protocol p.
func (s Service) Wants(p string) bool {
	return slices.Contains(s.EffectiveProtocols(), p)
}

var serviceID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

// Parse decodes and validates one catalog file.
func Parse(b []byte, source string) (File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return File{}, fmt.Errorf("%s: %w", source, err)
	}
	if f.Version != 1 {
		return File{}, fmt.Errorf("%s: unsupported catalog version %d", source, f.Version)
	}
	var errs []error
	seen := map[string]bool{}
	for i := range f.Services {
		s := &f.Services[i]
		s.Source = source
		if err := s.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: services[%d] (%s): %w", source, i, s.ID, err))
		}
		if seen[s.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate service %q", source, s.ID))
		}
		seen[s.ID] = true
	}
	return f, errors.Join(errs...)
}

func (s *Service) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !serviceID.MatchString(s.ID) {
		bad("id must match %s", serviceID)
	}
	if s.Name == "" {
		bad("name is required")
	}
	if !slices.Contains(Categories, s.Category) {
		bad("category %q is not one of %v", s.Category, Categories)
	}
	if len(s.Hosts) == 0 && len(s.IPs) == 0 && len(s.Discovery) == 0 {
		bad("needs hosts, ips or discovery")
	}
	for _, h := range s.Hosts {
		if !config.ValidHost(h) {
			bad("host %q is not a valid lowercase hostname", h)
		}
	}
	for _, ip := range s.IPs {
		a, err := netip.ParseAddr(ip)
		if err != nil || !config.UsableAddr(a) {
			bad("ip %q is not a public IPv4 address", ip)
		}
	}
	for _, d := range s.Discovery {
		if !slices.Contains(Discoverers, d) {
			bad("discovery %q is not one of %v", d, Discoverers)
		}
	}
	if slices.Contains(s.Discovery, "stun") != (len(s.STUN) > 0) {
		bad("stun discovery and the stun server list go together")
	}
	for _, p := range s.Protocols {
		if !slices.Contains(Protocols, p) {
			bad("protocol %q is not one of %v", p, Protocols)
		}
	}
	if s.ICMPInterval != 0 && s.ICMPInterval < 100*time.Millisecond {
		bad("icmp_interval %v is below 100ms", s.ICMPInterval)
	}
	return errors.Join(errs...)
}

// Load reads the global catalog and the requested regional packs, which
// live in regions/<name>.yaml next to it. A service ID may appear only once
// across all files.
func Load(path string, regions []string) ([]Service, error) {
	files := []string{path}
	for _, r := range regions {
		files = append(files, filepath.Join(filepath.Dir(path), "regions", r+".yaml"))
	}
	var out []Service
	origin := map[string]string{}
	var errs []error
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		f, err := Parse(b, p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, s := range f.Services {
			if prev, dup := origin[s.ID]; dup {
				errs = append(errs, fmt.Errorf("service %q defined in both %s and %s", s.ID, prev, p))
				continue
			}
			origin[s.ID] = p
			out = append(out, s)
		}
	}
	return out, errors.Join(errs...)
}

// Select applies the enabled flag and the only/exclude filters, which match
// service IDs or categories.
func Select(services []Service, only, exclude []string) []Service {
	match := func(s Service, list []string) bool {
		return slices.Contains(list, s.ID) || slices.Contains(list, s.Category)
	}
	var out []Service
	for _, s := range services {
		if !s.IsEnabled() || match(s, exclude) || (len(only) > 0 && !match(s, only)) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Targets turns each host and IP of the services into a target with ID
// "<service>/<host or ip>", measured with the service's protocols. HTTP
// needs a hostname, so IP entries drop it. With discovery on, each
// discoverer of a service adds targets "<service>/<discoverer>/<n>" whose
// address the discoverer sets at runtime.
func Targets(services []Service, discovery bool) []config.Target {
	var out []config.Target
	for _, s := range services {
		if discovery {
			out = append(out, discoveryTargets(s)...)
		}
		protos := s.EffectiveProtocols()
		for _, h := range s.Hosts {
			out = append(out, config.Target{
				ID: s.ID + "/" + h, Category: s.Category, Service: s.ID, Host: h,
				Interval: s.ICMPInterval, Protocols: slices.Clone(protos),
			})
		}
		ipProtos := slices.DeleteFunc(slices.Clone(protos), func(p string) bool { return p == "http" })
		if len(ipProtos) == 0 {
			continue
		}
		for _, ip := range s.IPs {
			out = append(out, config.Target{
				ID: s.ID + "/" + ip, Category: s.Category, Service: s.ID, IP: ip,
				Interval: s.ICMPInterval, Protocols: ipProtos,
			})
		}
	}
	return out
}

// Apply loads the catalog configured in cfg, appends its targets to
// cfg.Targets and re-validates the result, so that ID clashes and the probe
// budget cover catalog and configured targets together. It returns the
// selected services. A config without a catalog path is left unchanged.
func Apply(cfg *config.Config) ([]Service, error) {
	if cfg.Catalog.Path == "" {
		return nil, nil
	}
	all, err := Load(cfg.Catalog.Path, cfg.Catalog.Regions)
	if err != nil {
		return nil, err
	}
	services := Select(all, cfg.Catalog.Only, cfg.Catalog.Exclude)
	cfg.Targets = append(cfg.Targets, Targets(services, cfg.Discovery.Enabled)...)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return services, nil
}

func discoveryTargets(s Service) []config.Target {
	var out []config.Target
	for _, d := range s.Discovery {
		spec := discover.Specs[d]
		slots := spec.Slots
		if d == "stun" {
			slots = min(slots, len(s.STUN))
		}
		for n := 1; n <= slots; n++ {
			t := config.Target{
				ID: fmt.Sprintf("%s/%s/%d", s.ID, d, n), Category: s.Category, Service: s.ID,
				Discovery: d, Interval: s.ICMPInterval, Protocols: slices.Clone(spec.Protocols),
			}
			if d == "stun" {
				t.DiscoveryArgs = slices.Clone(s.STUN)
			}
			if slices.Contains(spec.Protocols, config.ProtoTCP) {
				t.Port = spec.Port
			}
			if slices.Contains(spec.Protocols, config.ProtoUDP) || slices.Contains(spec.Protocols, config.ProtoSTUN) {
				t.UDPPort = spec.Port
			}
			out = append(out, t)
		}
	}
	return out
}
