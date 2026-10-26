package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultsValid(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Targets) != 6 || c.Targets[0].TTL != 1 || c.Targets[2].TTL != 3 {
		t.Fatalf("targets = %+v", c.Targets)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), false); err == nil {
		t.Fatal("missing required file accepted")
	}
}

func TestParseOverrides(t *testing.T) {
	c, err := Parse([]byte(`
device: ex7501-home
runtime:
  memory_limit: 32MiB
icmp:
  mode: raw
  timeout: 1500ms
targets:
  - {id: gw, category: infra, service: isp-gateway, auto: gateway}
  - {id: cf, category: infra, service: cloudflare, ip: 1.1.1.1, interval: 2s}
output:
  stdout: true
  jsonl:
    max_file_size: 1MiB
dns:
  enabled: false
collectors:
  lan:
    enabled: false
  clock:
    interval: 0s
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Device != "ex7501-home" || c.Runtime.MemoryLimit != 32*MiB || c.Runtime.GOMAXPROCS != 1 {
		t.Fatalf("runtime %+v device %q", c.Runtime, c.Device)
	}
	if c.ICMP.Mode != "raw" || c.ICMP.Timeout != 1500*time.Millisecond || c.ICMP.Interval != time.Second {
		t.Fatalf("icmp %+v", c.ICMP)
	}
	if len(c.Targets) != 2 || c.TargetInterval(c.Targets[1]) != 2*time.Second || c.TargetInterval(c.Targets[0]) != time.Second {
		t.Fatalf("targets %+v", c.Targets)
	}
	if !c.Output.Stdout || !c.Output.JSONL.Enabled || c.Output.JSONL.MaxFileSize != MiB || c.Output.JSONL.MaxFiles != 3 {
		t.Fatalf("output %+v", c.Output)
	}
	if r := c.ProbeRate(); r != 1.5 {
		t.Fatalf("rate %v", r)
	}
}

func TestParseEmptyUsesDefaults(t *testing.T) {
	c, err := Parse(nil)
	if err != nil || len(c.Targets) != 6 {
		t.Fatalf("%v %+v", err, c.Targets)
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"unknown key":   "icmp:\n  modee: raw\n",
		"bad mode":      "icmp:\n  mode: tcp\n",
		"fast interval": "icmp:\n  interval: 10ms\n",
		"bad duration":  "icmp:\n  timeout: soon\n",
		"bad size":      "runtime:\n  memory_limit: 32MB\n",
		"tiny limit":    "runtime:\n  memory_limit: 1MiB\n",
		"bad device":    "device: My Router\n",
		"dup id":        "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1}\n  - {id: a, category: c, service: s, ip: 8.8.8.8}\n",
		"both ip auto":  "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1, auto: gateway}\n",
		"neither":       "targets:\n  - {id: a, category: c, service: s}\n",
		"ipv6":          "targets:\n  - {id: a, category: c, service: s, ip: '2606:4700::1111'}\n",
		"loopback":      "targets:\n  - {id: a, category: c, service: s, ip: 127.0.0.1}\n",
		"bad auto":      "targets:\n  - {id: a, category: c, service: s, auto: dns}\n",
		"no service":    "targets:\n  - {id: a, category: c, ip: 1.1.1.1}\n",
		"upper id":      "targets:\n  - {id: A, category: c, service: s, ip: 1.1.1.1}\n",
		"budget":        "scheduler:\n  max_pps: 1\n",
		"ttl range":     "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1, ttl: 40}\n",
		"ttl auto":      "targets:\n  - {id: a, category: c, service: s, auto: gateway, ttl: 1}\n",
		"ttl host":      "targets:\n  - {id: a, category: c, service: s, host: www.example.com, ttl: 1}\n",
		"ip and host":   "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1, host: one.one.one.one}\n",
		"bad host":      "targets:\n  - {id: a, category: c, service: s, host: 'Not A Host'}\n",
		"single label":  "targets:\n  - {id: a, category: c, service: s, host: localhost}\n",
		"region name":   "catalog:\n  regions: ['../etc']\n",
		"resolve fast":  "catalog:\n  resolve_interval: 1s\n",
		"bad protocol":  "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1, protocols: [quic]}\n",
		"http on ip":    "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1, protocols: [http]}\n",
		"tcp on hop":    "targets:\n  - {id: a, category: c, service: s, ip: 1.1.1.1, ttl: 1, protocols: [tcp]}\n",
		"bad path":      "targets:\n  - {id: a, category: c, service: s, host: a.example.com, protocols: [http], path: health}\n",
		"doh http":      "dns:\n  doh: [{id: x, url: 'http://dns.example.com/q', ip: 8.8.8.8}]\n",
		"doh private":   "dns:\n  doh: [{id: x, url: 'https://dns.example.com/q', ip: 10.0.0.1}]\n",
		"doh dup":       "dns:\n  doh: [{id: x, url: 'https://a.example.com/q', ip: 8.8.8.8}, {id: x, url: 'https://b.example.com/q', ip: 1.1.1.1}]\n",
		"dns names":     "dns:\n  names: ['bad name']\n",
		"dns fast":      "dns:\n  interval: 1s\n",
		"zone":          "dns:\n  uncached_zone: 'not a zone'\n",
		"http fast":     "http:\n  interval: 1s\n",
		"tcp port":      "tcp:\n  port: 0\n",
		"wan fast":      "collectors:\n  wan:\n    interval: 100ms\n",
		"lan clients":   "collectors:\n  lan:\n    max_clients: 0\n",
		"lan pattern":   "collectors:\n  lan:\n    interfaces: ['[']\n",
		"clock server":  "collectors:\n  clock:\n    server: 'not a host'\n",
		"clock private": "collectors:\n  clock:\n    server: 192.168.1.1\n",
		"procs fast":    "collectors:\n  processes:\n    interval: 1s\n",
		"jsonl dir":     "output:\n  jsonl:\n    dir: ''\n",
		"nice":          "runtime:\n  nice: 25\n",
	}
	for name, in := range tests {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateReportsAllProblems(t *testing.T) {
	_, err := Parse([]byte("icmp:\n  mode: x\n  payload_size: 2\nscheduler:\n  burst: 0\n"))
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"icmp.mode", "payload_size", "burst"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
}

func TestLoadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(p, []byte("device: x\nicmp:\n  mode: nope\n"), 0o600)
	_, err := Load(p, false)
	if err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("err %v", err)
	}
}

func TestProtocolsAndRate(t *testing.T) {
	c, err := Parse([]byte(`
targets:
  - {id: a, category: c, service: s, host: www.example.com, protocols: [icmp, tcp, http], port: 8443, path: /health}
  - {id: b, category: c, service: s, ip: 1.1.1.1, protocols: [tcp]}
`))
	if err != nil {
		t.Fatal(err)
	}
	a, b := c.Targets[0], c.Targets[1]
	if !a.Wants(ProtoHTTP) || b.Wants(ProtoICMP) || c.TargetPort(a) != 8443 || c.TargetPort(b) != 443 {
		t.Fatalf("%+v %+v", a, b)
	}
	// icmp 1/s + two tcp at 1/10s + one http at 1/60s, plus DNS: five
	// layers at 1/30s and two identity names at 1/60s, plus 32 LAN clients
	// at 1/5s and the clock check at 1/60s.
	want := 1 + 0.2 + 1.0/60 + 5.0/30 + 2.0/60 + 32.0/5 + 1.0/60
	if r := c.ProbeRate(); r < want-1e-9 || r > want+1e-9 {
		t.Fatalf("rate %v, want %v", r, want)
	}
}

func TestHostTarget(t *testing.T) {
	c, err := Parse([]byte("targets:\n  - {id: youtube/www.youtube.com, category: streaming, service: youtube, host: www.youtube.com}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Targets[0].Host != "www.youtube.com" {
		t.Fatalf("%+v", c.Targets[0])
	}
}

func TestUsableAddr(t *testing.T) {
	tests := map[string]bool{
		"142.250.187.110": true,
		"1.1.1.1":         true,
		"0.0.0.0":         false,
		"127.0.0.1":       false,
		"10.1.2.3":        false,
		"192.168.1.10":    false,
		"100.90.232.1":    false,
		"169.254.1.1":     false,
		"224.0.0.1":       false,
		"2606:4700::1111": false,
	}
	for in, want := range tests {
		if got := UsableAddr(netip.MustParseAddr(in)); got != want {
			t.Errorf("UsableAddr(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestByteSize(t *testing.T) {
	good := map[string]ByteSize{"0": 0, "512": 512, "64KiB": 64 * KiB, "16 MiB": 16 * MiB, "1GiB": GiB, "100B": 100}
	for in, want := range good {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("%q = %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "1.5MiB", "-1", "16MB", "MiB", "99999999999GiB"} {
		if _, err := ParseByteSize(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if s := (48 * MiB).String(); s != "48MiB" {
		t.Fatalf("String = %s", s)
	}
	if s := ByteSize(1500).String(); s != "1500B" {
		t.Fatalf("String = %s", s)
	}
}

func TestDeviceFromHostname(t *testing.T) {
	tests := map[string]string{"EX7501-B0": "ex7501-b0", "my router!": "my-router", "": "cpe", "--": "cpe"}
	for in, want := range tests {
		if got := DeviceFromHostname(in); got != want {
			t.Errorf("%q = %q, want %q", in, got, want)
		}
	}
}
