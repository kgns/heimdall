package config

import (
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
	if len(c.Targets) != 4 || c.Targets[0].Auto != AutoGateway {
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
	if err != nil || len(c.Targets) != 4 {
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
