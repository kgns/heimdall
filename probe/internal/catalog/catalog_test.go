package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kgns/heimdall/probe/internal/config"
)

const repoCatalog = "../../../catalog/targets.yaml"

func TestRepoCatalogLoads(t *testing.T) {
	services, err := Load(repoCatalog, []string{"tr"})
	if err != nil {
		t.Fatal(err)
	}
	cats := map[string]int{}
	for _, s := range services {
		cats[s.Category]++
	}
	for _, c := range []string{"streaming", "gaming", "video_calls", "voice", "messaging", "browsing", "social", "cloud_work"} {
		if cats[c] == 0 {
			t.Errorf("no %s services", c)
		}
	}

	cfg := config.Default()
	cfg.Targets = config.DefaultTargets()
	cfg.Catalog.Path = repoCatalog
	cfg.Catalog.Regions = []string{"tr"}
	sel, err := Apply(&cfg)
	if err != nil {
		t.Fatalf("repo catalog does not fit the default budget: %v", err)
	}
	if len(sel) != len(services) {
		t.Fatalf("selected %d of %d", len(sel), len(services))
	}
	if r := cfg.ProbeRate(); r > cfg.Scheduler.MaxPPS*0.75 {
		t.Fatalf("catalog uses %.0f of %.0f probes/s; leave headroom for TCP, DNS and HTTP probes", r, cfg.Scheduler.MaxPPS)
	}
}

func TestParseRejects(t *testing.T) {
	tests := map[string]string{
		"version":      "version: 2\nservices: []\n",
		"unknown key":  "version: 1\nservices:\n  - {id: a, name: A, category: browsing, hosts: [a.example], colour: red}\n",
		"category":     "version: 1\nservices:\n  - {id: a, name: A, category: email, hosts: [a.example]}\n",
		"no endpoints": "version: 1\nservices:\n  - {id: a, name: A, category: browsing}\n",
		"bad host":     "version: 1\nservices:\n  - {id: a, name: A, category: browsing, hosts: [A.Example]}\n",
		"private ip":   "version: 1\nservices:\n  - {id: a, name: A, category: browsing, ips: [10.0.0.1]}\n",
		"discovery":    "version: 1\nservices:\n  - {id: a, name: A, category: gaming, discovery: [magic]}\n",
		"protocol":     "version: 1\nservices:\n  - {id: a, name: A, category: browsing, hosts: [a.example], protocols: [quic]}\n",
		"bad id":       "version: 1\nservices:\n  - {id: A/B, name: A, category: browsing, hosts: [a.example]}\n",
		"no name":      "version: 1\nservices:\n  - {id: a, category: browsing, hosts: [a.example]}\n",
		"duplicate":    "version: 1\nservices:\n  - {id: a, name: A, category: browsing, hosts: [a.example]}\n  - {id: a, name: B, category: social, hosts: [b.example]}\n",
	}
	for name, in := range tests {
		if _, err := Parse([]byte(in), "test.yaml"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func writeCatalog(t *testing.T, global, region string) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "regions"), 0o755)
	p := filepath.Join(dir, "targets.yaml")
	os.WriteFile(p, []byte(global), 0o644)
	if region != "" {
		os.WriteFile(filepath.Join(dir, "regions", "xx.yaml"), []byte(region), 0o644)
	}
	return p
}

func TestLoadRegionsAndSelect(t *testing.T) {
	p := writeCatalog(t, `version: 1
services:
  - {id: yt, name: YouTube, category: streaming, hosts: [www.youtube.com]}
  - {id: gh, name: GitHub, category: cloud_work, hosts: [github.com]}
  - {id: off, name: Off, category: browsing, hosts: [off.example.com], enabled: false}
  - {id: aws, name: AWS, category: cloud_work, hosts: [dynamodb.eu-central-1.amazonaws.com], protocols: [tcp]}
  - {id: dns, name: DNS, category: infra, ips: [1.1.1.1, 8.8.8.8], icmp_interval: 2s}
`, `version: 1
region: xx
services:
  - {id: local, name: Local, category: streaming, hosts: [tv.example.com, cdn.example.com]}
`)
	all, err := Load(p, []string{"xx"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 6 || all[5].Source != filepath.Join(filepath.Dir(p), "regions", "xx.yaml") {
		t.Fatalf("services %+v", all)
	}

	sel := Select(all, nil, nil)
	if len(sel) != 5 {
		t.Fatalf("disabled service kept: %d", len(sel))
	}
	targets := Targets(sel, true)
	ids := []string{}
	for _, tg := range targets {
		ids = append(ids, tg.ID+"="+strings.Join(tg.Protocols, "+"))
	}
	want := "yt/www.youtube.com=icmp+tcp+http gh/github.com=icmp+tcp+http aws/dynamodb.eu-central-1.amazonaws.com=tcp " +
		"dns/1.1.1.1=icmp+tcp dns/8.8.8.8=icmp+tcp local/tv.example.com=icmp+tcp+http local/cdn.example.com=icmp+tcp+http"
	if strings.Join(ids, " ") != want {
		t.Fatalf("targets\n got %q\nwant %q", strings.Join(ids, " "), want)
	}
	if targets[3].IP != "1.1.1.1" || targets[3].Interval.Seconds() != 2 || targets[0].Host != "www.youtube.com" {
		t.Fatalf("target fields %+v", targets)
	}
	// Each target gets its own protocol slice.
	targets[0].Protocols[0] = "changed"
	if targets[1].Protocols[0] != "icmp" {
		t.Fatal("protocol slices are shared between targets")
	}

	if got := Select(all, []string{"streaming"}, nil); len(got) != 2 {
		t.Fatalf("only=streaming kept %d", len(got))
	}
	if got := Select(all, []string{"streaming", "gh"}, []string{"local"}); len(got) != 2 || got[1].ID != "gh" {
		t.Fatalf("only+exclude kept %+v", got)
	}
}

func TestLoadErrors(t *testing.T) {
	p := writeCatalog(t, "version: 1\nservices:\n  - {id: a, name: A, category: browsing, hosts: [a.example.com]}\n",
		"version: 1\nservices:\n  - {id: a, name: Again, category: browsing, hosts: [b.example.com]}\n")
	if _, err := Load(p, []string{"xx"}); err == nil || !strings.Contains(err.Error(), "both") {
		t.Fatalf("cross-file duplicate: %v", err)
	}
	if _, err := Load(p, []string{"missing"}); err == nil {
		t.Fatal("missing region accepted")
	}
}

func TestApplyBudgetAndClashes(t *testing.T) {
	p := writeCatalog(t, "version: 1\nservices:\n  - {id: a, name: A, category: browsing, hosts: [a.example.com, b.example.com, c.example.com]}\n", "")
	cfg := config.Default()
	cfg.Targets = []config.Target{{ID: "x", Category: "infra", Service: "x", IP: "1.1.1.1"}}
	cfg.Scheduler.MaxPPS = 3
	cfg.Catalog.Path = p
	if _, err := Apply(&cfg); err == nil || !strings.Contains(err.Error(), "max_pps") {
		t.Fatalf("budget overflow: %v", err)
	}

	cfg = config.Default()
	cfg.Targets = []config.Target{{ID: "a/a.example.com", Category: "infra", Service: "x", IP: "1.1.1.1"}}
	cfg.Catalog.Path = p
	if _, err := Apply(&cfg); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("id clash: %v", err)
	}

	cfg = config.Default()
	if s, err := Apply(&cfg); err != nil || s != nil {
		t.Fatalf("no catalog: %v %v", s, err)
	}
}

func TestDiscoveryTargets(t *testing.T) {
	f, err := Parse([]byte(`version: 1
services:
  - {id: netflix, name: Netflix, category: streaming, hosts: [www.netflix.com], discovery: [netflix_oca]}
  - {id: meet, name: Meet, category: video_calls, discovery: [stun], stun: ["stun.l.google.com:19302"]}
  - {id: gl, name: GameLift, category: gaming, discovery: [gamelift]}
`), "test")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	byID := map[string]config.Target{}
	for _, tg := range Targets(f.Services, true) {
		ids = append(ids, tg.ID)
		byID[tg.ID] = tg
	}
	want := "netflix/netflix_oca/1 netflix/netflix_oca/2 netflix/netflix_oca/3 netflix/www.netflix.com " +
		"meet/stun/1 gl/gamelift/1 gl/gamelift/2 gl/gamelift/3 gl/gamelift/4"
	if strings.Join(ids, " ") != want {
		t.Fatalf("targets %v", ids)
	}
	if tg := byID["netflix/netflix_oca/2"]; tg.Discovery != "netflix_oca" || tg.Port != 443 || !tg.Wants("tcp") {
		t.Fatalf("%+v", tg)
	}
	if tg := byID["gl/gamelift/1"]; tg.UDPPort != 7770 || !tg.Wants("udp") || tg.Wants("icmp") {
		t.Fatalf("%+v", tg)
	}
	if got := Targets(f.Services, false); len(got) != 1 {
		t.Fatalf("discovery off kept %d targets", len(got))
	}
	cfg := config.Default()
	cfg.Targets = Targets(f.Services, true)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"  - {id: x, name: X, category: voice, discovery: [stun]}\n",
		"  - {id: x, name: X, category: voice, discovery: [riot]}\n",
		"  - {id: x, name: X, category: voice, hosts: [a.example.com], stun: [\"a.example.com:3478\"]}\n",
	} {
		if _, err := Parse([]byte("version: 1\nservices:\n"+bad), "bad"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
