package app

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
)

// echoConn answers every echo request after a fixed delay, except to
// destinations in drop.
type echoConn struct {
	mode   icmp.Mode
	delay  time.Duration
	drop   map[netip.Addr]bool
	in     chan []byte
	src    chan netip.Addr
	once   sync.Once
	closed chan struct{}
}

func newEchoConn(delay time.Duration, drop ...netip.Addr) *echoConn {
	c := &echoConn{delay: delay, drop: map[netip.Addr]bool{}, in: make(chan []byte, 256), src: make(chan netip.Addr, 256), closed: make(chan struct{})}
	for _, d := range drop {
		c.drop[d] = true
	}
	return c
}

func (c *echoConn) Mode() icmp.Mode {
	if c.mode != "" {
		return c.mode
	}
	return icmp.ModeRaw
}

var testHops = []netip.Addr{netip.MustParseAddr("10.234.0.1"), netip.MustParseAddr("10.36.7.234")}

// WriteTo answers TTL-limited requests with time exceeded from testHops
// and everything else with an echo reply from the destination.
func (c *echoConn) WriteTo(b []byte, dst netip.Addr, ttl int) error {
	if c.drop[dst] {
		return nil
	}
	m, err := xicmp.ParseMessage(1, b)
	if err != nil {
		return err
	}
	from := dst
	var reply []byte
	if ttl > 0 && ttl <= len(testHops) {
		from = testHops[ttl-1]
		quote := make([]byte, 20, 28)
		quote[0], quote[9] = 0x45, 1
		d := dst.As4()
		copy(quote[16:], d[:])
		quote = append(quote, b[:8]...)
		reply, _ = (&xicmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &xicmp.TimeExceeded{Data: quote}}).Marshal(nil)
	} else {
		m.Type = ipv4.ICMPTypeEchoReply
		reply, _ = m.Marshal(nil)
	}
	go func() {
		time.Sleep(c.delay)
		select {
		case c.in <- reply:
			c.src <- from
		case <-c.closed:
		}
	}()
	return nil
}

func (c *echoConn) ReadFrom(b []byte) (int, netip.Addr, int, error) {
	select {
	case p := <-c.in:
		return copy(b, p), <-c.src, 57, nil
	case <-c.closed:
		return 0, netip.Addr{}, 0, icmp.ErrClosed
	}
}

func (c *echoConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func testHost(t *testing.T, conn icmp.Conn, mem *sample.MemorySink) Host {
	t.Helper()
	route, err := os.ReadFile("../../testdata/hosts/ex7501/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	return Host{
		FS: fstest.MapFS{
			"proc/net/route":   {Data: route},
			"proc/self/status": {Data: []byte("VmRSS:\t9000 kB\n")},
		},
		Interface: func(string) (sysinfo.Interface, error) {
			return sysinfo.Interface{Name: "ppp1.4", IPv4: []netip.Addr{netip.MustParseAddr("10.234.57.8")}}, nil
		},
		ListenICMP: func(icmp.Mode) (icmp.Conn, error) { return conn, nil },
		Hostname:   func() (string, error) { return "EX7501-B0", nil },
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			switch host {
			case "www.youtube.com":
				return []netip.Addr{netip.MustParseAddr("142.251.150.4")}, nil
			case "blocked.example.com":
				return []netip.Addr{netip.MustParseAddr("0.0.0.0")}, nil
			}
			return nil, errors.New("no such host")
		},
		Now:        time.Now,
		Stdout:     io.Discard,
		ExtraSinks: []sample.Sink{mem},
	}
}

func TestRunEmitsSamples(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled = false
	cfg.Output.JSONL.Enabled = true
	cfg.Output.JSONL.Dir = t.TempDir()
	cfg.ICMP.Interval = 100 * time.Millisecond
	cfg.ICMP.Timeout = 150 * time.Millisecond
	cfg.SelfMetrics.Interval = time.Second
	cfg.Targets = []config.Target{
		{ID: "gateway", Category: "infra", Service: "isp-gateway", Auto: config.AutoGateway},
		{ID: "cf", Category: "infra", Service: "cloudflare", IP: "1.1.1.1"},
		{ID: "lost", Category: "infra", Service: "blackhole", IP: "192.0.2.1"},
		{ID: "mgmt", Category: "infra", Service: "operator", IP: "62.58.244.17"},
		{ID: "hop2", Category: "infra", Service: "isp-hop", IP: "1.1.1.1", TTL: 2},
		{ID: "hop9", Category: "infra", Service: "isp-hop", IP: "1.1.1.1", TTL: 9},
		{ID: "youtube/www.youtube.com", Category: "streaming", Service: "youtube", Host: "www.youtube.com"},
		{ID: "x/blocked.example.com", Category: "browsing", Service: "x", Host: "blocked.example.com"},
		{ID: "x/nxdomain.example.com", Category: "browsing", Service: "x", Host: "nxdomain.example.com"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	mem := &sample.MemorySink{}
	conn := newEchoConn(5*time.Millisecond, netip.MustParseAddr("192.0.2.1"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	if err := Run(ctx, cfg, "test", testHost(t, conn, mem), log); err != nil {
		t.Fatal(err)
	}

	byTarget := map[string]map[sample.Status]int{}
	events := map[string]int{}
	selfSamples := 0
	for _, s := range mem.Samples() {
		if s.Device != "ex7501-b0" {
			t.Fatalf("device %q", s.Device)
		}
		switch s.Kind {
		case sample.KindICMP:
			if byTarget[s.TargetID] == nil {
				byTarget[s.TargetID] = map[sample.Status]int{}
			}
			byTarget[s.TargetID][s.Status]++
			if s.Status == sample.StatusOK && (s.RTTms == nil || *s.RTTms < 5 || s.Extra["ttl"] != 57) {
				t.Fatalf("ok sample %+v", s)
			}
			if s.Status == sample.StatusTimeout && s.RTTms != nil {
				t.Fatalf("timeout with rtt %+v", s)
			}
			if s.TargetID == "gateway" && s.DstIP != "10.234.0.1" {
				t.Fatalf("gateway dst %s", s.DstIP)
			}
			if s.TargetID == "hop2" && (s.Status != sample.StatusOK || s.DstIP != "10.36.7.234" ||
				s.Extra["via"] != "1.1.1.1" || s.Extra["ttl_limit"] != 2) {
				t.Fatalf("hop sample %+v", s)
			}
			if s.TargetID == "hop9" && (s.Status != sample.StatusError || s.RTTms != nil || s.DstIP != "") {
				t.Fatalf("hop beyond destination %+v", s)
			}
		case sample.KindEvent:
			events[s.Extra["event"].(string)]++
		case sample.KindSelf:
			selfSamples++
		}
	}
	if byTarget["gateway"][sample.StatusOK] < 8 || byTarget["cf"][sample.StatusOK] < 8 {
		t.Fatalf("ok counts %+v", byTarget)
	}
	if byTarget["youtube/www.youtube.com"][sample.StatusOK] < 8 {
		t.Fatalf("host target counts %+v", byTarget["youtube/www.youtube.com"])
	}
	for _, id := range []string{"x/blocked.example.com", "x/nxdomain.example.com"} {
		if _, probed := byTarget[id]; probed {
			t.Fatalf("%s probed without a usable address", id)
		}
	}
	if events["dst_change"] != 1 || events["resolve_unusable"] != 1 || events["resolve_error"] != 1 {
		t.Fatalf("resolve events %+v", events)
	}
	if byTarget["hop2"][sample.StatusOK] < 8 || byTarget["hop9"][sample.StatusError] < 8 {
		t.Fatalf("hop counts %+v %+v", byTarget["hop2"], byTarget["hop9"])
	}
	if byTarget["lost"][sample.StatusTimeout] < 6 || byTarget["lost"][sample.StatusOK] != 0 {
		t.Fatalf("loss counts %+v", byTarget["lost"])
	}
	if _, probed := byTarget["mgmt"]; probed {
		t.Fatal("management network target was probed")
	}
	if events["start"] != 1 || events["stop"] != 1 || events["target_blocked"] != 1 {
		t.Fatalf("events %+v", events)
	}
	if selfSamples < 1 {
		t.Fatal("no self metrics")
	}

	entries, err := os.ReadDir(cfg.Output.JSONL.Dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("jsonl dir: %v %v", entries, err)
	}
	if st, _ := entries[0].Info(); st.Size() == 0 {
		t.Fatal("jsonl file empty after shutdown")
	}
}

func TestRunSkipsTTLTargetsWithoutRawSocket(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled = false
	cfg.Output.JSONL.Enabled = false
	cfg.ICMP.Interval = 100 * time.Millisecond
	cfg.Targets = []config.Target{
		{ID: "hop1", Category: "infra", Service: "isp-hop", IP: "1.1.1.1", TTL: 1},
		{ID: "cf", Category: "infra", Service: "cloudflare", IP: "1.1.1.1"},
	}
	mem := &sample.MemorySink{}
	conn := newEchoConn(time.Millisecond)
	conn.mode = icmp.ModeDgram
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if err := Run(ctx, cfg, "test", testHost(t, conn, mem), log); err != nil {
		t.Fatal(err)
	}
	unsupported, cf := 0, 0
	for _, s := range mem.Samples() {
		if s.TargetID == "hop1" && s.Kind == sample.KindICMP {
			t.Fatalf("TTL target probed in dgram mode: %+v", s)
		}
		if s.Kind == sample.KindEvent && s.Extra["event"] == "target_unsupported" {
			unsupported++
		}
		if s.TargetID == "cf" && s.Status == sample.StatusOK {
			cf++
		}
	}
	if unsupported != 1 || cf == 0 {
		t.Fatalf("unsupported events %d, cf samples %d", unsupported, cf)
	}
}

func TestRunUploads(t *testing.T) {
	var mu sync.Mutex
	kinds := map[string]int{}
	var envelopes []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var env map[string]any
		if err := json.NewDecoder(zr).Decode(&env); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, s := range env["samples"].([]any) {
			m := s.(map[string]any)
			k := m["kind"].(string)
			if k == "event" {
				k += ":" + m["extra"].(map[string]any)["event"].(string)
			}
			kinds[k]++
		}
		delete(env, "samples")
		envelopes = append(envelopes, env)
		w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()

	tokenFile := filepath.Join(t.TempDir(), "upload.token")
	os.WriteFile(tokenFile, []byte("test-token\n"), 0o600)

	cfg := config.Default()
	cfg.DNS.Enabled = false
	cfg.Output.JSONL.Enabled = false
	cfg.ICMP.Interval = 100 * time.Millisecond
	cfg.Collectors.LAN.Enabled = false
	cfg.Collectors.Clock.Interval = 0
	cfg.Targets = []config.Target{{ID: "cf", Category: "infra", Service: "cloudflare", IP: "1.1.1.1"}}
	cfg.Upload = config.Upload{
		Enabled: true, URL: srv.URL + "/v1/batch", TokenFile: tokenFile, Interval: time.Second, Timeout: 5 * time.Second,
		Buffer: 4 * config.MiB, MaxBatch: 1000, MaxBatchBytes: config.MiB, Heartbeat: 10 * time.Second, DrainOnStop: 5 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h := testHost(t, newEchoConn(time.Millisecond), &sample.MemorySink{})
	h.UploadClient = srv.Client()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := Run(ctx, cfg, "test", h, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if kinds["event:start"] != 1 || kinds["event:stop"] != 1 || kinds["icmp"] < 10 || kinds["heartbeat"] < 1 {
		t.Fatalf("uploaded kinds %v", kinds)
	}
	if len(envelopes) == 0 || envelopes[0]["device"] != "ex7501-b0" || envelopes[0]["run_id"] == "" {
		t.Fatalf("envelopes %v", envelopes)
	}
}

func TestRunFailsWithoutToken(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled = false
	cfg.Output.JSONL.Enabled = false
	cfg.Upload.Enabled = true
	cfg.Upload.URL = "https://ingest.example.com/v1/batch"
	cfg.Upload.TokenFile = filepath.Join(t.TempDir(), "missing")
	err := Run(context.Background(), cfg, "test", testHost(t, newEchoConn(0), &sample.MemorySink{}), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "upload token") {
		t.Fatalf("err %v", err)
	}
}

func TestRunShutdownWithInFlightProbes(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.Enabled = false
	cfg.Output.JSONL.Enabled = false
	cfg.ICMP.Interval = 100 * time.Millisecond
	cfg.ICMP.Timeout = 10 * time.Second
	cfg.Targets = []config.Target{{ID: "x", Category: "infra", Service: "x", IP: "192.0.2.1"}}
	mem := &sample.MemorySink{}
	conn := newEchoConn(0, netip.MustParseAddr("192.0.2.1"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := Run(ctx, cfg, "test", testHost(t, conn, mem), log); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("shutdown took %v", el)
	}
	for _, s := range mem.Samples() {
		if s.Kind == sample.KindICMP {
			t.Fatalf("cancelled probe produced a sample: %+v", s)
		}
	}
}
