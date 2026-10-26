package resolve

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/target"
)

type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	err     map[string]error
	calls   int
}

func (f *fakeDNS) set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var as []netip.Addr
	for _, a := range addrs {
		as = append(as, netip.MustParseAddr(a))
	}
	f.answers[host] = as
	delete(f.err, host)
}

func (f *fakeDNS) fail(host string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err[host] = err
}

func (f *fakeDNS) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if err := f.err[host]; err != nil {
		return nil, err
	}
	return f.answers[host], nil
}

type recorder struct {
	mu sync.Mutex
	s  []sample.Sample
}

func (r *recorder) emit(s sample.Sample) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.s = append(r.s, s)
}

func (r *recorder) events(name string) []sample.Sample {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []sample.Sample
	for _, s := range r.s {
		if s.Extra["event"] == name {
			out = append(out, s)
		}
	}
	return out
}

func setup() (*fakeDNS, *recorder, *Resolver) {
	dns := &fakeDNS{answers: map[string][]netip.Addr{}, err: map[string]error{}}
	rec := &recorder{}
	blocked := netip.MustParsePrefix("62.58.244.16/29")
	r := New(dns.lookup, func(a netip.Addr) bool { return !blocked.Contains(a) }, rec.emit,
		slog.New(slog.NewTextHandler(io.Discard, nil)), time.Second)
	return dns, rec, r
}

func hostTarget(host string) *target.Target {
	t := target.New("svc/"+host, "streaming", "svc", netip.Addr{})
	t.Host = host
	return t
}

func TestRefreshStickyChoice(t *testing.T) {
	dns, rec, r := setup()
	tg := hostTarget("www.youtube.com")
	if _, ok := tg.Dst(); ok {
		t.Fatal("unresolved target probeable")
	}

	dns.set("www.youtube.com", "142.251.150.4", "142.251.151.4")
	res := r.Refresh(context.Background(), tg)
	if !res.Changed || res.Chosen != netip.MustParseAddr("142.251.150.4") {
		t.Fatalf("first refresh %+v", res)
	}
	if d, ok := tg.Dst(); !ok || d != res.Chosen {
		t.Fatalf("dst %v %v", d, ok)
	}

	// Rotated answer that still contains the current address: keep it.
	dns.set("www.youtube.com", "142.251.152.4", "142.251.151.4", "142.251.150.4")
	if res := r.Refresh(context.Background(), tg); res.Changed || res.Chosen != netip.MustParseAddr("142.251.150.4") {
		t.Fatalf("rotation changed target: %+v", res)
	}

	// Current address gone: move to the first new one.
	dns.set("www.youtube.com", "142.251.152.4")
	if res := r.Refresh(context.Background(), tg); !res.Changed || res.Chosen != netip.MustParseAddr("142.251.152.4") {
		t.Fatalf("move %+v", res)
	}
	ev := rec.events("dst_change")
	if len(ev) != 2 || ev[1].Extra["prev"] != "142.251.150.4" || ev[1].DstIP != "142.251.152.4" {
		t.Fatalf("dst_change events %+v", ev)
	}
	if _, hasPrev := ev[0].Extra["prev"]; hasPrev {
		t.Fatal("first assignment carries prev")
	}
}

func TestRefreshFailureKeepsLastAddress(t *testing.T) {
	dns, rec, r := setup()
	tg := hostTarget("tvplus.com.tr")
	dns.set("tvplus.com.tr", "176.235.12.177")
	r.Refresh(context.Background(), tg)

	dns.fail("tvplus.com.tr", errors.New("i/o timeout"))
	for range 3 {
		if res := r.Refresh(context.Background(), tg); res.Err == nil || res.Chosen != netip.MustParseAddr("176.235.12.177") {
			t.Fatalf("failure result %+v", res)
		}
	}
	if d, ok := tg.Dst(); !ok || d != netip.MustParseAddr("176.235.12.177") {
		t.Fatal("last good address dropped on failure")
	}
	if n := len(rec.events("resolve_error")); n != 1 {
		t.Fatalf("%d resolve_error events, want 1 per failure streak", n)
	}
	dns.set("tvplus.com.tr", "176.235.12.177")
	r.Refresh(context.Background(), tg)
	if n := len(rec.events("resolve_recovered")); n != 1 {
		t.Fatalf("%d recovered events", n)
	}
}

func TestRefreshUnusableAnswers(t *testing.T) {
	dns, rec, r := setup()
	tg := hostTarget("blocked.example.com")
	dns.set("blocked.example.com", "0.0.0.0", "127.0.0.1", "10.0.0.5")
	r.Refresh(context.Background(), tg)
	r.Refresh(context.Background(), tg)
	if _, ok := tg.Dst(); ok {
		t.Fatal("block-page answer became a target")
	}
	if n := len(rec.events("resolve_unusable")); n != 1 {
		t.Fatalf("%d unusable events", n)
	}
}

func TestRefreshPrefersAllowedAddress(t *testing.T) {
	dns, _, r := setup()
	tg := hostTarget("svc.example.com")
	dns.set("svc.example.com", "62.58.244.17", "93.184.215.14")
	if res := r.Refresh(context.Background(), tg); res.Chosen != netip.MustParseAddr("93.184.215.14") {
		t.Fatalf("chose %v", res.Chosen)
	}
	if tg.Blocked() {
		t.Fatal("allowed address blocked")
	}

	dns.set("svc.example.com", "62.58.244.18")
	r.Refresh(context.Background(), tg)
	if _, ok := tg.Dst(); ok || !tg.Blocked() {
		t.Fatal("address behind the management route is probeable")
	}
}

func TestRefreshAllConcurrency(t *testing.T) {
	dns, _, r := setup()
	var targets []*target.Target
	for _, h := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"} {
		dns.set(h, "93.184.215.14")
		targets = append(targets, hostTarget(h))
	}
	r.RefreshAll(context.Background(), targets, 2)
	for _, tg := range targets {
		if _, ok := tg.Dst(); !ok {
			t.Fatalf("%s unresolved", tg.Host)
		}
	}
	if dns.calls != 5 {
		t.Fatalf("%d lookups", dns.calls)
	}
}
