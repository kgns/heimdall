package app

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/probes/trace"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/target"
)

type twoHops struct{}

func (twoHops) Ping(_ context.Context, dst netip.Addr, ttl int, _ time.Duration) icmp.Result {
	if ttl == 1 {
		return icmp.Result{Status: sample.StatusTimeExceeded, From: netip.MustParseAddr("10.234.0.1"), RTT: time.Millisecond}
	}
	return icmp.Result{Status: sample.StatusOK, RTT: 10 * time.Millisecond}
}

func TestTracer(t *testing.T) {
	cfg := config.Default()
	cfg.Trace.Gap = 0
	e, mem := testEnv(t, cfg)
	a := target.New("cloudflare-dns", "infra", "cloudflare", netip.MustParseAddr("1.1.1.1"))
	hop := target.New("isp-hop1", "infra", "isp-hop", netip.MustParseAddr("1.1.1.1"))
	hop.TTL = 1
	same := target.New("cloudflare/www.cloudflare.com", "browsing", "cloudflare", netip.MustParseAddr("1.1.1.1"))
	none := target.New("svc/unresolved", "browsing", "svc", netip.Addr{})
	b := target.New("google-dns", "infra", "google", netip.MustParseAddr("8.8.8.8"))
	tr := newTracer(e, twoHops{}, []*target.Target{a, hop, same, none, b})
	if len(tr.targets) != 4 {
		t.Fatalf("TTL target kept: %d", len(tr.targets))
	}
	job := tr.job()
	for range 3 {
		job.Run(context.Background())
	}
	got := mem.Samples()
	// 1.1.1.1 once (the second target with it is skipped), then 8.8.8.8;
	// the third run finds nothing new within the round.
	if len(got) != 2 || got[0].TargetID != "cloudflare-dns" || got[1].TargetID != "google-dns" {
		t.Fatalf("%+v", got)
	}
	s := got[0]
	hops := s.Extra["hops"].([]trace.Hop)
	if s.Kind != sample.KindTrace || s.Status != sample.StatusOK || *s.RTTms != 10 || len(hops) != 2 ||
		hops[0].IP != "10.234.0.1" || hops[1].IP != "1.1.1.1" || s.Extra["reached"] != true {
		t.Fatalf("%+v", s)
	}
}
