package trace

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// path simulates routers: hop i (1-based) is routers[i-1]; an empty entry
// never answers; beyond the list the destination answers.
type path struct {
	routers []string
	// balanced answers alternately from two addresses at this TTL.
	balanced int
	n        atomic.Int64
}

func (p *path) Ping(_ context.Context, dst netip.Addr, ttl int, _ time.Duration) icmp.Result {
	rtt := time.Duration(ttl) * time.Millisecond
	if ttl > len(p.routers) {
		return icmp.Result{Status: sample.StatusOK, RTT: rtt + 5*time.Millisecond}
	}
	r := p.routers[ttl-1]
	if r == "" {
		return icmp.Result{Status: sample.StatusTimeout}
	}
	if ttl == p.balanced && p.n.Add(1)%2 == 0 {
		r = "198.51.100.99"
	}
	return icmp.Result{Status: sample.StatusTimeExceeded, From: netip.MustParseAddr(r), RTT: rtt}
}

func TestRun(t *testing.T) {
	dst := netip.MustParseAddr("203.0.113.10")
	p := &path{routers: []string{"10.234.0.1", "", "198.51.100.1"}, balanced: 3}
	r := Run(context.Background(), p, dst, Options{MaxHops: 10, Probes: 2, Timeout: time.Second, Gap: time.Millisecond})
	if !r.Reached || len(r.Hops) != 4 || r.RTT != 9*time.Millisecond {
		t.Fatalf("%+v", r)
	}
	if h := r.Hops[0]; h.IP != "10.234.0.1" || *h.RTTms != 1 || h.Answers != 2 {
		t.Fatalf("hop 1 %+v", h)
	}
	if h := r.Hops[1]; h.IP != "" || h.RTTms != nil || h.Answers != 0 {
		t.Fatalf("silent hop %+v", h)
	}
	if h := r.Hops[2]; len(h.Other) != 1 || h.Answers != 2 {
		t.Fatalf("balanced hop %+v", h)
	}
	if h := r.Hops[3]; h.IP != dst.String() || h.TTL != 4 {
		t.Fatalf("destination %+v", h)
	}
}

func TestRunUnreached(t *testing.T) {
	p := &path{routers: []string{"10.234.0.1", "198.51.100.1", "", "", "", "", "", ""}}
	r := Run(context.Background(), p, netip.MustParseAddr("203.0.113.10"), Options{MaxHops: 6, Probes: 1, Timeout: time.Second})
	if r.Reached || len(r.Hops) != 2 {
		t.Fatalf("%+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := Run(ctx, p, netip.MustParseAddr("203.0.113.10"), Options{MaxHops: 6, Probes: 1, Timeout: time.Second}); r.Hops != nil {
		t.Fatalf("cancelled trace %+v", r)
	}
}
