package icmp

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// TestLoopbackSocket pings 127.0.0.1 through a real socket when the host
// permits either socket mode.
func TestLoopbackSocket(t *testing.T) {
	conn, err := Listen(ModeAuto)
	if err != nil {
		t.Skipf("no ICMP socket available: %v", err)
	}
	p, err := New(conn, Options{PayloadSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	r := p.Ping(context.Background(), netip.MustParseAddr("127.0.0.1"), 0, 2*time.Second)
	if r.Status != sample.StatusOK {
		t.Fatalf("mode %s: %+v", p.Mode(), r)
	}
	if r.RTT <= 0 || r.RTT > time.Second {
		t.Fatalf("rtt %v", r.RTT)
	}
	t.Logf("mode %s rtt %v ttl %d", p.Mode(), r.RTT, r.TTL)
}
