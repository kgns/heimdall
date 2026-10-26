package icmp

import (
	"context"
	"net/netip"
	"os"
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

// TestTTLAppliedOnWire checks against a real internet host that a
// TTL-limited request never reaches it while a default one does, and that
// the socket TTL is restored afterwards. It needs internet access and is
// enabled with HEIMDALL_NET_TESTS=1.
func TestTTLAppliedOnWire(t *testing.T) {
	if os.Getenv("HEIMDALL_NET_TESTS") != "1" {
		t.Skip("set HEIMDALL_NET_TESTS=1 to run")
	}
	conn, err := Listen(ModeAuto)
	if err != nil {
		t.Skipf("no ICMP socket available: %v", err)
	}
	p, err := New(conn, Options{PayloadSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	dst := netip.MustParseAddr("1.1.1.1")

	if r := p.Ping(context.Background(), dst, 0, 2*time.Second); r.Status != sample.StatusOK {
		t.Fatalf("default TTL ping failed: %+v", r)
	}
	r := p.Ping(context.Background(), dst, 1, 2*time.Second)
	switch {
	case r.Status == sample.StatusOK:
		t.Fatalf("TTL 1 request reached %s: TTL not applied", dst)
	case p.Mode() == ModeRaw && r.Status != sample.StatusTimeExceeded:
		t.Fatalf("raw mode expected time exceeded, got %+v", r)
	}
	t.Logf("mode %s ttl=1 result %s from %v after %v", p.Mode(), r.Status, r.From, r.RTT)
	if r := p.Ping(context.Background(), dst, 0, 2*time.Second); r.Status != sample.StatusOK {
		t.Fatalf("socket TTL not restored: %+v", r)
	}
}
