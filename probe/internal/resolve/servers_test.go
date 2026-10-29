package resolve

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeServer answers A queries for known.example. and NXDOMAIN otherwise.
func fakeServer(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Name {
		case "known.example.":
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "known.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A: net.ParseIP("203.0.113.7")})
		case "v6only.example.":
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestServerResolver(t *testing.T) {
	good := fakeServer(t)
	// Nothing listens on port 9 of 127.0.0.1, so the first server fails.
	dead := netip.MustParseAddrPort("127.0.0.1:9")
	r := NewServerResolver([]netip.AddrPort{dead, good}, 500*time.Millisecond)
	ctx := context.Background()

	addrs, err := r.Lookup(ctx, "known.example")
	if err != nil || len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("got %v %v", addrs, err)
	}
	if r.Last() != "127.0.0.1" {
		t.Errorf("last %q", r.Last())
	}
	if _, err := r.Lookup(ctx, "missing.example"); err == nil {
		t.Error("NXDOMAIN gave no error")
	}
	if _, err := r.Lookup(ctx, "v6only.example"); !errors.Is(err, ErrNoAddress) {
		t.Errorf("empty answer: %v", err)
	}

	fallback := WithFallback(NewServerResolver([]netip.AddrPort{dead}, 200*time.Millisecond).Lookup,
		func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("198.51.100.1")}, nil
		})
	if addrs, err := fallback(ctx, "anything.example"); err != nil || addrs[0] != netip.MustParseAddr("198.51.100.1") {
		t.Errorf("fallback: %v %v", addrs, err)
	}
}
