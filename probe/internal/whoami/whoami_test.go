package whoami

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/probes/dnsp"
)

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestAnswer(t *testing.T) {
	z := New("w.lat.kgns.dev", "ns.lat.kgns.dev", "hostmaster.kgns.dev")
	src := netip.MustParseAddr("89.117.2.17")

	m := z.Answer(query("a1b2.W.lat.kgns.dev", dns.TypeTXT), src)
	if !m.Authoritative || m.Rcode != dns.RcodeSuccess || len(m.Answer) != 1 {
		t.Fatalf("%v", m)
	}
	txt := m.Answer[0].(*dns.TXT)
	if txt.Txt[0] != "ns" || txt.Txt[1] != "89.117.2.17" || txt.Hdr.Ttl != 0 || txt.Hdr.Name != "a1b2.W.lat.kgns.dev." {
		t.Fatalf("%v", txt)
	}
	id := dnsp.ParseIdentity([][]string{txt.Txt})
	if id.Resolver != src {
		t.Fatalf("identity %v", id)
	}

	m = z.Answer(query("x.w.lat.kgns.dev", dns.TypeA), src)
	if a := m.Answer[0].(*dns.A); a.A.String() != "89.117.2.17" {
		t.Fatalf("%v", m)
	}
	m = z.Answer(query("x.w.lat.kgns.dev", dns.TypeAAAA), src)
	if len(m.Answer) != 0 || len(m.Ns) != 1 || m.Rcode != dns.RcodeSuccess {
		t.Fatalf("AAAA for an IPv4 resolver: %v", m)
	}
	m = z.Answer(query("w.lat.kgns.dev", dns.TypeSOA), src)
	if _, ok := m.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("%v", m)
	}
	m = z.Answer(query("w.lat.kgns.dev", dns.TypeNS), src)
	if ns := m.Answer[0].(*dns.NS); ns.Ns != "ns.lat.kgns.dev." {
		t.Fatalf("%v", m)
	}
	m = z.Answer(query("www.example.com", dns.TypeA), src)
	if m.Rcode != dns.RcodeRefused || m.Authoritative {
		t.Fatalf("out-of-zone name: %v", m)
	}
	if z.Stats().Refused != 1 {
		t.Fatalf("%+v", z.Stats())
	}
}

func TestClientSubnet(t *testing.T) {
	z := New("w.lat.kgns.dev.", "ns.lat.kgns.dev.", "hostmaster.kgns.dev.")
	q := query("x.w.lat.kgns.dev", dns.TypeTXT)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = append(q.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.ParseIP("88.230.12.34").To4(),
	})
	m := z.Answer(q, netip.MustParseAddr("8.8.4.4"))
	if len(m.Answer) != 2 {
		t.Fatalf("%v", m)
	}
	var txt [][]string
	for _, rr := range m.Answer {
		txt = append(txt, rr.(*dns.TXT).Txt)
	}
	id := dnsp.ParseIdentity(txt)
	if id.Resolver.String() != "8.8.4.4" || id.ClientSubnet != "88.230.12.0/24" {
		t.Fatalf("%+v", id)
	}
	opt := m.IsEdns0()
	if opt == nil || opt.Option[0].(*dns.EDNS0_SUBNET).SourceScope != 0 {
		t.Fatalf("ECS option not echoed with scope 0: %v", opt)
	}
}

func TestServeUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: New("w.test", "ns.test", "h.test")}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)
	ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	r := dnsp.Query(context.Background(), dnsp.Plain{Server: ap}, "abc.w.test", dns.TypeTXT, time.Second)
	if r.Status != "ok" || dnsp.ParseIdentity(r.TXT).Resolver.String() != "127.0.0.1" {
		t.Fatalf("%+v", r)
	}
}
