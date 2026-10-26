package app

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/probes/stamp"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/target"
	"github.com/kgns/heimdall/probe/internal/whoami"
)

func testEnv(t *testing.T, cfg config.Config) (*env, *sample.MemorySink) {
	t.Helper()
	mem := &sample.MemorySink{}
	return &env{
		cfg:       cfg,
		rec:       sample.NewRecorder("test", nil, mem),
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		userAgent: "heimdall-test",
	}, mem
}

func TestTCPJob(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	cfg := config.Default()
	e, mem := testEnv(t, cfg)
	open := target.New("svc/open", "browsing", "svc", netip.MustParseAddr("127.0.0.1"))
	open.Port = port
	closedLn, _ := net.Listen("tcp4", "127.0.0.1:0")
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()
	closed := target.New("svc/closed", "browsing", "svc", netip.MustParseAddr("127.0.0.1"))
	closed.Port = closedPort
	unresolved := target.New("svc/none", "browsing", "svc", netip.Addr{})

	for _, tg := range []*target.Target{open, closed, unresolved} {
		e.tcpJob(tg).Run(context.Background())
	}
	got := mem.Samples()
	if len(got) != 2 {
		t.Fatalf("%d samples: %+v", len(got), got)
	}
	if s := got[0]; s.Kind != sample.KindTCP || s.Status != sample.StatusOK || s.RTTms == nil || s.DstPort != port {
		t.Fatalf("open %+v", s)
	}
	if s := got[1]; s.Status != sample.StatusRefused || s.RTTms == nil || s.Extra["reason"] != "refused" {
		t.Fatalf("closed %+v", s)
	}
}

func TestHTTPSampleFromFailure(t *testing.T) {
	cfg := config.Default()
	cfg.HTTP.Timeout = time.Second
	e, mem := testEnv(t, cfg)
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	tg := target.New("svc/www.example.com", "browsing", "svc", netip.MustParseAddr("127.0.0.1"))
	tg.Host, tg.Port = "www.example.com", port
	e.httpJob(tg).Run(context.Background())
	got := mem.Samples()
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	s := got[0]
	if s.Kind != sample.KindHTTP || s.Status != sample.StatusRefused || s.RTTms != nil || s.Extra["phase"] != "connect" {
		t.Fatalf("%+v", s)
	}
}

// fakeResolvers serves a forwarder and an upstream on loopback. The
// forwarder reports resolver identity changes through o-o.myaddr.
func fakeResolvers(t *testing.T, resolverIP *atomic.Value) (local, upstream netip.AddrPort) {
	t.Helper()
	start := func(h dns.HandlerFunc) netip.AddrPort {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := &dns.Server{PacketConn: pc, Handler: h}
		go srv.ActivateAndServe()
		t.Cleanup(func() { srv.Shutdown() })
		return netip.MustParseAddrPort(pc.LocalAddr().String())
	}
	answer := func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		name := q.Question[0].Name
		switch {
		case name == "cached.whoami.example.":
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"203.0.113.99"}})
		case name == "o-o.myaddr.l.google.com.":
			// Slow enough to count as an upstream answer, not a cache hit.
			time.Sleep(freshIdentityRTT + 5*time.Millisecond)
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{resolverIP.Load().(string)}})
		case q.Question[0].Qtype == dns.TypeA && dns.IsSubDomain("example.com.", name):
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("93.184.215.14")})
		default:
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	}
	return start(answer), start(answer)
}

func TestDNSProbes(t *testing.T) {
	var resolverIP atomic.Value
	resolverIP.Store("185.228.168.10")
	local, upstream := fakeResolvers(t, &resolverIP)
	fsys := fstest.MapFS{"etc/dnsmasq.conf": {Data: []byte(fmt.Sprintf(
		"port=%d\nno-resolv\nserver=127.0.0.1#%d\nserver=/corp.example/10.0.0.53\n", local.Port(), upstream.Port()))}}

	cfg := config.Default()
	cfg.DNS.Names = []string{"www.example.com", "cdn.example.com"}
	cfg.DNS.UncachedZone = "probe.example.com"
	cfg.DNS.DoH = nil
	cfg.DNS.Identity.Names = []string{"o-o.myaddr.l.google.com"}
	e, mem := testEnv(t, cfg)
	d := newDNSProbes(e, fsys, func(netip.Addr) bool { return true })
	defer d.close()

	ids := dnsLayerIDs(d.layers)
	want := []string{"dns/local/" + local.String(), "dns/upstream/" + upstream.String(), "dns/uncached/probe.example.com"}
	if fmt.Sprint(ids) != fmt.Sprint(want) || len(d.identity) != 1 {
		t.Fatalf("layers %v identity %d", ids, len(d.identity))
	}

	d.probeIdentity(context.Background(), d.identity[0])
	if d.ResolverID() != "185.228.168.10" {
		t.Fatalf("resolver %q", d.ResolverID())
	}
	for range 2 {
		for _, l := range d.layers {
			d.probe(context.Background(), l)
		}
	}
	resolverIP.Store("149.112.112.10")
	d.probeIdentity(context.Background(), d.identity[0])

	var qnames []string
	changes := 0
	for _, s := range mem.Samples() {
		switch {
		case s.Kind == sample.KindEvent && s.Extra["event"] == "resolver_change":
			changes++
			if changes == 2 && (s.Extra["prev"] != "185.228.168.10" || s.ResolverID != "149.112.112.10") {
				t.Fatalf("second change %+v", s)
			}
		case s.Kind == sample.KindDNS && s.Extra["layer"] != layerIdentity:
			if s.Status != sample.StatusOK || s.RTTms == nil || s.ResolverID != "185.228.168.10" {
				t.Fatalf("dns sample %+v", s)
			}
			qnames = append(qnames, s.Extra["layer"].(string)+":"+s.Extra["qname"].(string))
		case s.Kind == sample.KindDNS:
			if s.Extra["resolver"] == nil {
				t.Fatalf("identity sample without resolver %+v", s)
			}
		}
	}
	if changes != 2 {
		t.Fatalf("%d resolver_change events", changes)
	}

	// A fast (cached) identity answer is recorded but does not change the
	// current resolver.
	cached := d.identity[0]
	cached.id = "dns/identity/cached.whoami.example"
	d.probeIdentity(context.Background(), cached)
	last := mem.Samples()[len(mem.Samples())-1]
	if last.Extra["fresh"] != false || last.Extra["resolver"] != "203.0.113.99" || d.ResolverID() != "149.112.112.10" {
		t.Fatalf("cached identity %+v, current %q", last, d.ResolverID())
	}
	if len(qnames) != 6 || qnames[0] != "local:www.example.com" || qnames[3] != "local:cdn.example.com" ||
		qnames[1] != "upstream:www.example.com" || qnames[4] != "upstream:cdn.example.com" {
		t.Fatalf("name rotation %v", qnames)
	}
	if qnames[2] == qnames[5] || len(qnames[2]) < len("uncached:.probe.example.com")+16 {
		t.Fatalf("uncached names not random: %v", qnames)
	}
}

func TestDNSIdentityZone(t *testing.T) {
	zone := whoami.New("w.example.net", "ns.example.net", "hostmaster.example.net")
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		if dns.IsSubDomain("w.example.net.", q.Question[0].Name) {
			zone.ServeDNS(w, q)
			return
		}
		time.Sleep(freshIdentityRTT + 5*time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"203.0.113.7"}})
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	fsys := fstest.MapFS{"etc/dnsmasq.conf": {Data: []byte(fmt.Sprintf("port=%d\nno-resolv\n", port))}}

	cfg := config.Default()
	cfg.DNS.DoH = nil
	cfg.DNS.Identity.Names = []string{"o-o.myaddr.l.google.com"}
	cfg.DNS.Identity.Zone = "w.example.net"
	e, mem := testEnv(t, cfg)
	d := newDNSProbes(e, fsys, func(netip.Addr) bool { return true })
	defer d.close()
	if len(d.identity) != 2 || d.identity[0].id != "dns/identity/w.example.net" {
		t.Fatalf("identity layers %+v", d.identity)
	}
	for range 2 {
		d.probeIdentity(context.Background(), d.identity[0])
	}
	if d.ResolverID() != "127.0.0.1" {
		t.Fatalf("resolver %q", d.ResolverID())
	}
	// A fresh answer for a fixed name is recorded but the zone decides.
	d.probeIdentity(context.Background(), d.identity[1])
	if d.ResolverID() != "127.0.0.1" {
		t.Fatalf("fixed name overrode the zone: %q", d.ResolverID())
	}
	var qnames []string
	for _, s := range mem.Samples() {
		if s.Kind == sample.KindDNS {
			qnames = append(qnames, s.Extra["qname"].(string))
			if s.Extra["layer"] != layerIdentity || s.Extra["fresh"] != true {
				t.Fatalf("%+v", s)
			}
		}
	}
	if len(qnames) != 3 || qnames[0] == qnames[1] || !strings.HasSuffix(qnames[0], ".w.example.net") ||
		qnames[2] != "o-o.myaddr.l.google.com" {
		t.Fatalf("qnames %v", qnames)
	}
}

func TestSTAMPJob(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go stamp.NewReflector().Serve(ctx, pc)

	cfg := config.Default()
	cfg.STAMP.Port = pc.LocalAddr().(*net.UDPAddr).Port
	cfg.STAMP.Timeout = time.Second
	e, mem := testEnv(t, cfg)
	ss := &stampSenders{}
	defer ss.close()
	tg := target.New("aws-reflector", "infra", "aws-reflector", netip.MustParseAddr("127.0.0.1"))
	job := e.stampJob(tg, ss)
	for range 3 {
		job.Run(context.Background())
	}
	got := mem.Samples()
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	for i, s := range got {
		if s.Kind != sample.KindUDPEcho || s.Status != sample.StatusOK || s.RTTms == nil || s.DstPort != cfg.STAMP.Port ||
			s.Extra["proto"] != "stamp" || s.Extra["refl_seq"] != uint32(i) || s.Extra["fwd_hops"] != 0 {
			t.Fatalf("sample %d: %+v", i, s)
		}
	}
	if got[0].Extra["lost_up"] != nil || got[2].Extra["lost_up"] != 0 || got[2].Extra["lost_down"] != 0 {
		t.Fatalf("loss fields %+v %+v", got[0].Extra, got[2].Extra)
	}

	// No reflector: the probe times out and says so.
	cfg.STAMP.Port = cfg.STAMP.Port + 1
	cfg.STAMP.Timeout = 50 * time.Millisecond
	e2, mem2 := testEnv(t, cfg)
	e2.stampJob(tg, ss).Run(context.Background())
	if s := mem2.Samples()[0]; s.Status != sample.StatusTimeout || s.RTTms != nil || s.Extra["reason"] != "timeout" {
		t.Fatalf("%+v", s)
	}
}

func TestDNSProbesWithoutForwarder(t *testing.T) {
	fsys := fstest.MapFS{"etc/resolv.conf": {Data: []byte("nameserver 127.0.0.53\n")}}
	cfg := config.Default()
	cfg.DNS.DoH = nil
	e, _ := testEnv(t, cfg)
	d := newDNSProbes(e, fsys, func(netip.Addr) bool { return true })
	if ids := dnsLayerIDs(d.layers); len(ids) != 1 || ids[0] != "dns/system/127.0.0.53:53" {
		t.Fatalf("layers %v", ids)
	}
	if len(d.identity) != 2 {
		t.Fatalf("identity layers %d", len(d.identity))
	}

	cfg.DNS.Enabled = false
	e, _ = testEnv(t, cfg)
	if d := newDNSProbes(e, fsys, func(netip.Addr) bool { return true }); len(d.layers)+len(d.identity) != 0 {
		t.Fatal("disabled DNS probes still configured")
	}
}

func TestDNSProbesSkipGuardedServers(t *testing.T) {
	fsys := fstest.MapFS{"etc/dnsmasq.conf": {Data: []byte("no-resolv\nserver=62.58.244.20\nserver=127.0.0.1#5300\n")}}
	cfg := config.Default()
	cfg.DNS.DoH = []config.DoHServer{{ID: "blocked", URL: "https://dns.example.com/dns-query", IP: "62.58.244.21"}}
	e, _ := testEnv(t, cfg)
	blocked := netip.MustParsePrefix("62.58.244.16/29")
	d := newDNSProbes(e, fsys, func(a netip.Addr) bool { return !blocked.Contains(a) })
	if ids := dnsLayerIDs(d.layers); fmt.Sprint(ids) != "[dns/local/127.0.0.1:53 dns/upstream/127.0.0.1:5300]" {
		t.Fatalf("layers %v", ids)
	}
}
