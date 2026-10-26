package dnsp

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// handler answers www.example.com with two A records, whoami names with
// identity TXT, big.example.com with a truncated UDP answer, and
// everything else with NXDOMAIN.
func handler(tcpHits *atomic.Int64) dns.HandlerFunc {
	return func(w dns.ResponseWriter, q *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(q)
		name := q.Question[0].Name
		_, isTCP := w.RemoteAddr().(*net.TCPAddr)
		if isTCP {
			tcpHits.Add(1)
		}
		switch name {
		case "www.example.com.":
			m.Answer = append(m.Answer,
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("93.184.215.14")},
				&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("93.184.215.15")})
		case "o-o.myaddr.l.google.com.":
			m.Answer = append(m.Answer,
				&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"185.228.168.10"}},
				&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"edns0-client-subnet 88.230.0.0/24"}})
		case "big.example.com.":
			if !isTCP {
				m.Truncated = true
				break
			}
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("93.184.215.16")})
		case "servfail.example.com.":
			m.Rcode = dns.RcodeServerFailure
		case "slow.example.com.":
			time.Sleep(300 * time.Millisecond)
		default:
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	}
}

func startServers(t *testing.T) (netip.AddrPort, *atomic.Int64) {
	t.Helper()
	var tcpHits atomic.Int64
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddrPort(pc.LocalAddr().String())
	ln, err := net.Listen("tcp4", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	h := handler(&tcpHits)
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: ln, Handler: h}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	return addr, &tcpHits
}

func TestPlainQuery(t *testing.T) {
	addr, tcpHits := startServers(t)
	ex := Plain{Server: addr}

	r := Query(context.Background(), ex, "www.example.com", dns.TypeA, time.Second)
	if r.Status != sample.StatusOK || r.Rcode != "NOERROR" || len(r.Addrs) != 2 || r.MinTTL != 120 || r.RTT <= 0 {
		t.Fatalf("%+v", r)
	}

	r = Query(context.Background(), ex, "nope.example.com", dns.TypeA, time.Second)
	if r.Status != sample.StatusOK || r.Rcode != "NXDOMAIN" || len(r.Addrs) != 0 || r.MinTTL != 0 {
		t.Fatalf("nxdomain %+v", r)
	}

	r = Query(context.Background(), ex, "big.example.com", dns.TypeA, time.Second)
	if r.Status != sample.StatusOK || len(r.Addrs) != 1 || tcpHits.Load() != 1 {
		t.Fatalf("truncation fallback %+v tcp=%d", r, tcpHits.Load())
	}

	r = Query(context.Background(), ex, "servfail.example.com", dns.TypeA, time.Second)
	if r.Status != sample.StatusError || r.Reason != "rcode_servfail" {
		t.Fatalf("servfail %+v", r)
	}

	r = Query(context.Background(), ex, "slow.example.com", dns.TypeA, 50*time.Millisecond)
	if r.Status != sample.StatusTimeout {
		t.Fatalf("timeout %+v", r)
	}
}

func TestIdentity(t *testing.T) {
	addr, _ := startServers(t)
	r := Query(context.Background(), Plain{Server: addr}, "o-o.myaddr.l.google.com", dns.TypeTXT, time.Second)
	id := ParseIdentity(r.TXT)
	if id.Resolver != netip.MustParseAddr("185.228.168.10") || id.ClientSubnet != "88.230.0.0/24" {
		t.Fatalf("%+v from %v", id, r.TXT)
	}

	aka := ParseIdentity([][]string{{"ns", "2001:db8::53"}, {"ecs", "88.230.0.0/24/0"}, {"ip", "192.0.2.1"}})
	if aka.Resolver != netip.MustParseAddr("2001:db8::53") || aka.ClientSubnet != "88.230.0.0/24/0" {
		t.Fatalf("akahelp %+v", aka)
	}
	if none := ParseIdentity([][]string{{"hello"}}); none.Resolver.IsValid() {
		t.Fatalf("garbage parsed: %+v", none)
	}
}

func TestDoH(t *testing.T) {
	var gotCT string
	var gotID atomic.Int64
	gotID.Store(-1)
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get("Content-Type")
		if r.URL.Path != "/dns-query" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotID.Store(int64(q.Id))
		m := new(dns.Msg)
		m.SetReply(q)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("142.250.187.100")})
		wire, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wire)
	}))
	srv.EnableHTTP2 = true
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := netip.MustParseAddrPort(srv.Listener.Addr().String())

	d, err := NewDoH("https://example.com/dns-query", addr, pool)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for range 3 {
		r := Query(context.Background(), d, "www.google.com", dns.TypeA, 2*time.Second)
		if r.Status != sample.StatusOK || len(r.Addrs) != 1 || r.Addrs[0] != netip.MustParseAddr("142.250.187.100") {
			t.Fatalf("%+v", r)
		}
	}
	if gotCT != "application/dns-message" || gotID.Load() != 0 {
		t.Fatalf("content type %q id %d", gotCT, gotID.Load())
	}
	if conns.Load() != 1 {
		t.Fatalf("%d connections for 3 queries; keep-alive not used", conns.Load())
	}

	bad, _ := NewDoH("https://example.com/other", addr, pool)
	defer bad.Close()
	if r := Query(context.Background(), bad, "www.google.com", dns.TypeA, 2*time.Second); r.Status != sample.StatusError || !strings.Contains(r.Err.Error(), "404") {
		t.Fatalf("404 %+v", r)
	}
	if _, err := NewDoH("http://example.com/dns-query", addr, pool); err == nil {
		t.Fatal("plain http accepted")
	}
}
