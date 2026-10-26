package httpp

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// newServer starts a TLS server whose certificate is valid for
// "example.com", which the probe uses as SNI and Host.
func newServer(t *testing.T, h http.HandlerFunc) (netip.AddrPort, *x509.CertPool) {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	return netip.MustParseAddrPort(s.Listener.Addr().String()), pool
}

func TestProbePhases(t *testing.T) {
	var gotUA, gotHost string
	dst, pool := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotHost = r.UserAgent(), r.Host
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Cf-Ray", "8f2c1a2b3c4d5e6f-IST")
		w.Header().Set("Cf-Cache-Status", "HIT")
		w.Header().Set("Server", "cloudflare")
		w.Write([]byte(strings.Repeat("x", 100<<10)))
	})
	r := Probe(context.Background(), Request{Host: "example.com", Dst: dst, Timeout: 5 * time.Second, UserAgent: "heimdall-test", MaxBody: 1024, RootCAs: pool})
	if r.Status != sample.StatusOK || r.StatusCode != 200 || r.Proto != "HTTP/2.0" {
		t.Fatalf("%+v", r)
	}
	if r.Connect <= 0 || r.TLS <= 0 || r.TTFB < 20*time.Millisecond || r.FirstByte < r.TTFB || r.Total < r.FirstByte {
		t.Fatalf("phases %+v", r)
	}
	if r.Bytes != 1024 {
		t.Fatalf("body not capped: %d", r.Bytes)
	}
	if r.Edge != (Edge{CDN: "cloudflare", PoP: "IST", Server: "cloudflare", Cache: "HIT"}) {
		t.Fatalf("edge %+v", r.Edge)
	}
	if gotUA != "heimdall-test" || gotHost != "example.com" || r.TLSVersion != "TLS 1.3" {
		t.Fatalf("ua %q host %q tls %q", gotUA, gotHost, r.TLSVersion)
	}
}

func TestProbeDoesNotFollowRedirects(t *testing.T) {
	dst, pool := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	})
	r := Probe(context.Background(), Request{Host: "example.com", Dst: dst, Timeout: 5 * time.Second, RootCAs: pool})
	if r.Status != sample.StatusOK || r.StatusCode != http.StatusFound {
		t.Fatalf("%+v", r)
	}
}

func TestProbeTimeoutWaitingForFirstByte(t *testing.T) {
	dst, pool := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2 * time.Second):
		case <-r.Context().Done():
		}
	})
	r := Probe(context.Background(), Request{Host: "example.com", Dst: dst, Timeout: 200 * time.Millisecond, RootCAs: pool})
	if r.Status != sample.StatusTimeout || r.Phase != "ttfb" || r.TLS <= 0 {
		t.Fatalf("%+v", r)
	}
}

func TestProbeTLSVerifyFailure(t *testing.T) {
	dst, _ := newServer(t, func(http.ResponseWriter, *http.Request) {})
	r := Probe(context.Background(), Request{Host: "example.com", Dst: dst, Timeout: 2 * time.Second, RootCAs: x509.NewCertPool()})
	if r.Status != sample.StatusError || r.Reason != "tls_verify" || r.Phase != "tls" || r.Connect <= 0 {
		t.Fatalf("%+v", r)
	}
}

func TestProbeConnectFailure(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	r := Probe(context.Background(), Request{Host: "example.com", Dst: closed, Timeout: 2 * time.Second})
	if r.Status != sample.StatusRefused || r.Phase != "connect" {
		t.Fatalf("%+v", r)
	}
}

func TestEdgeFromHeaders(t *testing.T) {
	tests := []struct {
		h    map[string]string
		want Edge
	}{
		{map[string]string{"X-Amz-Cf-Pop": "IST50-P1", "X-Cache": "Hit from cloudfront", "Server": "AmazonS3"},
			Edge{CDN: "cloudfront", PoP: "IST50", Server: "AmazonS3", Cache: "Hit from cloudfront"}},
		{map[string]string{"X-Served-By": "cache-fra-eddf8230045-FRA, cache-ist-ltfm2340021-IST", "X-Cache": "MISS, HIT"},
			Edge{CDN: "fastly", PoP: "IST", Cache: "MISS, HIT"}},
		{map[string]string{"X-Served-By": "cache-sof1510034-SOF"}, Edge{CDN: "fastly", PoP: "SOF"}},
		{map[string]string{"Server": "AkamaiGHost"}, Edge{CDN: "akamai", Server: "AkamaiGHost"}},
		{map[string]string{"Server": "gws"}, Edge{CDN: "google", Server: "gws"}},
		{map[string]string{"Server": "nginx"}, Edge{Server: "nginx"}},
	}
	for _, tc := range tests {
		h := http.Header{}
		for k, v := range tc.h {
			h.Set(k, v)
		}
		if got := EdgeFromHeaders(h); got != tc.want {
			t.Errorf("%v: got %+v, want %+v", tc.h, got, tc.want)
		}
	}
}
