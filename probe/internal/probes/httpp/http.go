// Package httpp measures one HTTPS request to a fixed address, broken into
// connect, TLS handshake and time to first byte, and records the CDN edge
// that answered when the response headers reveal it.
package httpp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"

	// Embedded Mozilla roots, used only when the host has no CA bundle.
	_ "golang.org/x/crypto/x509roots/fallback"

	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/probes/tlsconf"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// Request describes one probe.
type Request struct {
	Host      string
	Path      string
	Dst       netip.AddrPort
	Timeout   time.Duration
	UserAgent string
	MaxBody   int64
	// RootCAs overrides the trust store, for tests.
	RootCAs *x509.CertPool
}

// Result is the outcome with phase timings. Zero durations mean the phase
// was not reached.
type Result struct {
	Status sample.Status
	Reason string
	// Phase is where a failure happened: connect, tls, request, ttfb or body.
	Phase string
	Sent  time.Time

	Connect time.Duration
	TLS     time.Duration
	// TTFB runs from the request being written to the first response byte:
	// one round trip plus server think time.
	TTFB time.Duration
	// FirstByte runs from the start of the probe to the first response
	// byte: what a browser waits for on a fresh connection.
	FirstByte time.Duration
	Total     time.Duration

	StatusCode int
	Proto      string
	TLSVersion string
	// KeyExchange is the negotiated group, e.g. X25519MLKEM768.
	KeyExchange string
	Bytes       int64
	Edge        Edge
	Err         error
}

// Edge is what the response headers say about the serving CDN node.
type Edge struct {
	CDN    string `json:"cdn,omitempty"`
	PoP    string `json:"pop,omitempty"`
	Server string `json:"server,omitempty"`
	Cache  string `json:"cache,omitempty"`
}

// Probe performs one request on a fresh connection and does not follow
// redirects.
func Probe(ctx context.Context, req Request) Result {
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	if req.Path == "" {
		req.Path = "/"
	}
	if req.MaxBody <= 0 {
		req.MaxBody = 32 << 10
	}

	var (
		mu                              sync.Mutex
		start                           = time.Now()
		connStart, connDone             time.Time
		tlsStart, tlsDone, wrote, first time.Time
	)
	mark := func(p *time.Time) {
		mu.Lock()
		if p.IsZero() {
			*p = time.Now()
		}
		mu.Unlock()
	}
	// The Done hooks also fire on failure; only successful phases count.
	trace := &httptrace.ClientTrace{
		ConnectStart: func(string, string) { mark(&connStart) },
		ConnectDone: func(_, _ string, err error) {
			if err == nil {
				mark(&connDone)
			}
		},
		TLSHandshakeStart: func() { mark(&tlsStart) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				mark(&tlsDone)
			}
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { mark(&wrote) },
		GotFirstResponseByte: func() { mark(&first) },
	}

	var dialer net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", req.Dst.String())
		},
		TLSClientConfig:        tlsconf.Client(req.Host, req.RootCAs),
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    req.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	hreq, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, "https://"+req.Host+req.Path, nil)
	if err != nil {
		return Result{Status: sample.StatusError, Reason: "request", Phase: "request", Sent: start, Err: err}
	}
	if req.UserAgent != "" {
		hreq.Header.Set("User-Agent", req.UserAgent)
	}
	hreq.Header.Set("Accept", "*/*")

	resp, err := client.Do(hreq)
	r := Result{Sent: start}
	mu.Lock()
	fill(&r, start, connStart, connDone, tlsStart, tlsDone, wrote, first)
	mu.Unlock()
	if err != nil {
		r.Status, r.Reason = neterr.Classify(err)
		r.Phase = failedPhase(connDone, tlsDone, wrote, first)
		r.Err = err
		return r
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, req.MaxBody))
	r.Total = time.Since(start)
	r.Bytes = n
	r.StatusCode = resp.StatusCode
	r.Proto = resp.Proto
	if resp.TLS != nil {
		r.TLSVersion = tls.VersionName(resp.TLS.Version)
		if resp.TLS.CurveID != 0 {
			r.KeyExchange = resp.TLS.CurveID.String()
		}
	}
	r.Edge = EdgeFromHeaders(resp.Header)
	if err != nil {
		r.Status, r.Reason = neterr.Classify(err)
		r.Phase = "body"
		r.Err = err
		return r
	}
	r.Status = sample.StatusOK
	return r
}

func fill(r *Result, start, connStart, connDone, tlsStart, tlsDone, wrote, first time.Time) {
	if !connStart.IsZero() && !connDone.IsZero() {
		r.Connect = connDone.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		r.TLS = tlsDone.Sub(tlsStart)
	}
	if !wrote.IsZero() && !first.IsZero() {
		r.TTFB = first.Sub(wrote)
	}
	if !first.IsZero() {
		r.FirstByte = first.Sub(start)
	}
}

func failedPhase(connDone, tlsDone, wrote, first time.Time) string {
	switch {
	case connDone.IsZero():
		return "connect"
	case tlsDone.IsZero():
		return "tls"
	case wrote.IsZero():
		return "request"
	case first.IsZero():
		return "ttfb"
	}
	return "body"
}

var (
	// Three or four uppercase letters at the end of a cf-ray, e.g. "8f2c...-IST".
	cfRay = regexp.MustCompile(`-([A-Z]{3,4})$`)
	// Fastly cache node names end in the PoP code, e.g. "cache-ist-ltfm2340021-IST".
	fastlyNode = regexp.MustCompile(`^cache-[a-z0-9-]+-([A-Z]{3})$`)
	// CloudFront PoPs, e.g. "IST50-P1".
	cfPop = regexp.MustCompile(`^([A-Z]{3}\d*)`)
)

// EdgeFromHeaders identifies the CDN and the point of presence from
// well-known response headers. Unknown CDNs leave the fields empty.
func EdgeFromHeaders(h http.Header) Edge {
	e := Edge{Server: trimHeader(h.Get("Server"), 48)}
	switch {
	case h.Get("Cf-Ray") != "":
		e.CDN = "cloudflare"
		if m := cfRay.FindStringSubmatch(h.Get("Cf-Ray")); m != nil {
			e.PoP = m[1]
		}
		e.Cache = h.Get("Cf-Cache-Status")
	case h.Get("X-Amz-Cf-Pop") != "":
		e.CDN = "cloudfront"
		if m := cfPop.FindStringSubmatch(h.Get("X-Amz-Cf-Pop")); m != nil {
			e.PoP = m[1]
		}
		e.Cache = h.Get("X-Cache")
	case strings.Contains(h.Get("X-Served-By"), "cache-"):
		e.CDN = "fastly"
		// With shielding the header lists every node on the way; the edge
		// that answered the client appends itself last.
		nodes := strings.Split(h.Get("X-Served-By"), ",")
		if m := fastlyNode.FindStringSubmatch(strings.TrimSpace(nodes[len(nodes)-1])); m != nil {
			e.PoP = m[1]
		}
		e.Cache = h.Get("X-Cache")
	case h.Get("Akamai-Grn") != "" || strings.Contains(strings.ToLower(e.Server), "akamai"):
		e.CDN = "akamai"
		e.Cache = h.Get("X-Cache")
	case strings.HasPrefix(strings.ToLower(e.Server), "gws") || strings.EqualFold(e.Server, "ESF"):
		e.CDN = "google"
	}
	e.Cache = trimHeader(e.Cache, 32)
	return e
}

func trimHeader(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
