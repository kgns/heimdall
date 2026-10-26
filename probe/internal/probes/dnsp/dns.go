// Package dnsp times DNS queries against a specific server over UDP (with
// TCP fallback on truncation) or DNS over HTTPS, and extracts resolver
// identity from "whoami" TXT answers.
package dnsp

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// Result is one query.
type Result struct {
	Status sample.Status
	Reason string
	Sent   time.Time
	RTT    time.Duration
	Rcode  string
	// Addrs are the A/AAAA answers, TXT the TXT strings, one slice per
	// record.
	Addrs     []netip.Addr
	TXT       [][]string
	MinTTL    uint32
	Truncated bool
	TCP       bool
	Err       error
}

// Exchanger sends one DNS message. Both the plain and the DoH client
// implement it.
type Exchanger interface {
	Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error)
}

// Plain queries a server over UDP and retries over TCP when the answer is
// truncated.
type Plain struct {
	Server netip.AddrPort
}

// Exchange implements Exchanger.
func (p Plain) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", UDPSize: dns.DefaultMsgSize}
	resp, _, err := c.ExchangeContext(ctx, m, p.Server.String())
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, p.Server.String())
	}
	return resp, err
}

// NewQuery builds a recursive query for name with a random ID and EDNS0.
func NewQuery(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(dns.DefaultMsgSize, false)
	return m
}

// Query sends name/qtype through ex and summarises the answer.
func Query(ctx context.Context, ex Exchanger, name string, qtype uint16, timeout time.Duration) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	m := NewQuery(name, qtype)
	start := time.Now()
	resp, err := ex.Exchange(ctx, m)
	rtt := time.Since(start)
	r := Result{Sent: start}
	if err != nil {
		r.Status, r.Reason = neterr.Classify(err)
		r.Err = err
		return r
	}
	if resp.Id != m.Id && m.Id != 0 && resp.Id != 0 {
		r.Status, r.Reason = sample.StatusError, "id_mismatch"
		return r
	}
	r.RTT = rtt
	r.Rcode = dns.RcodeToString[resp.Rcode]
	r.Truncated = resp.Truncated
	r.MinTTL = ^uint32(0)
	for _, rr := range resp.Answer {
		if ttl := rr.Header().Ttl; ttl < r.MinTTL {
			r.MinTTL = ttl
		}
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A); ok {
				r.Addrs = append(r.Addrs, a.Unmap())
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				r.Addrs = append(r.Addrs, a)
			}
		case *dns.TXT:
			r.TXT = append(r.TXT, v.Txt)
		}
	}
	if len(resp.Answer) == 0 {
		r.MinTTL = 0
	}
	switch resp.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		// NXDOMAIN is a valid, timed answer; uncached probes rely on it.
		r.Status = sample.StatusOK
	default:
		r.Status, r.Reason = sample.StatusError, "rcode_"+strings.ToLower(r.Rcode)
	}
	return r
}

// Identity is what a whoami name reveals about the resolver that queried
// the authoritative server.
type Identity struct {
	// Resolver is the egress address of the recursive resolver.
	Resolver netip.Addr
	// ClientSubnet is the EDNS client subnet the resolver forwarded, if any.
	ClientSubnet string
}

// ParseIdentity reads the TXT formats of o-o.myaddr.l.google.com (a bare
// address, plus "edns0-client-subnet <prefix>") and whoami.ds.akahelp.net
// ("ns" <address>, "ecs" <prefix> ...).
func ParseIdentity(txt [][]string) Identity {
	var id Identity
	for _, rec := range txt {
		switch {
		case len(rec) == 1:
			s := strings.TrimSpace(rec[0])
			if rest, ok := strings.CutPrefix(s, "edns0-client-subnet "); ok {
				id.ClientSubnet = rest
			} else if a, err := netip.ParseAddr(s); err == nil && !id.Resolver.IsValid() {
				id.Resolver = a
			}
		case len(rec) >= 2 && rec[0] == "ns":
			if a, err := netip.ParseAddr(rec[1]); err == nil {
				id.Resolver = a
			}
		case len(rec) >= 2 && rec[0] == "ecs":
			id.ClientSubnet = rec[1]
		}
	}
	return id
}
