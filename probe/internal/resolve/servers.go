package resolve

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/probes/dnsp"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// ServerResolver resolves through fixed recursive resolvers, queried
// directly, instead of the CPE's own forwarder. The probe uses it with the
// ISP's resolvers, so that the addresses it measures are the ones the
// ISP's DNS gives its customers, whatever DNS the user configured.
type ServerResolver struct {
	servers []netip.AddrPort
	timeout time.Duration
	last    atomic.Pointer[string]
}

// NewServerResolver returns a resolver that tries servers in order.
func NewServerResolver(servers []netip.AddrPort, timeout time.Duration) *ServerResolver {
	return &ServerResolver{servers: servers, timeout: timeout}
}

// ErrNoAddress is returned for names that exist but have no IPv4 address.
var ErrNoAddress = errors.New("no IPv4 address")

// Lookup returns the IPv4 addresses of host from the first server that
// answers. A server that answers NXDOMAIN or without an address ends the
// lookup; only unreachable servers make it try the next.
func (r *ServerResolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	var errs []error
	for _, s := range r.servers {
		res := dnsp.Query(ctx, dnsp.Plain{Server: s}, host, dns.TypeA, r.timeout)
		if res.Status != sample.StatusOK {
			errs = append(errs, fmt.Errorf("%s: %s", s, res.Reason))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		id := s.Addr().String()
		r.last.Store(&id)
		if res.Rcode == dns.RcodeToString[dns.RcodeNameError] {
			return nil, fmt.Errorf("%s: no such host", host)
		}
		var out []netip.Addr
		for _, a := range res.Addrs {
			if a.Is4() {
				out = append(out, a)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s: %w", host, ErrNoAddress)
		}
		return out, nil
	}
	return nil, errors.Join(errs...)
}

// Last returns the address of the server that answered last, or "".
func (r *ServerResolver) Last() string {
	if p := r.last.Load(); p != nil {
		return *p
	}
	return ""
}

// Servers returns the servers in the order they are tried.
func (r *ServerResolver) Servers() []netip.AddrPort { return r.servers }

// WithFallback tries primary and, when it fails, fallback. It is meant for
// the probe's own housekeeping (uploads), which must keep working when the
// measurement resolvers do not.
func WithFallback(primary, fallback LookupFunc) LookupFunc {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		addrs, err := primary(ctx, host)
		if err == nil {
			return addrs, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		return fallback(ctx, host)
	}
}
