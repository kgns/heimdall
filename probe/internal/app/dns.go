package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/probes/dnsp"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/scheduler"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
)

// DNS layer names, from the client outwards.
const (
	layerLocal    = "local"    // the CPE's forwarder, as LAN clients use it
	layerSystem   = "system"   // resolv.conf servers when there is no dnsmasq
	layerUpstream = "upstream" // each server the forwarder sends to
	layerUncached = "uncached" // full path, cache-busting name
	layerDoH      = "doh"      // public resolvers reached directly over HTTPS
	layerIdentity = "identity" // whoami names that reveal the egress resolver
	// layerISP and layerISPUncached query the ISP's resolvers directly,
	// whatever DNS the user configured on the CPE.
	layerISP         = "isp"
	layerISPUncached = "isp_uncached"
)

// dnsLayer is one place a DNS query can be sent.
type dnsLayer struct {
	id     string
	layer  string
	server netip.AddrPort
	ex     dnsp.Exchanger
	// viaSystemPath marks layers whose answers come from the resolver the
	// forwarder currently uses, so samples carry its identity.
	viaSystemPath bool
	random        string // zone for uncached queries
}

// dnsProbes owns the DNS layers and the current resolver identity.
type dnsProbes struct {
	*env
	layers   []dnsLayer
	identity []dnsLayer
	doh      []*dnsp.DoH

	// identityZone is set when a random-label whoami zone is configured;
	// only its answers then set the resolver identity.
	identityZone bool

	resolverID atomic.Pointer[string]
	mu         sync.Mutex
	names      map[string]int
}

// newDNSProbes discovers the layers from the forwarder's configuration.
// allowed is the route guard for directly contacted servers; isp are the
// ISP's resolvers, measured as layers of their own.
func newDNSProbes(e *env, fsys fs.FS, allowed func(netip.Addr) bool, isp []netip.AddrPort) *dnsProbes {
	d := &dnsProbes{env: e, names: map[string]int{}}
	c := e.cfg.DNS
	if !c.Enabled {
		return d
	}

	var entry []dnsLayer
	dm, err := sysinfo.DiscoverDnsmasq(fsys)
	if err != nil {
		e.log.Warn("dnsmasq discovery failed", "err", err)
	}
	if dm != nil && dm.ListenPort > 0 {
		ap := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(dm.ListenPort))
		entry = append(entry, dnsLayer{id: "dns/local/" + ap.String(), layer: layerLocal, server: ap, ex: dnsp.Plain{Server: ap}, viaSystemPath: true})
	} else if sys, err := sysinfo.ReadResolvConf(fsys, "/etc/resolv.conf"); err == nil {
		for _, a := range sys {
			ap := netip.AddrPortFrom(a, 53)
			entry = append(entry, dnsLayer{id: "dns/system/" + ap.String(), layer: layerSystem, server: ap, ex: dnsp.Plain{Server: ap}, viaSystemPath: true})
		}
	}
	if c.Local {
		d.layers = append(d.layers, entry...)
	}
	if c.Upstreams && dm != nil {
		for _, u := range dm.Upstreams() {
			if !u.Addr.Addr().IsLoopback() && !allowed(u.Addr.Addr()) {
				e.log.Warn("skipping DNS upstream behind a non-default route", "server", u.Addr)
				continue
			}
			d.layers = append(d.layers, dnsLayer{id: "dns/upstream/" + u.Addr.String(), layer: layerUpstream, server: u.Addr, ex: dnsp.Plain{Server: u.Addr}, viaSystemPath: true})
		}
	}
	for _, ap := range isp {
		d.layers = append(d.layers, dnsLayer{id: "dns/isp/" + ap.String(), layer: layerISP, server: ap, ex: dnsp.Plain{Server: ap}})
	}
	if c.UncachedZone != "" && len(isp) > 0 {
		d.layers = append(d.layers, dnsLayer{id: "dns/isp-uncached/" + c.UncachedZone, layer: layerISPUncached,
			server: isp[0], ex: dnsp.Plain{Server: isp[0]}, random: c.UncachedZone})
	}
	if c.UncachedZone != "" && len(entry) > 0 {
		l := entry[0]
		l.id, l.layer, l.random = "dns/uncached/"+c.UncachedZone, layerUncached, c.UncachedZone
		d.layers = append(d.layers, l)
	}
	for _, s := range c.DoH {
		ip := netip.MustParseAddr(s.IP)
		if !allowed(ip) {
			e.log.Warn("skipping DoH server behind a non-default route", "id", s.ID, "ip", ip)
			continue
		}
		ap := netip.AddrPortFrom(ip, 443)
		cl, err := dnsp.NewDoH(s.URL, ap, nil)
		if err != nil {
			e.log.Warn("DoH server unusable", "id", s.ID, "err", err)
			continue
		}
		d.doh = append(d.doh, cl)
		d.layers = append(d.layers, dnsLayer{id: "dns/doh/" + s.ID, layer: layerDoH, server: ap, ex: cl})
	}
	if len(entry) > 0 && c.Identity.Zone != "" {
		l := entry[0]
		l.id, l.layer, l.random = "dns/identity/"+c.Identity.Zone, layerIdentity, c.Identity.Zone
		d.identity = append(d.identity, l)
		d.identityZone = true
	}
	// The ISP resolver's own identity shows its egress address and whether
	// it forwards the client subnet. It never sets the system path's
	// identity.
	if len(isp) > 0 && c.Identity.Zone != "" {
		d.identity = append(d.identity, dnsLayer{id: "dns/identity/isp/" + isp[0].Addr().String(), layer: layerISP,
			server: isp[0], ex: dnsp.Plain{Server: isp[0]}, random: c.Identity.Zone})
	}
	if len(entry) > 0 {
		for _, n := range c.Identity.Names {
			l := entry[0]
			l.id, l.layer = "dns/identity/"+n, layerIdentity
			d.identity = append(d.identity, l)
		}
	}
	return d
}

// ResolverID returns the egress address of the resolver currently answering
// for the system path, or "" while unknown.
func (d *dnsProbes) ResolverID() string {
	if p := d.resolverID.Load(); p != nil {
		return *p
	}
	return ""
}

func (d *dnsProbes) close() {
	for _, c := range d.doh {
		c.Close()
	}
}

// jobs returns one job per layer and identity name.
func (d *dnsProbes) jobs() []scheduler.Job {
	c := d.cfg.DNS
	var out []scheduler.Job
	for _, l := range d.layers {
		out = append(out, scheduler.Job{
			Name: l.id, Interval: c.Interval, Budgeted: true, MaxInFlight: 1,
			Run: func(ctx context.Context) { d.probe(ctx, l) },
		})
	}
	for _, l := range d.identity {
		out = append(out, scheduler.Job{
			Name: l.id, Interval: c.Identity.Interval, Budgeted: true, MaxInFlight: 1,
			Run: func(ctx context.Context) { d.probeIdentity(ctx, l) },
		})
	}
	return out
}

func (d *dnsProbes) nextName(layerID string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.cfg.DNS.Names[d.names[layerID]%len(d.cfg.DNS.Names)]
	d.names[layerID]++
	return n
}

func randomLabel() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (d *dnsProbes) probe(ctx context.Context, l dnsLayer) {
	var name string
	if l.random != "" {
		name = randomLabel() + "." + l.random
	} else {
		name = d.nextName(l.id)
	}
	r := dnsp.Query(ctx, l.ex, name, dns.TypeA, d.cfg.DNS.Timeout)
	if ctx.Err() != nil {
		return
	}
	d.rec.Emit(d.sample(l, name, r))
}

func (d *dnsProbes) probeIdentity(ctx context.Context, l dnsLayer) {
	name := l.id[len("dns/identity/"):]
	if l.random != "" {
		name = randomLabel() + "." + l.random
	}
	r := dnsp.Query(ctx, l.ex, name, dns.TypeTXT, d.cfg.DNS.Timeout)
	if ctx.Err() != nil {
		return
	}
	s := d.sample(l, name, r)
	if r.Status == sample.StatusOK {
		id := dnsp.ParseIdentity(r.TXT)
		if id.Resolver.IsValid() {
			s.Extra["resolver"] = id.Resolver.String()
			if id.ClientSubnet != "" {
				s.Extra["ecs"] = id.ClientSubnet
			}
			// A cached answer names whichever resolver filled the cache,
			// possibly long ago (dnscrypt-proxy keeps answers for at least
			// cache_min_ttl, 40 minutes by default), so only answers that
			// came from upstream update the current identity. Random
			// labels are never cached.
			fresh := l.random != "" || r.RTT >= freshIdentityRTT
			s.Extra["fresh"] = fresh
			if l.layer == layerIdentity && fresh && (l.random != "" || !d.identityZone) {
				d.setResolver(id.Resolver.String(), l.id[len("dns/identity/"):])
			}
		}
	}
	s.ResolverID = d.ResolverID()
	if l.layer == layerISP {
		s.ResolverID = l.server.Addr().String()
	}
	d.rec.Emit(s)
}

// freshIdentityRTT separates answers served by a local cache, which take
// about a millisecond, from answers fetched through an upstream resolver,
// which take tens of milliseconds or more.
const freshIdentityRTT = 10 * time.Millisecond

// setResolver records a new resolver identity and emits an event when it
// differs from the previous one.
func (d *dnsProbes) setResolver(id, via string) {
	prev := d.ResolverID()
	if prev == id {
		return
	}
	d.resolverID.Store(&id)
	d.log.Info("resolver identity", "resolver", id, "prev", prev, "via", via)
	x := map[string]any{"event": "resolver_change", "resolver": id, "via": via}
	if prev != "" {
		x["prev"] = prev
	}
	d.rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Category: "infra", Service: "dns",
		ResolverID: id, Extra: x})
}

const maxAnswersInSample = 8

func (d *dnsProbes) sample(l dnsLayer, name string, r dnsp.Result) sample.Sample {
	s := sample.Sample{
		TS: r.Sent.UnixMilli(), Kind: sample.KindDNS, Category: "infra", Service: "dns",
		TargetID: l.id, DstIP: l.server.Addr().String(), DstPort: int(l.server.Port()), Status: r.Status,
	}
	if r.Status == sample.StatusOK {
		s.RTTms = sample.RTT(r.RTT)
	}
	if l.viaSystemPath && l.layer != layerIdentity {
		s.ResolverID = d.ResolverID()
	}
	if l.layer == layerISP || l.layer == layerISPUncached {
		s.ResolverID = l.server.Addr().String()
	}
	x := map[string]any{"layer": l.layer, "qname": name}
	if r.Rcode != "" {
		x["rcode"] = r.Rcode
		x["min_ttl"] = r.MinTTL
	}
	if len(r.Addrs) > 0 {
		as := r.Addrs
		if len(as) > maxAnswersInSample {
			as = as[:maxAnswersInSample]
		}
		x["answers"] = addrStrings(as)
	}
	if r.Truncated {
		x["truncated"] = true
	}
	if r.Status != sample.StatusOK {
		x["reason"] = r.Reason
	}
	s.Extra = x
	return s
}
