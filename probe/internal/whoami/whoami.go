// Package whoami is an authoritative DNS server for a zone in which every
// name answers with the address of the resolver that asked. Probes query a
// random label under the zone, so no cache can answer and the reply always
// names the resolver that is in use right now.
package whoami

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// Zone answers for Name and every name below it:
//
//	TXT   "ns" "<resolver address>" and, when the resolver forwarded an
//	      EDNS client subnet, "ecs" "<prefix>" (the whoami.ds.akahelp.net
//	      format)
//	A     the resolver's address when it queried over IPv4
//	AAAA  the resolver's address when it queried over IPv6
//
// The apex also has SOA and NS records. Answers have TTL 0.
type Zone struct {
	Name       string // zone apex, e.g. "w.lat.kgns.dev."
	NS         string // name server host, e.g. "ns.lat.kgns.dev."
	Hostmaster string // SOA RNAME, e.g. "hostmaster.kgns.dev."

	queries, refused atomic.Uint64
}

// New returns a zone; names may be given with or without the trailing dot.
func New(name, ns, hostmaster string) *Zone {
	return &Zone{
		Name:       dns.CanonicalName(name),
		NS:         dns.CanonicalName(ns),
		Hostmaster: dns.CanonicalName(hostmaster),
	}
}

// Stats is a snapshot of the zone's counters.
type Stats struct {
	Queries uint64 `json:"queries"`
	Refused uint64 `json:"refused"`
}

// Stats returns the counters.
func (z *Zone) Stats() Stats {
	return Stats{Queries: z.queries.Load(), Refused: z.refused.Load()}
}

func (z *Zone) soa() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: z.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:  z.NS, Mbox: z.Hostmaster, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400,
		// Minimum 0: negative answers are not cached either.
		Minttl: 0,
	}
}

// ServeDNS implements dns.Handler.
func (z *Zone) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	z.queries.Add(1)
	m := z.Answer(r, remoteAddr(w.RemoteAddr()))
	_ = w.WriteMsg(m)
}

// Answer builds the response to r, asked by src.
func (z *Zone) Answer(r *dns.Msg, src netip.Addr) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = false
	if r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		m.SetRcode(r, dns.RcodeNotImplemented)
		return m
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	if q.Qclass != dns.ClassINET || !dns.IsSubDomain(z.Name, name) {
		z.refused.Add(1)
		m.SetRcode(r, dns.RcodeRefused)
		return m
	}
	m.Authoritative = true
	ecs := clientSubnet(r)
	if opt := r.IsEdns0(); opt != nil {
		o := m.SetEdns0(dns.DefaultMsgSize, false).IsEdns0()
		if ecs != nil {
			// Scope 0: the answer does not depend on the client subnet.
			o.Option = append(o.Option, &dns.EDNS0_SUBNET{
				Code: dns.EDNS0SUBNET, Family: ecs.Family, SourceNetmask: ecs.SourceNetmask,
				SourceScope: 0, Address: ecs.Address,
			})
		}
	}
	hdr := func(t uint16) dns.RR_Header {
		return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: 0}
	}

	if name == z.Name {
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, z.soa())
			return m
		case dns.TypeNS:
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: z.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: z.NS})
			return m
		}
	}
	switch q.Qtype {
	case dns.TypeTXT, dns.TypeANY:
		m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{"ns", src.String()}})
		if ecs != nil {
			p := netip.PrefixFrom(addrOf(ecs.Address), int(ecs.SourceNetmask))
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{"ecs", p.Masked().String()}})
		}
	case dns.TypeA:
		if src.Is4() {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: src.AsSlice()})
		}
	case dns.TypeAAAA:
		if src.Is6() {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr(dns.TypeAAAA), AAAA: src.AsSlice()})
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, z.soa())
	}
	return m
}

func clientSubnet(r *dns.Msg) *dns.EDNS0_SUBNET {
	opt := r.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if s, ok := o.(*dns.EDNS0_SUBNET); ok && len(s.Address) > 0 {
			return s
		}
	}
	return nil
}

func addrOf(ip net.IP) netip.Addr {
	if v4 := ip.To4(); v4 != nil {
		a, _ := netip.AddrFromSlice(v4)
		return a
	}
	a, _ := netip.AddrFromSlice(ip)
	return a
}

func remoteAddr(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return v.AddrPort().Addr().Unmap()
	}
	return netip.Addr{}
}
