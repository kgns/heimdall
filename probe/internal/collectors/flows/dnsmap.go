package flows

import (
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// dnsMap remembers which name each address was the answer for, from the
// DNS replies the CPE sent its clients. A client's own lookups win over
// those of other clients, since one address can serve many names.
type dnsMap struct {
	max     int
	minTTL  time.Duration
	maxTTL  time.Duration
	byPair  map[pairKey]dnsEntry
	byAddr  map[netip.Addr]dnsEntry
	answers uint64
}

type pairKey struct {
	client, server netip.Addr
}

type dnsEntry struct {
	name    string
	expires time.Time
}

func newDNSMap(max int) *dnsMap {
	return &dnsMap{
		max: max, minTTL: 5 * time.Minute, maxTTL: 2 * time.Hour,
		byPair: map[pairKey]dnsEntry{}, byAddr: map[netip.Addr]dnsEntry{},
	}
}

// Observe records the answers of a DNS reply sent to client.
func (m *dnsMap) Observe(client netip.Addr, payload []byte, now time.Time) {
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil || !msg.Response || len(msg.Question) != 1 {
		return
	}
	name := strings.ToLower(strings.TrimSuffix(msg.Question[0].Name, "."))
	if !validName(name) {
		return
	}
	for _, rr := range msg.Answer {
		var a netip.Addr
		switch r := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(r.A.To4())
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(r.AAAA)
		default:
			continue
		}
		if !a.IsValid() {
			continue
		}
		ttl := min(max(time.Duration(rr.Header().Ttl)*time.Second, m.minTTL), m.maxTTL)
		e := dnsEntry{name: name, expires: now.Add(ttl)}
		m.byPair[pairKey{client.Unmap(), a.Unmap()}] = e
		m.byAddr[a.Unmap()] = e
		m.answers++
	}
	if len(m.byPair) > m.max || len(m.byAddr) > m.max {
		m.sweep(now)
	}
}

// Lookup returns the name client most likely connected to at server.
func (m *dnsMap) Lookup(client, server netip.Addr, now time.Time) (string, bool) {
	if e, ok := m.byPair[pairKey{client.Unmap(), server.Unmap()}]; ok && now.Before(e.expires) {
		return e.name, true
	}
	if e, ok := m.byAddr[server.Unmap()]; ok && now.Before(e.expires) {
		return e.name, true
	}
	return "", false
}

// Len returns the number of remembered client and address pairs.
func (m *dnsMap) Len() int { return len(m.byPair) }

func (m *dnsMap) sweep(now time.Time) {
	for k, e := range m.byPair {
		if !now.Before(e.expires) {
			delete(m.byPair, k)
		}
	}
	for k, e := range m.byAddr {
		if !now.Before(e.expires) {
			delete(m.byAddr, k)
		}
	}
	// Still full: drop entries in map order, which is arbitrary, until a
	// tenth is free.
	trim := func(n int, del func() bool) {
		for n > m.max*9/10 && del() {
			n--
		}
	}
	trim(len(m.byPair), func() bool {
		for k := range m.byPair {
			delete(m.byPair, k)
			return true
		}
		return false
	})
	trim(len(m.byAddr), func() bool {
		for k := range m.byAddr {
			delete(m.byAddr, k)
			return true
		}
		return false
	})
}
