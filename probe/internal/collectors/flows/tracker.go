package flows

import (
	"net"
	"net/netip"
	"time"
)

// Flow statuses.
const (
	StatusOK = "ok"
	// StatusTimeout: the server never answered the client's SYN or
	// Initial.
	StatusTimeout = "timeout"
	// StatusNoAck: the server answered but the client's reply was not
	// seen, so only the WAN part is known.
	StatusNoAck = "no_ack"
)

// Name sources.
const (
	NameSNI = "sni"
	NameDNS = "dns"
)

// Flow is one connection setup seen on the bridge.
type Flow struct {
	Proto     string // "tcp" or "quic"
	Client    netip.AddrPort
	Server    netip.AddrPort
	ClientMAC net.HardwareAddr
	Start     time.Time
	Status    string
	// WAN is from the client's first packet passing the CPE to the
	// server's answer passing it back; LAN is from that answer to the
	// client's reply.
	WAN, LAN       time.Duration
	HasWAN, HasLAN bool
	// LANMin is, for QUIC, LAN measured from the server's last packet
	// before the client's reply, a lower bound when the server's first
	// flight spans several datagrams.
	LANMin time.Duration
	// Retransmissions of the client's opening packet and of the server's
	// answer. A retransmitted opening makes WAN ambiguous.
	ClientRetx, ServerRetx int
	// LANFromData: the client's reply was a data segment, not a pure ACK,
	// so LAN may include the client application's delay.
	LANFromData bool
	Name        string
	NameSource  string
	// SNI tells whether a TLS ClientHello was seen and what it held.
	SNI string
}

// TrackerOptions bound the tracker.
type TrackerOptions struct {
	// MaxFlows caps the half-open connections tracked at once.
	MaxFlows int
	// AnswerTimeout is how long a connection waits for the server.
	AnswerTimeout time.Duration
	// ReplyTimeout is how long it waits for the client's reply.
	ReplyTimeout time.Duration
	// HelloWait is how long, after the handshake, it waits for the TLS
	// ClientHello that names the server.
	HelloWait time.Duration
	// Local reports addresses that are not internet servers: the CPE's own
	// and those on the LAN.
	Local func(netip.Addr) bool
	// MaxDNS caps the DNS answers remembered.
	MaxDNS int
}

// DefaultTrackerOptions returns sensible bounds for a home CPE.
func DefaultTrackerOptions() TrackerOptions {
	return TrackerOptions{
		// Browsers open connections ahead of use and may send the
		// ClientHello seconds later.
		MaxFlows: 4096, AnswerTimeout: 5 * time.Second, ReplyTimeout: 3 * time.Second,
		HelloWait: 3 * time.Second, MaxDNS: 8192,
	}
}

// TrackerStats counts what the tracker saw.
type TrackerStats struct {
	Packets   uint64 `json:"packets"`
	Tracked   int    `json:"tracked"`
	Completed uint64 `json:"completed"`
	Overflow  uint64 `json:"overflow"`
	DNS       uint64 `json:"dns_answers"`
	DNSNames  int    `json:"dns_names"`
}

type flowKey struct {
	proto          uint8
	client, server netip.AddrPort
}

type entry struct {
	Flow
	t0, t1, t2 time.Time
	lastServer time.Time
	synackSeq  uint32
	helloSeen  bool
}

// Tracker turns captured packets into flows. It is not safe for concurrent
// use.
type Tracker struct {
	opt   TrackerOptions
	flows map[flowKey]*entry
	dns   *dnsMap
	stats TrackerStats
}

// NewTracker returns an empty tracker.
func NewTracker(opt TrackerOptions) *Tracker {
	d := DefaultTrackerOptions()
	if opt.MaxFlows <= 0 {
		opt.MaxFlows = d.MaxFlows
	}
	if opt.AnswerTimeout <= 0 {
		opt.AnswerTimeout = d.AnswerTimeout
	}
	if opt.ReplyTimeout <= 0 {
		opt.ReplyTimeout = d.ReplyTimeout
	}
	if opt.HelloWait <= 0 {
		opt.HelloWait = d.HelloWait
	}
	if opt.MaxDNS <= 0 {
		opt.MaxDNS = d.MaxDNS
	}
	if opt.Local == nil {
		opt.Local = func(a netip.Addr) bool { return !a.IsGlobalUnicast() || a.IsPrivate() }
	}
	return &Tracker{opt: opt, flows: map[flowKey]*entry{}, dns: newDNSMap(opt.MaxDNS)}
}

// Stats returns the counters.
func (t *Tracker) Stats() TrackerStats {
	s := t.stats
	s.Tracked = len(t.flows)
	s.DNS = t.dns.answers
	s.DNSNames = t.dns.Len()
	return s
}

// Observe processes one packet seen at ts. fromRouter tells whether the
// CPE sent it towards the LAN.
func (t *Tracker) Observe(p Packet, ts time.Time, fromRouter bool) {
	t.stats.Packets++
	switch p.Proto {
	case protoTCP:
		t.tcp(p, ts, fromRouter)
	case protoUDP:
		switch {
		case fromRouter && p.Src.Port() == 53:
			t.dns.Observe(p.Dst.Addr(), p.Payload, ts)
		case len(p.Payload) > 0 && p.Payload[0]&0x80 != 0:
			t.quic(p, ts, fromRouter)
		}
	}
}

func (t *Tracker) add(k flowKey, e *entry) bool {
	if len(t.flows) >= t.opt.MaxFlows {
		t.stats.Overflow++
		return false
	}
	t.flows[k] = e
	return true
}

func (t *Tracker) tcp(p Packet, ts time.Time, fromRouter bool) {
	syn, ack := p.Flags&flagSYN != 0, p.Flags&flagACK != 0
	switch {
	case syn && !ack && !fromRouter:
		if t.opt.Local(p.Dst.Addr()) {
			return
		}
		k := flowKey{protoTCP, p.Src, p.Dst}
		if e, ok := t.flows[k]; ok && e.t1.IsZero() {
			e.ClientRetx++
			e.t0 = ts
			return
		}
		t.add(k, &entry{Flow: Flow{Proto: "tcp", Client: p.Src, Server: p.Dst,
			ClientMAC: append(net.HardwareAddr(nil), p.SrcMAC...), Start: ts}, t0: ts})
	case syn && ack && fromRouter:
		e, ok := t.flows[flowKey{protoTCP, p.Dst, p.Src}]
		if !ok {
			return
		}
		if e.t1.IsZero() {
			e.t1, e.synackSeq = ts, p.Seq
			e.WAN, e.HasWAN = ts.Sub(e.t0), true
			return
		}
		if e.t2.IsZero() {
			// The client's ACK was lost or slow; measure LAN from the
			// answer it replies to.
			e.ServerRetx++
			e.t1 = ts
		}
	case !syn && ack && !fromRouter:
		e, ok := t.flows[flowKey{protoTCP, p.Src, p.Dst}]
		if !ok || e.t1.IsZero() {
			return
		}
		if e.t2.IsZero() && p.Ack == e.synackSeq+1 {
			e.t2 = ts
			e.LAN, e.HasLAN = ts.Sub(e.t1), true
			e.LANFromData = p.PayloadLen > 0
		}
		if p.PayloadLen > 0 && !e.helloSeen && len(p.Payload) > 0 && p.Payload[0] == 0x16 {
			e.helloSeen = true
			name, res := ParseSNI(p.Payload)
			switch res {
			case sniFound:
				e.Name, e.NameSource, e.SNI = name, NameSNI, "found"
			case sniAbsent:
				e.SNI = "absent"
			case sniTruncated:
				e.SNI = "truncated"
			default:
				e.SNI = "invalid"
			}
		}
	}
}

// QUIC long-header packet types (version 1).
const (
	quicInitial = 0
	quicRetry   = 3
)

func (t *Tracker) quic(p Packet, ts time.Time, fromRouter bool) {
	typ := (p.Payload[0] >> 4) & 0x03
	if !fromRouter && p.Dst.Port() == 443 {
		if t.opt.Local(p.Dst.Addr()) {
			return
		}
		k := flowKey{protoUDP, p.Src, p.Dst}
		e, ok := t.flows[k]
		if !ok {
			if typ == quicInitial {
				t.add(k, &entry{Flow: Flow{Proto: "quic", Client: p.Src, Server: p.Dst,
					ClientMAC: append(net.HardwareAddr(nil), p.SrcMAC...), Start: ts}, t0: ts})
			}
			return
		}
		switch {
		case e.t1.IsZero():
			// A ClientHello larger than one datagram is sent as several
			// Initials back to back; a later one is a retransmission.
			if ts.Sub(e.t0) > 200*time.Millisecond {
				e.ClientRetx++
				e.t0 = ts
			}
		case e.t2.IsZero():
			e.t2 = ts
			e.LAN, e.HasLAN = ts.Sub(e.t1), true
			e.LANMin = ts.Sub(e.lastServer)
		}
		return
	}
	if fromRouter && p.Src.Port() == 443 {
		k := flowKey{protoUDP, p.Dst, p.Src}
		e, ok := t.flows[k]
		if !ok {
			return
		}
		if typ == quicRetry {
			// The client starts over with a new Initial.
			delete(t.flows, k)
			return
		}
		if e.t1.IsZero() {
			e.t1 = ts
			e.WAN, e.HasWAN = ts.Sub(e.t0), true
		}
		if e.t2.IsZero() {
			e.lastServer = ts
		}
	}
}

// Ready returns the flows that are complete or timed out at now and stops
// tracking them.
func (t *Tracker) Ready(now time.Time) []Flow {
	var out []Flow
	for k, e := range t.flows {
		done := false
		switch {
		case e.t1.IsZero():
			if now.Sub(e.t0) >= t.opt.AnswerTimeout {
				e.Status, done = StatusTimeout, true
			}
		case e.t2.IsZero():
			if now.Sub(e.t1) >= t.opt.ReplyTimeout {
				e.Status, done = StatusNoAck, true
			}
		case e.Proto == "quic" || e.helloSeen || now.Sub(e.t2) >= t.opt.HelloWait:
			e.Status, done = StatusOK, true
		}
		if !done {
			continue
		}
		delete(t.flows, k)
		if e.Name == "" {
			if name, ok := t.dns.Lookup(e.Client.Addr(), e.Server.Addr(), now); ok {
				e.Name, e.NameSource = name, NameDNS
			}
		}
		t.stats.Completed++
		out = append(out, e.Flow)
	}
	return out
}
