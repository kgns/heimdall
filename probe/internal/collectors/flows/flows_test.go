package flows

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/bpf"
)

var (
	routerMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	clientMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}
	client4   = netip.MustParseAddrPort("192.168.1.10:50000")
	server4   = netip.MustParseAddrPort("203.0.113.5:443")
	client6   = netip.MustParseAddrPort("[2001:db8::10]:50001")
	server6   = netip.MustParseAddrPort("[2001:db8:1::5]:443")
)

type seg struct {
	src, dst netip.AddrPort
	flags    uint8
	seq, ack uint32
	payload  []byte
	udp      bool
	fromCPE  bool
}

func frame(s seg) []byte {
	var l4 []byte
	proto := byte(protoTCP)
	if s.udp {
		proto = protoUDP
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:], s.src.Port())
		binary.BigEndian.PutUint16(l4[2:], s.dst.Port())
		binary.BigEndian.PutUint16(l4[4:], uint16(8+len(s.payload)))
	} else {
		l4 = make([]byte, 32)
		binary.BigEndian.PutUint16(l4[0:], s.src.Port())
		binary.BigEndian.PutUint16(l4[2:], s.dst.Port())
		binary.BigEndian.PutUint32(l4[4:], s.seq)
		binary.BigEndian.PutUint32(l4[8:], s.ack)
		l4[12] = 8 << 4 // 32-byte header with options
		l4[13] = s.flags
	}
	l4 = append(l4, s.payload...)
	eth := make([]byte, 14)
	if s.fromCPE {
		copy(eth[0:6], clientMAC)
		copy(eth[6:12], routerMAC)
	} else {
		copy(eth[0:6], routerMAC)
		copy(eth[6:12], clientMAC)
	}
	var ip []byte
	if s.src.Addr().Is4() {
		binary.BigEndian.PutUint16(eth[12:], etherIPv4)
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
		ip[8], ip[9] = 64, proto
		a, b := s.src.Addr().As4(), s.dst.Addr().As4()
		copy(ip[12:], a[:])
		copy(ip[16:], b[:])
	} else {
		binary.BigEndian.PutUint16(eth[12:], etherIPv6)
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(l4)))
		ip[6], ip[7] = proto, 64
		a, b := s.src.Addr().As16(), s.dst.Addr().As16()
		copy(ip[8:], a[:])
		copy(ip[24:], b[:])
	}
	return append(append(eth, ip...), l4...)
}

func clientHello(t *testing.T, sni string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		tc := tls.Client(c1, &tls.Config{ServerName: sni, InsecureSkipVerify: sni == ""})
		_ = tc.Handshake()
	}()
	buf := make([]byte, 4096)
	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf[:n]
}

func dnsAnswer(t *testing.T, name string, addrs ...netip.Addr) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "edge.cdn.example."})
	for _, a := range addrs {
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: "edge.cdn.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: a.AsSlice()})
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFilter(t *testing.T) {
	raw, err := Filter(routerMAC)
	if err != nil {
		t.Fatal(err)
	}
	ins := make([]bpf.Instruction, len(raw))
	for i, r := range raw {
		ins[i] = r.Disassemble()
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	hello := clientHello(t, "www.example.com")
	quicLong := append([]byte{0xc0, 0, 0, 0, 1}, make([]byte, 40)...)
	quicShort := append([]byte{0x40}, make([]byte, 40)...)
	dnsPort := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 53)
	cases := []struct {
		name string
		s    seg
		want int
	}{
		{"v4 syn from client", seg{src: client4, dst: server4, flags: flagSYN}, snapHeaders},
		{"v4 syn-ack to client", seg{src: server4, dst: client4, flags: flagSYN | flagACK, fromCPE: true}, snapHeaders},
		{"v4 pure ack from client", seg{src: client4, dst: server4, flags: flagACK}, snapHeaders},
		{"v4 pure ack to client", seg{src: server4, dst: client4, flags: flagACK, fromCPE: true}, 0},
		{"v4 client hello", seg{src: client4, dst: server4, flags: flagACK | flagPSH, payload: hello}, snapHello},
		{"v4 other data", seg{src: client4, dst: server4, flags: flagACK | flagPSH, payload: []byte("GET / HTTP/1.1\r\n")}, 0},
		{"v4 fin", seg{src: client4, dst: server4, flags: flagFIN | flagACK}, 0},
		{"v4 quic long", seg{src: client4, dst: server4, udp: true, payload: quicLong}, snapHeaders},
		{"v4 quic long from server", seg{src: server4, dst: client4, udp: true, payload: quicLong, fromCPE: true}, snapHeaders},
		{"v4 quic short", seg{src: client4, dst: server4, udp: true, payload: quicShort}, 0},
		{"v4 dns answer to client", seg{src: dnsPort, dst: client4, udp: true, payload: []byte{1, 2, 3}, fromCPE: true}, snapDNS},
		{"v4 dns from client side", seg{src: dnsPort, dst: client4, udp: true, payload: []byte{1, 2, 3}}, 0},
		{"v6 syn", seg{src: client6, dst: server6, flags: flagSYN}, snapHeaders},
		{"v6 pure ack from client", seg{src: client6, dst: server6, flags: flagACK}, snapHeaders},
		{"v6 pure ack to client", seg{src: server6, dst: client6, flags: flagACK, fromCPE: true}, 0},
		{"v6 client hello", seg{src: client6, dst: server6, flags: flagACK | flagPSH, payload: hello}, snapHello},
		{"v6 quic long", seg{src: client6, dst: server6, udp: true, payload: quicLong}, snapHeaders},
	}
	for _, tc := range cases {
		got, err := vm.Run(frame(tc.s))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: filter returned %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestParseSNI(t *testing.T) {
	hello := clientHello(t, "www.example.com")
	if name, res := ParseSNI(hello); res != sniFound || name != "www.example.com" {
		t.Fatalf("got %q %v", name, res)
	}
	if _, res := ParseSNI(hello[:60]); res != sniTruncated {
		t.Errorf("truncated hello: got %v", res)
	}
	if _, res := ParseSNI([]byte("GET / HTTP/1.1")); res != sniInvalid {
		t.Errorf("http: got %v", res)
	}
}

func mustParse(t *testing.T, s seg) Packet {
	t.Helper()
	p, err := Parse(frame(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTrackerTCP(t *testing.T) {
	tr := NewTracker(TrackerOptions{})
	t0 := time.Unix(1000, 0)
	obs := func(s seg, at time.Duration) { tr.Observe(mustParse(t, s), t0.Add(at), s.fromCPE) }

	obs(seg{src: client4, dst: server4, flags: flagSYN, seq: 100}, 0)
	obs(seg{src: server4, dst: client4, flags: flagSYN | flagACK, seq: 5000, ack: 101, fromCPE: true}, 40*time.Millisecond)
	obs(seg{src: client4, dst: server4, flags: flagACK, seq: 101, ack: 5001}, 43*time.Millisecond)
	obs(seg{src: client4, dst: server4, flags: flagACK | flagPSH, seq: 101, ack: 5001, payload: clientHello(t, "api.example.com")}, 44*time.Millisecond)

	got := tr.Ready(t0.Add(50 * time.Millisecond))
	if len(got) != 1 {
		t.Fatalf("got %d flows", len(got))
	}
	f := got[0]
	if f.Status != StatusOK || f.WAN != 40*time.Millisecond || f.LAN != 3*time.Millisecond || f.LANFromData {
		t.Errorf("flow %+v", f)
	}
	if f.Name != "api.example.com" || f.NameSource != NameSNI || f.Client != client4 || f.Server != server4 {
		t.Errorf("flow %+v", f)
	}
	if tr.Stats().Tracked != 0 {
		t.Error("flow still tracked")
	}
}

func TestTrackerTimeoutsAndDNS(t *testing.T) {
	tr := NewTracker(TrackerOptions{})
	t0 := time.Unix(1000, 0)
	dnsSrc := netip.AddrPortFrom(netip.MustParseAddr("192.168.1.1"), 53)
	tr.Observe(mustParse(t, seg{src: dnsSrc, dst: client4, udp: true, fromCPE: true,
		payload: dnsAnswer(t, "video.example.net", server4.Addr())}), t0, true)

	// Unanswered SYN, retransmitted once.
	other := netip.AddrPortFrom(client4.Addr(), 50002)
	tr.Observe(mustParse(t, seg{src: other, dst: server4, flags: flagSYN}), t0, false)
	tr.Observe(mustParse(t, seg{src: other, dst: server4, flags: flagSYN}), t0.Add(time.Second), false)
	// Answered, but the client's ACK is never seen.
	tr.Observe(mustParse(t, seg{src: client4, dst: server4, flags: flagSYN, seq: 1}), t0, false)
	tr.Observe(mustParse(t, seg{src: server4, dst: client4, flags: flagSYN | flagACK, seq: 9, ack: 2, fromCPE: true}), t0.Add(20*time.Millisecond), true)
	// To the CPE itself: ignored.
	tr.Observe(mustParse(t, seg{src: client4, dst: netip.MustParseAddrPort("192.168.1.1:80"), flags: flagSYN}), t0, false)

	if got := tr.Ready(t0.Add(2 * time.Second)); len(got) != 0 {
		t.Fatalf("early: %+v", got)
	}
	got := tr.Ready(t0.Add(10 * time.Second))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	byStatus := map[string]Flow{}
	for _, f := range got {
		byStatus[f.Status] = f
	}
	if f := byStatus[StatusTimeout]; f.ClientRetx != 1 || f.HasWAN {
		t.Errorf("timeout flow %+v", f)
	}
	if f := byStatus[StatusNoAck]; !f.HasWAN || f.HasLAN || f.Name != "video.example.net" || f.NameSource != NameDNS {
		t.Errorf("no-ack flow %+v", f)
	}
}

func TestTrackerQUIC(t *testing.T) {
	tr := NewTracker(TrackerOptions{})
	t0 := time.Unix(1000, 0)
	initial := append([]byte{0xc0, 0, 0, 0, 1}, make([]byte, 40)...)
	handshake := append([]byte{0xe0, 0, 0, 0, 1}, make([]byte, 40)...)
	obs := func(s seg, at time.Duration) {
		s.udp = true
		tr.Observe(mustParse(t, s), t0.Add(at), s.fromCPE)
	}
	obs(seg{src: client6, dst: server6, payload: initial}, 0)
	obs(seg{src: client6, dst: server6, payload: initial}, time.Millisecond)
	obs(seg{src: server6, dst: client6, payload: initial, fromCPE: true}, 30*time.Millisecond)
	obs(seg{src: server6, dst: client6, payload: handshake, fromCPE: true}, 31*time.Millisecond)
	obs(seg{src: client6, dst: server6, payload: handshake}, 36*time.Millisecond)
	got := tr.Ready(t0.Add(40 * time.Millisecond))
	if len(got) != 1 {
		t.Fatalf("got %+v", got)
	}
	f := got[0]
	if f.Proto != "quic" || f.WAN != 30*time.Millisecond || f.LAN != 6*time.Millisecond || f.LANMin != 5*time.Millisecond || f.ClientRetx != 0 {
		t.Errorf("flow %+v", f)
	}
}

func TestClassifier(t *testing.T) {
	c := NewClassifier([]Rule{
		{Domain: "google.com", Service: "google", Category: "browsing"},
		{Domain: "meet.google.com", Service: "google-meet", Category: "video_calls"},
	})
	for name, want := range map[string]string{
		"www.google.com": "google", "meet.google.com": "google-meet", "x.meet.google.com": "google-meet",
		"google.com": "google",
	} {
		if r, ok := c.Classify(name); !ok || r.Service != want {
			t.Errorf("%s: got %+v", name, r)
		}
	}
	if _, ok := c.Classify("notgoogle.com"); ok {
		t.Error("notgoogle.com matched")
	}
}

type fakeCapture struct {
	frames [][]byte
	ts     []time.Time
	i      int
}

func (f *fakeCapture) Read() ([]byte, time.Time, error) {
	if f.i >= len(f.frames) {
		time.Sleep(time.Millisecond)
		return nil, time.Time{}, ErrTimeout
	}
	f.i++
	return f.frames[f.i-1], f.ts[f.i-1], nil
}
func (f *fakeCapture) Drops() uint64 { return 0 }
func (f *fakeCapture) Close() error  { return nil }

func TestCollector(t *testing.T) {
	now := time.Now()
	fc := &fakeCapture{}
	add := func(s seg, at time.Duration) {
		fc.frames = append(fc.frames, frame(s))
		fc.ts = append(fc.ts, now.Add(at))
	}
	add(seg{src: client4, dst: server4, flags: flagSYN, seq: 1}, -time.Second)
	add(seg{src: server4, dst: client4, flags: flagSYN | flagACK, seq: 7, ack: 2, fromCPE: true}, -time.Second+10*time.Millisecond)
	add(seg{src: client4, dst: server4, flags: flagACK, seq: 2, ack: 8}, -time.Second+12*time.Millisecond)

	got := make(chan Flow, 1)
	c := NewCollector(fc, routerMAC, TrackerOptions{HelloWait: 100 * time.Millisecond}, func(f Flow) { got <- f })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	select {
	case f := <-got:
		if f.LAN != 2*time.Millisecond || f.WAN != 10*time.Millisecond {
			t.Errorf("flow %+v", f)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no flow")
	}
}
