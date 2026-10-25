package icmp

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/kgns/heimdall/probe/internal/sample"
)

type packet struct {
	b   []byte
	src netip.Addr
	ttl int
}

type sent struct {
	dst  netip.Addr
	id   uint16
	seq  uint16
	data []byte
}

// fakeConn hands every written echo request to respond, which may inject
// packets for the reader with deliver.
type fakeConn struct {
	mode     Mode
	in       chan packet
	once     sync.Once
	closed   chan struct{}
	writeErr error
	respond  func(f *fakeConn, s sent)
}

func newFake(mode Mode, respond func(f *fakeConn, s sent)) *fakeConn {
	return &fakeConn{mode: mode, in: make(chan packet, 64), closed: make(chan struct{}), respond: respond}
}

func (f *fakeConn) Mode() Mode { return f.mode }

func (f *fakeConn) WriteTo(b []byte, dst netip.Addr) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	m, err := xicmp.ParseMessage(protocolICMP, b)
	if err != nil {
		return err
	}
	e := m.Body.(*xicmp.Echo)
	s := sent{dst: dst, id: uint16(e.ID), seq: uint16(e.Seq), data: append([]byte(nil), e.Data...)}
	if f.respond != nil {
		go f.respond(f, s)
	}
	return nil
}

func (f *fakeConn) ReadFrom(b []byte) (int, netip.Addr, int, error) {
	select {
	case p := <-f.in:
		return copy(b, p.b), p.src, p.ttl, nil
	case <-f.closed:
		return 0, netip.Addr{}, 0, ErrClosed
	}
}

func (f *fakeConn) Close() error {
	f.once.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeConn) deliver(b []byte, src netip.Addr, ttl int) {
	select {
	case f.in <- packet{b, src, ttl}:
	case <-f.closed:
	}
}

func echoReply(id, seq uint16, data []byte) []byte {
	b, _ := (&xicmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &xicmp.Echo{ID: int(id), Seq: int(seq), Data: data}}).Marshal(nil)
	return b
}

func quotedEcho(dst netip.Addr, id, seq uint16) []byte {
	ip := make([]byte, 20+8)
	ip[0] = 0x45
	ip[8] = 1
	ip[9] = protocolICMP
	copy(ip[12:16], []byte{10, 234, 57, 8})
	d := dst.As4()
	copy(ip[16:20], d[:])
	ip[20] = byte(ipv4.ICMPTypeEcho)
	binary.BigEndian.PutUint16(ip[24:], id)
	binary.BigEndian.PutUint16(ip[26:], seq)
	return ip
}

func dstUnreach(dst netip.Addr, id, seq uint16, code int) []byte {
	b, _ := (&xicmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: code, Body: &xicmp.DstUnreach{Data: quotedEcho(dst, id, seq)}}).Marshal(nil)
	return b
}

func timeExceeded(dst netip.Addr, id, seq uint16) []byte {
	b, _ := (&xicmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &xicmp.TimeExceeded{Data: quotedEcho(dst, id, seq)}}).Marshal(nil)
	return b
}

var (
	dstA = netip.MustParseAddr("1.1.1.1")
	dstB = netip.MustParseAddr("8.8.8.8")
	hop  = netip.MustParseAddr("10.234.0.1")
)

func newPinger(t *testing.T, f *fakeConn, opt Options) *Pinger {
	t.Helper()
	if opt.ID == 0 {
		opt.ID = 0x4242
	}
	if opt.PayloadSize == 0 {
		opt.PayloadSize = 32
	}
	p, err := New(f, opt)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestPingReply(t *testing.T) {
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		time.Sleep(15 * time.Millisecond)
		f.deliver(echoReply(s.id, s.seq, s.data), s.dst, 54)
	})
	p := newPinger(t, f, Options{})
	r := p.Ping(context.Background(), dstA, time.Second)
	if r.Status != sample.StatusOK || r.TTL != 54 || r.From != dstA {
		t.Fatalf("result %+v", r)
	}
	if r.RTT < 15*time.Millisecond || r.RTT > 200*time.Millisecond {
		t.Fatalf("rtt %v", r.RTT)
	}
	st := p.Stats()
	if st.Sent != 1 || st.Replies != 1 || st.Outstanding != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPingTimeoutThenLateReply(t *testing.T) {
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		time.Sleep(80 * time.Millisecond)
		f.deliver(echoReply(s.id, s.seq, s.data), s.dst, 54)
	})
	p := newPinger(t, f, Options{})
	r := p.Ping(context.Background(), dstA, 30*time.Millisecond)
	if r.Status != sample.StatusTimeout || r.RTT != 0 {
		t.Fatalf("result %+v", r)
	}
	waitFor(t, func() bool { return p.Stats().Late == 1 })
	if st := p.Stats(); st.Timeouts != 1 || st.Replies != 0 || st.Outstanding != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestDuplicateReplyIgnored(t *testing.T) {
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		b := echoReply(s.id, s.seq, s.data)
		f.deliver(b, s.dst, 54)
		f.deliver(b, s.dst, 54)
	})
	p := newPinger(t, f, Options{})
	if r := p.Ping(context.Background(), dstA, time.Second); r.Status != sample.StatusOK {
		t.Fatalf("result %+v", r)
	}
	waitFor(t, func() bool { return p.Stats().Unmatched == 1 })
	if st := p.Stats(); st.Replies != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestForeignAndMismatchedRepliesIgnored(t *testing.T) {
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		f.deliver(echoReply(s.id+1, s.seq, s.data), s.dst, 54)                       // other process
		f.deliver(echoReply(s.id, s.seq, []byte("not-our-token-at-all")), s.dst, 54) // wrong token
		f.deliver(echoReply(s.id, s.seq, s.data), dstB, 54)                          // wrong source
		f.deliver([]byte{0xff}, s.dst, 54)                                           // garbage
	})
	p := newPinger(t, f, Options{})
	r := p.Ping(context.Background(), dstA, 60*time.Millisecond)
	if r.Status != sample.StatusTimeout {
		t.Fatalf("result %+v", r)
	}
	st := p.Stats()
	if st.Foreign != 3 || st.Unmatched != 1 || st.Replies != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestDgramModeIgnoresID(t *testing.T) {
	f := newFake(ModeDgram, func(f *fakeConn, s sent) {
		f.deliver(echoReply(0x7777, s.seq, s.data), s.dst, 60)
	})
	p := newPinger(t, f, Options{})
	if r := p.Ping(context.Background(), dstA, time.Second); r.Status != sample.StatusOK {
		t.Fatalf("result %+v", r)
	}
}

func TestICMPErrors(t *testing.T) {
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		if s.dst == dstA {
			f.deliver(dstUnreach(s.dst, s.id, s.seq, 1), hop, 63)
		} else {
			f.deliver(timeExceeded(s.dst, s.id, s.seq), hop, 63)
		}
	})
	p := newPinger(t, f, Options{})
	r := p.Ping(context.Background(), dstA, time.Second)
	if r.Status != sample.StatusUnreachable || r.From != hop || r.ICMPType != 3 || r.ICMPCode != 1 {
		t.Fatalf("unreachable result %+v", r)
	}
	r = p.Ping(context.Background(), dstB, time.Second)
	if r.Status != sample.StatusTimeExceeded || r.ICMPType != 11 {
		t.Fatalf("time exceeded result %+v", r)
	}
	if st := p.Stats(); st.Errors != 2 {
		t.Fatalf("stats %+v", st)
	}
}

func TestICMPErrorForOtherProcessIgnored(t *testing.T) {
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		f.deliver(dstUnreach(s.dst, s.id^0xffff, s.seq, 1), hop, 63)
	})
	p := newPinger(t, f, Options{})
	if r := p.Ping(context.Background(), dstA, 50*time.Millisecond); r.Status != sample.StatusTimeout {
		t.Fatalf("result %+v", r)
	}
}

func TestConcurrentPingsMatchCorrectly(t *testing.T) {
	delays := map[netip.Addr]time.Duration{}
	var dsts []netip.Addr
	for i := range 40 {
		a := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		dsts = append(dsts, a)
		delays[a] = time.Duration(i%8) * 5 * time.Millisecond
	}
	f := newFake(ModeRaw, func(f *fakeConn, s sent) {
		time.Sleep(delays[s.dst])
		f.deliver(echoReply(s.id, s.seq, s.data), s.dst, 50)
	})
	p := newPinger(t, f, Options{FirstSeq: 65530})

	var wg sync.WaitGroup
	results := make([]Result, len(dsts))
	for i, d := range dsts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = p.Ping(context.Background(), d, time.Second)
		}()
	}
	wg.Wait()
	for i, r := range results {
		if r.Status != sample.StatusOK || r.From != dsts[i] {
			t.Fatalf("ping %d: %+v", i, r)
		}
		if r.RTT < delays[dsts[i]] {
			t.Fatalf("ping %d rtt %v below injected delay %v", i, r.RTT, delays[dsts[i]])
		}
	}
	if st := p.Stats(); st.Replies != 40 || st.Unmatched != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPingCancelled(t *testing.T) {
	f := newFake(ModeRaw, nil)
	p := newPinger(t, f, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	r := p.Ping(ctx, dstA, 10*time.Second)
	if r.Err == nil || r.Status != "" || time.Since(start) > time.Second {
		t.Fatalf("result %+v after %v", r, time.Since(start))
	}
	if st := p.Stats(); st.Timeouts != 0 || st.Outstanding != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestSendError(t *testing.T) {
	f := newFake(ModeRaw, nil)
	f.writeErr = errors.New("network is unreachable")
	p := newPinger(t, f, Options{})
	r := p.Ping(context.Background(), dstA, time.Second)
	if r.Status != sample.StatusError || r.Err == nil {
		t.Fatalf("result %+v", r)
	}
	if st := p.Stats(); st.SendErrors != 1 || st.Sent != 0 || st.Outstanding != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestSequenceReuseClearsLateMarker(t *testing.T) {
	p := &Pinger{pending: map[uint16]*inflight{}, timedOut: map[uint16]struct{}{}}
	p.rememberTimeoutLocked(5)
	p.seq = 5
	if s, ok := p.nextSeqLocked(); !ok || s != 5 {
		t.Fatalf("seq %d", s)
	}
	if _, stale := p.timedOut[5]; stale {
		t.Fatal("reused sequence still marked as timed out")
	}
	p.pending[6] = &inflight{}
	if s, _ := p.nextSeqLocked(); s != 7 {
		t.Fatalf("busy sequence reused: %d", s)
	}
}

func TestTimeoutMemoryBounded(t *testing.T) {
	p := &Pinger{timedOut: map[uint16]struct{}{}}
	for i := range recentTimeouts * 3 {
		p.rememberTimeoutLocked(uint16(i))
	}
	if len(p.timedOut) != recentTimeouts {
		t.Fatalf("%d remembered", len(p.timedOut))
	}
}

func TestParseQuotedEcho(t *testing.T) {
	d, id, seq, ok := parseQuotedEcho(quotedEcho(dstB, 0xbeef, 7))
	if !ok || d != dstB || id != 0xbeef || seq != 7 {
		t.Fatalf("%v %x %d %v", d, id, seq, ok)
	}
	short := quotedEcho(dstB, 1, 1)[:24]
	if _, _, _, ok := parseQuotedEcho(short); ok {
		t.Fatal("truncated quote accepted")
	}
	udp := quotedEcho(dstB, 1, 1)
	udp[9] = 17
	if _, _, _, ok := parseQuotedEcho(udp); ok {
		t.Fatal("non-ICMP quote accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
