package stamp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func TestPacketRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 26, 12, 0, 0, 123456789, time.UTC)
	var b [PacketSize]byte
	SenderPacket{Seq: 7, TS: ts, ErrEst: errSecond}.Marshal(b[:])
	sp, err := ParseSender(b[:])
	if err != nil || sp.Seq != 7 || sp.ErrEst != errSecond {
		t.Fatalf("%+v %v", sp, err)
	}
	if d := sp.TS.Sub(ts); d < -time.Microsecond || d > time.Microsecond {
		t.Fatalf("timestamp off by %v", d)
	}
	rp := ReflectorPacket{Seq: 3, TS: ts.Add(time.Millisecond), ErrEst: errSynced | errMillisecond, RxTS: ts,
		SenderSeq: 7, SenderTS: ts, SenderErrEst: errSecond, SenderTTL: 52}
	rp.Marshal(b[:])
	got, err := ParseReflector(b[:])
	if err != nil || got.Seq != 3 || got.SenderSeq != 7 || got.SenderTTL != 52 || !Synced(got.ErrEst) || Synced(got.SenderErrEst) {
		t.Fatalf("%+v %v", got, err)
	}
	if got.TS.Sub(got.RxTS).Round(time.Microsecond) != time.Millisecond {
		t.Fatalf("proc %v", got.TS.Sub(got.RxTS))
	}
	if _, err := ParseSender(b[:20]); err != ErrShort {
		t.Fatal("short packet accepted")
	}
}

func TestReflectorSessions(t *testing.T) {
	r := NewReflector()
	a := netip.MustParseAddrPort("192.0.2.1:4000")
	b := netip.MustParseAddrPort("192.0.2.1:4001")
	in := make([]byte, 60)
	SenderPacket{Seq: 9, TS: time.Now()}.Marshal(in)
	out := make([]byte, 1500)
	seqs := func(src netip.AddrPort) uint32 {
		n := r.Reflect(src, 50, time.Now(), in, out)
		if n != len(in) {
			t.Fatalf("reply length %d, want %d", n, len(in))
		}
		p, _ := ParseReflector(out[:n])
		if p.SenderSeq != 9 || p.SenderTTL != 50 {
			t.Fatalf("%+v", p)
		}
		return p.Seq
	}
	if seqs(a) != 0 || seqs(a) != 1 || seqs(b) != 0 || seqs(a) != 2 {
		t.Fatal("per-session sequence numbers")
	}
	if r.Reflect(a, 50, time.Now(), in[:10], out) != 0 || r.Stats().Malformed != 1 {
		t.Fatal("short packet reflected")
	}
	r.Expire(time.Now().Add(time.Hour))
	if r.Stats().Sessions != 0 || seqs(a) != 0 {
		t.Fatal("idle session kept")
	}
}

// lossyReflector drops the requests with sequence numbers in dropReq
// before the reflector sees them, and the replies to those in dropRep.
func lossyReflector(t *testing.T, dropReq, dropRep map[uint32]bool) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	r := NewReflector()
	go func() {
		in, out := make([]byte, 1500), make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(in)
			if err != nil {
				return
			}
			sp, _ := ParseSender(in[:n])
			if dropReq[sp.Seq] {
				continue
			}
			src := from.(*net.UDPAddr).AddrPort()
			m := r.Reflect(src, 64, time.Now(), in[:n], out)
			if dropRep[sp.Seq] {
				continue
			}
			pc.WriteTo(out[:m], from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestSenderLossDirection(t *testing.T) {
	dst := lossyReflector(t, map[uint32]bool{2: true, 3: true}, map[uint32]bool{5: true})
	s, err := Dial(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var res []Result
	for range 8 {
		res = append(res, s.Probe(context.Background(), 200*time.Millisecond))
	}
	for i, r := range res {
		lost := i == 2 || i == 3 || i == 5
		if lost != (r.Status == sample.StatusTimeout) {
			t.Fatalf("probe %d: %+v", i, r)
		}
	}
	if res[0].LossKnown {
		t.Fatal("first reply cannot know loss")
	}
	if r := res[1]; !r.LossKnown || r.LostUp != 0 || r.LostDown != 0 || r.ReflSeq != 1 {
		t.Fatalf("probe 1: %+v", r)
	}
	// Requests 2 and 3 never reached the reflector.
	if r := res[4]; !r.LossKnown || r.LostUp != 2 || r.LostDown != 0 || r.ReflSeq != 2 {
		t.Fatalf("probe 4: %+v", r)
	}
	// Request 5 was reflected (reflector sequence 3) but its reply lost.
	if r := res[6]; !r.LossKnown || r.LostUp != 0 || r.LostDown != 1 || r.ReflSeq != 4 {
		t.Fatalf("probe 6: %+v", r)
	}
	r := res[7]
	if r.RTT <= 0 || r.Proc < 0 || r.Proc > r.RTT || r.FwdHops != 0 || !r.ReflSynced {
		t.Fatalf("probe 7: %+v", r)
	}
	if d := r.Fwd + r.Rev + r.Proc - r.RTT; d < -time.Millisecond || d > time.Millisecond {
		t.Fatalf("fwd %v + rev %v + proc %v != rtt %v", r.Fwd, r.Rev, r.Proc, r.RTT)
	}
}

func TestServeEchoesTTL(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go NewReflector().Serve(ctx, pc)
	s, err := Dial(pc.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := s.Probe(context.Background(), time.Second)
	if r.Status != sample.StatusOK || r.ArrivalTTL != SendTTL || r.FwdHops != 0 {
		t.Fatalf("%+v", r)
	}
}

func TestSenderTimeoutAndCancel(t *testing.T) {
	// A bound socket that never answers.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s, err := Dial(pc.LocalAddr().(*net.UDPAddr).AddrPort())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if r := s.Probe(context.Background(), 50*time.Millisecond); r.Status != sample.StatusTimeout {
		t.Fatalf("%+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := s.Probe(ctx, time.Second); r.Status != "" {
		t.Fatalf("cancelled probe returned %+v", r)
	}
}
