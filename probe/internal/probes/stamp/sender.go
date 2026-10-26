package stamp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// SendTTL is the IP TTL of test packets. The reflector echoes the TTL it
// saw, so SendTTL minus that value is the forward hop count.
const SendTTL = 64

// Result is one test packet.
type Result struct {
	Status sample.Status
	Reason string
	Sent   time.Time
	// RTT is from sending to receiving the reply; Proc is the time the
	// packet spent in the reflector, measured on the reflector's clock.
	RTT  time.Duration
	Proc time.Duration
	// Fwd and Rev are the one-way delays. They combine two clocks, so any
	// offset between the sender's clock and the reflector's moves them in
	// opposite directions; their sum is RTT - Proc.
	Fwd, Rev   time.Duration
	Seq        uint32
	ReflSeq    uint32
	ReflSynced bool
	// ArrivalTTL is the TTL the request arrived with (0 when the reflector
	// could not read it) and FwdHops is SendTTL minus it.
	ArrivalTTL int
	FwdHops    int
	// LostUp and LostDown count packets lost since the previous in-order
	// reply: requests that never reached the reflector, and replies that
	// never came back. Known only when this reply arrives.
	LostUp, LostDown int
	// LossKnown is false when the reply cannot be compared with the
	// previous one, for example after the reflector restarted.
	LossKnown bool
}

type reply struct {
	p    ReflectorPacket
	recv time.Time
	up   int
	down int
	ok   bool
}

// Sender sends test packets to one reflector over a connected UDP socket
// and matches the replies.
type Sender struct {
	conn *net.UDPConn
	now  func() time.Time

	mu      sync.Mutex
	seq     uint32
	pending map[uint32]chan reply
	// lastSeq and lastRefl are the sender and reflector sequence numbers
	// of the newest reply, for loss direction.
	lastSeq, lastRefl uint32
	haveLast          bool
	closed            chan struct{}
}

// Dial opens a sender towards dst.
func Dial(dst netip.AddrPort) (*Sender, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
	if err != nil {
		return nil, err
	}
	// Linux defaults to 64 too; set it so FwdHops does not depend on the
	// system setting.
	_ = ipv4.NewConn(c).SetTTL(SendTTL)
	s := &Sender{conn: c, now: time.Now, pending: map[uint32]chan reply{}, closed: make(chan struct{})}
	go s.read()
	return s, nil
}

// Close stops the sender.
func (s *Sender) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return s.conn.Close()
}

func (s *Sender) read() {
	b := make([]byte, 1500)
	for {
		n, err := s.conn.Read(b)
		recv := s.now()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// ICMP port unreachable surfaces here as ECONNREFUSED on a
			// connected socket; the waiting probe times out.
			select {
			case <-s.closed:
				return
			default:
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}
		p, err := ParseReflector(b[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		r := reply{p: p, recv: recv}
		r.up, r.down, r.ok = s.lossLocked(p.SenderSeq, p.Seq)
		ch := s.pending[p.SenderSeq]
		delete(s.pending, p.SenderSeq)
		s.mu.Unlock()
		if ch != nil {
			ch <- r
		}
	}
}

// lossLocked compares a reply with the previous in-order one. Between two
// replies the sender sent ds packets and the reflector answered dr of
// them, so ds-dr requests were lost on the way out and dr-1 replies on the
// way back.
func (s *Sender) lossLocked(seq, refl uint32) (up, down int, ok bool) {
	defer func() {
		if !s.haveLast || seq > s.lastSeq || refl < s.lastRefl {
			s.lastSeq, s.lastRefl, s.haveLast = seq, refl, true
		}
	}()
	if !s.haveLast || seq <= s.lastSeq || refl < s.lastRefl {
		// First reply, a reordered one, or a new reflector session.
		return 0, 0, false
	}
	ds := int64(seq) - int64(s.lastSeq)
	dr := int64(refl) - int64(s.lastRefl)
	if dr < 1 || dr > ds {
		return 0, 0, false
	}
	return int(ds - dr), int(dr - 1), true
}

// Probe sends one test packet and waits up to timeout for its reply.
func (s *Sender) Probe(ctx context.Context, timeout time.Duration) Result {
	ch := make(chan reply, 1)
	s.mu.Lock()
	seq := s.seq
	s.seq++
	s.pending[seq] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, seq)
		s.mu.Unlock()
	}()

	var b [PacketSize]byte
	sent := s.now()
	SenderPacket{Seq: seq, TS: sent, ErrEst: errSecond}.Marshal(b[:])
	r := Result{Sent: sent, Seq: seq}
	if _, err := s.conn.Write(b[:]); err != nil {
		r.Status, r.Reason = neterr.Classify(err)
		return r
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return Result{}
	case <-t.C:
		r.Status, r.Reason = sample.StatusTimeout, "timeout"
		return r
	case rep := <-ch:
		p := rep.p
		r.Status = sample.StatusOK
		r.RTT = rep.recv.Sub(sent)
		r.Proc = p.TS.Sub(p.RxTS)
		r.Fwd = p.RxTS.Sub(sent)
		r.Rev = rep.recv.Sub(p.TS)
		r.ReflSeq = p.Seq
		r.ReflSynced = Synced(p.ErrEst)
		r.ArrivalTTL = int(p.SenderTTL)
		if p.SenderTTL > 0 {
			r.FwdHops = SendTTL - int(p.SenderTTL)
		}
		r.LostUp, r.LostDown, r.LossKnown = rep.up, rep.down, rep.ok
		return r
	}
}
