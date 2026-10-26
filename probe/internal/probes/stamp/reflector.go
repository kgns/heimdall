package stamp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

// Reflector is a stateful STAMP session-reflector. Each sender address and
// port is a session with its own sequence counter, so a sender can tell
// lost requests (the counter did not advance) from lost replies.
type Reflector struct {
	// Now returns the current time; ErrEst describes its accuracy.
	Now    func() time.Time
	ErrEst uint16
	// Idle is how long a session is kept without packets.
	Idle time.Duration
	// MaxSessions bounds memory; packets from new senders beyond it are
	// reflected without a session (sequence 0).
	MaxSessions int

	mu       sync.Mutex
	sessions map[netip.AddrPort]*session

	packets, malformed atomic.Uint64
}

type session struct {
	next uint32
	last time.Time
}

// NewReflector returns a reflector whose clock is synchronised to within
// about a millisecond, as on an instance using Amazon Time Sync.
func NewReflector() *Reflector {
	return &Reflector{
		Now:         time.Now,
		ErrEst:      errSynced | errMillisecond,
		Idle:        5 * time.Minute,
		MaxSessions: 10000,
		sessions:    map[netip.AddrPort]*session{},
	}
}

// Stats is a snapshot of the reflector's counters.
type Stats struct {
	Packets   uint64 `json:"packets"`
	Malformed uint64 `json:"malformed"`
	Sessions  int    `json:"sessions"`
}

// Stats returns the counters.
func (r *Reflector) Stats() Stats {
	r.mu.Lock()
	n := len(r.sessions)
	r.mu.Unlock()
	return Stats{Packets: r.packets.Load(), Malformed: r.malformed.Load(), Sessions: n}
}

// Reflect builds the reply to in, received from src at rx with IP TTL ttl,
// into out (at least len(in) bytes) and returns its length. It returns 0
// for packets that are not STAMP test packets.
func (r *Reflector) Reflect(src netip.AddrPort, ttl int, rx time.Time, in, out []byte) int {
	sp, err := ParseSender(in)
	if err != nil {
		r.malformed.Add(1)
		return 0
	}
	r.packets.Add(1)
	seq := r.nextSeq(src, rx)
	if ttl < 0 || ttl > 255 {
		ttl = 0
	}
	n := len(in)
	if n > len(out) {
		n = len(out)
	}
	clear(out[:n])
	ReflectorPacket{
		Seq: seq, TS: r.Now(), ErrEst: r.ErrEst, RxTS: rx,
		SenderSeq: sp.Seq, SenderTS: sp.TS, SenderErrEst: sp.ErrEst, SenderTTL: uint8(ttl),
	}.Marshal(out)
	return n
}

func (r *Reflector) nextSeq(src netip.AddrPort, now time.Time) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.sessions[src]
	if s == nil {
		if len(r.sessions) >= r.MaxSessions {
			r.expireLocked(now)
			if len(r.sessions) >= r.MaxSessions {
				return 0
			}
		}
		s = &session{}
		r.sessions[src] = s
	}
	s.last = now
	seq := s.next
	s.next++
	return seq
}

// Expire drops sessions idle for longer than Idle.
func (r *Reflector) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked(now)
}

func (r *Reflector) expireLocked(now time.Time) {
	for k, s := range r.sessions {
		if now.Sub(s.last) > r.Idle {
			delete(r.sessions, k)
		}
	}
}

// Serve reflects packets arriving on pc until ctx is cancelled. pc must be
// an IPv4 UDP socket.
func (r *Reflector) Serve(ctx context.Context, pc net.PacketConn) error {
	p := ipv4.NewPacketConn(pc)
	// The TTL of each request goes back to the sender; without it the
	// field stays zero.
	_ = p.SetControlMessage(ipv4.FlagTTL, true)
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				r.Expire(now)
			}
		}
	}()
	in := make([]byte, 1500)
	out := make([]byte, 1500)
	for {
		n, cm, from, err := p.ReadFrom(in)
		rx := r.Now()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ttl := 0
		if cm != nil {
			ttl = cm.TTL
		}
		src := ua.AddrPort()
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if m := r.Reflect(src, ttl, rx, in[:n], out); m > 0 {
			_, _ = p.WriteTo(out[:m], nil, from)
		}
	}
}
