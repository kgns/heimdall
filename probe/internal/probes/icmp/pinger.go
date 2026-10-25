package icmp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/kgns/heimdall/probe/internal/sample"
)

const (
	protocolICMP = 1
	tokenLen     = 8
	// MinPayload is the smallest payload that still carries the token.
	MinPayload = tokenLen
	// recentTimeouts bounds the memory used to recognise late replies.
	recentTimeouts = 1024
)

// Result is the outcome of one echo request.
type Result struct {
	Status   sample.Status
	Sent     time.Time
	RTT      time.Duration
	TTL      int
	From     netip.Addr
	ICMPType int
	ICMPCode int
	Err      error
}

// Stats are cumulative pinger counters.
type Stats struct {
	Sent        uint64 `json:"sent"`
	Replies     uint64 `json:"replies"`
	Errors      uint64 `json:"icmp_errors"`
	Timeouts    uint64 `json:"timeouts"`
	SendErrors  uint64 `json:"send_errors"`
	Late        uint64 `json:"late"`
	Unmatched   uint64 `json:"unmatched"`
	Foreign     uint64 `json:"foreign"`
	ReadErrors  uint64 `json:"read_errors"`
	SeqExhaust  uint64 `json:"seq_exhausted"`
	Outstanding int    `json:"outstanding"`
	// ForeignTypes counts foreign messages by ICMP type number, so that
	// other ICMP traffic on the host can be identified.
	ForeignTypes map[string]uint64 `json:"foreign_types,omitempty"`
}

type reply struct {
	at       time.Time
	status   sample.Status
	ttl      int
	from     netip.Addr
	typ, cod int
}

type inflight struct {
	dst  netip.Addr
	sent time.Time
	ch   chan reply
}

// Options configure a Pinger.
type Options struct {
	// PayloadSize is the echo data length in bytes, at least MinPayload.
	PayloadSize int
	// ID is the echo identifier used in raw mode. Zero picks a random one.
	ID uint16
	// FirstSeq sets the initial sequence number, for tests.
	FirstSeq uint16
	Now      func() time.Time
}

// Pinger multiplexes echo requests to many destinations over one socket.
type Pinger struct {
	conn    Conn
	id      uint16
	token   [tokenLen]byte
	payload []byte
	now     func() time.Time

	mu       sync.Mutex
	seq      uint16
	pending  map[uint16]*inflight
	timedOut map[uint16]struct{}
	toRing   []uint16
	toNext   int

	sent, replies, icmpErrors, timeouts, sendErrors atomic.Uint64
	late, unmatched, foreign, readErrors, exhausted atomic.Uint64
	// foreignTypes[256] counts messages too short to parse.
	foreignTypes [257]atomic.Uint64

	done chan struct{}
}

// New starts a pinger on conn. It owns conn and closes it in Close.
func New(conn Conn, opt Options) (*Pinger, error) {
	if opt.PayloadSize < MinPayload {
		opt.PayloadSize = MinPayload
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	p := &Pinger{
		conn:     conn,
		id:       opt.ID,
		seq:      opt.FirstSeq,
		now:      opt.Now,
		pending:  map[uint16]*inflight{},
		timedOut: map[uint16]struct{}{},
		toRing:   make([]uint16, 0, recentTimeouts),
		done:     make(chan struct{}),
	}
	if _, err := rand.Read(p.token[:]); err != nil {
		return nil, err
	}
	if p.id == 0 {
		var b [2]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		p.id = binary.BigEndian.Uint16(b[:]) | 1
	}
	p.payload = make([]byte, opt.PayloadSize)
	copy(p.payload, p.token[:])
	for i := tokenLen; i < len(p.payload); i++ {
		p.payload[i] = byte(i)
	}
	go p.readLoop()
	return p, nil
}

// Mode returns the socket mode in use.
func (p *Pinger) Mode() Mode { return p.conn.Mode() }

// Close stops the reader and closes the socket.
func (p *Pinger) Close() error {
	err := p.conn.Close()
	<-p.done
	return err
}

// Stats returns a snapshot of the counters.
func (p *Pinger) Stats() Stats {
	p.mu.Lock()
	out := len(p.pending)
	p.mu.Unlock()
	st := Stats{
		Sent: p.sent.Load(), Replies: p.replies.Load(), Errors: p.icmpErrors.Load(),
		Timeouts: p.timeouts.Load(), SendErrors: p.sendErrors.Load(), Late: p.late.Load(),
		Unmatched: p.unmatched.Load(), Foreign: p.foreign.Load(), ReadErrors: p.readErrors.Load(),
		SeqExhaust: p.exhausted.Load(), Outstanding: out,
	}
	for i := range p.foreignTypes {
		n := p.foreignTypes[i].Load()
		if n == 0 {
			continue
		}
		if st.ForeignTypes == nil {
			st.ForeignTypes = map[string]uint64{}
		}
		key := "short"
		if i < 256 {
			key = strconv.Itoa(i)
		}
		st.ForeignTypes[key] = n
	}
	return st
}

func (p *Pinger) countForeign(b []byte) {
	p.foreign.Add(1)
	if len(b) == 0 {
		p.foreignTypes[256].Add(1)
		return
	}
	p.foreignTypes[b[0]].Add(1)
}

var errSeqExhausted = errors.New("all ICMP sequence numbers in flight")

// Ping sends one echo request to dst with IP TTL ttl (0 for the socket
// default) and waits up to timeout for an answer: an echo reply, or an ICMP
// error such as time exceeded from the router where the TTL ran out. If ctx
// ends first the result has Status "" and Err set.
func (p *Pinger) Ping(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) Result {
	fl := &inflight{dst: dst, ch: make(chan reply, 1)}

	p.mu.Lock()
	seq, ok := p.nextSeqLocked()
	if !ok {
		p.mu.Unlock()
		p.exhausted.Add(1)
		return Result{Status: sample.StatusError, Sent: p.now(), Err: errSeqExhausted}
	}
	msg, err := (&xicmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &xicmp.Echo{ID: int(p.id), Seq: int(seq), Data: p.payload},
	}).Marshal(nil)
	if err != nil {
		p.mu.Unlock()
		return Result{Status: sample.StatusError, Sent: p.now(), Err: err}
	}
	fl.sent = p.now()
	p.pending[seq] = fl
	p.mu.Unlock()

	if err := p.conn.WriteTo(msg, dst, ttl); err != nil {
		p.mu.Lock()
		delete(p.pending, seq)
		p.mu.Unlock()
		p.sendErrors.Add(1)
		return Result{Status: sample.StatusError, Sent: fl.sent, Err: err}
	}
	p.sent.Add(1)

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case r := <-fl.ch:
		return p.result(fl, r)
	case <-timer.C:
	case <-ctx.Done():
	}

	p.mu.Lock()
	_, stillPending := p.pending[seq]
	if stillPending {
		delete(p.pending, seq)
		if ctx.Err() == nil {
			p.rememberTimeoutLocked(seq)
		}
	}
	p.mu.Unlock()
	if !stillPending {
		// The reader delivered between the timer firing and the lock.
		return p.result(fl, <-fl.ch)
	}
	if ctx.Err() != nil {
		return Result{Sent: fl.sent, Err: ctx.Err()}
	}
	p.timeouts.Add(1)
	return Result{Status: sample.StatusTimeout, Sent: fl.sent}
}

func (p *Pinger) result(fl *inflight, r reply) Result {
	return Result{
		Status: r.status, Sent: fl.sent, RTT: r.at.Sub(fl.sent),
		TTL: r.ttl, From: r.from, ICMPType: r.typ, ICMPCode: r.cod,
	}
}

func (p *Pinger) nextSeqLocked() (uint16, bool) {
	for range 1 << 16 {
		s := p.seq
		p.seq++
		if _, busy := p.pending[s]; !busy {
			// A late reply for a reused sequence number must not be
			// mistaken for the new request's answer.
			delete(p.timedOut, s)
			return s, true
		}
	}
	return 0, false
}

func (p *Pinger) rememberTimeoutLocked(seq uint16) {
	if len(p.toRing) < recentTimeouts {
		p.toRing = append(p.toRing, seq)
	} else {
		delete(p.timedOut, p.toRing[p.toNext])
		p.toRing[p.toNext] = seq
		p.toNext = (p.toNext + 1) % recentTimeouts
	}
	p.timedOut[seq] = struct{}{}
}

func (p *Pinger) readLoop() {
	defer close(p.done)
	buf := make([]byte, 1500)
	for {
		n, src, ttl, err := p.conn.ReadFrom(buf)
		at := p.now()
		if err != nil {
			if errors.Is(err, ErrClosed) {
				return
			}
			p.readErrors.Add(1)
			time.Sleep(10 * time.Millisecond)
			continue
		}
		p.handle(buf[:n], src, ttl, at)
	}
}

func (p *Pinger) handle(b []byte, src netip.Addr, ttl int, at time.Time) {
	m, err := xicmp.ParseMessage(protocolICMP, b)
	if err != nil {
		p.countForeign(b)
		return
	}
	switch m.Type {
	case ipv4.ICMPTypeEchoReply:
		echo, ok := m.Body.(*xicmp.Echo)
		if !ok || !p.ours(uint16(echo.ID), echo.Data) {
			p.countForeign(b)
			return
		}
		p.deliver(uint16(echo.Seq), src, reply{at: at, status: sample.StatusOK, ttl: ttl, from: src})
	case ipv4.ICMPTypeDestinationUnreachable, ipv4.ICMPTypeTimeExceeded:
		var data []byte
		status := sample.StatusUnreachable
		switch body := m.Body.(type) {
		case *xicmp.DstUnreach:
			data = body.Data
		case *xicmp.TimeExceeded:
			data, status = body.Data, sample.StatusTimeExceeded
		}
		dst, id, seq, ok := parseQuotedEcho(data)
		if !ok || (p.conn.Mode() == ModeRaw && id != p.id) {
			p.countForeign(b)
			return
		}
		typ, _ := m.Type.(ipv4.ICMPType)
		p.deliver(seq, dst, reply{at: at, status: status, ttl: ttl, from: src, typ: int(typ), cod: m.Code})
	default:
		p.countForeign(b)
	}
}

func (p *Pinger) ours(id uint16, data []byte) bool {
	if p.conn.Mode() == ModeRaw && id != p.id {
		return false
	}
	return len(data) >= tokenLen && [tokenLen]byte(data[:tokenLen]) == p.token
}

// deliver hands r to the request with sequence seq if dst matches its
// destination.
func (p *Pinger) deliver(seq uint16, dst netip.Addr, r reply) {
	p.mu.Lock()
	fl, ok := p.pending[seq]
	if ok && fl.dst != dst {
		ok = false
	}
	if ok {
		delete(p.pending, seq)
	} else if _, wasTimeout := p.timedOut[seq]; wasTimeout {
		delete(p.timedOut, seq)
		p.mu.Unlock()
		p.late.Add(1)
		return
	}
	p.mu.Unlock()
	if !ok {
		p.unmatched.Add(1)
		return
	}
	if r.status == sample.StatusOK {
		p.replies.Add(1)
	} else {
		p.icmpErrors.Add(1)
	}
	fl.ch <- r
}

// parseQuotedEcho extracts the destination, identifier and sequence number
// of an echo request quoted inside an ICMP error: the original IPv4 header
// followed by at least the first 8 bytes of the original ICMP message.
func parseQuotedEcho(d []byte) (dst netip.Addr, id, seq uint16, ok bool) {
	if len(d) < 20 || d[0]>>4 != 4 {
		return netip.Addr{}, 0, 0, false
	}
	ihl := int(d[0]&0x0f) * 4
	if ihl < 20 || len(d) < ihl+8 || d[9] != protocolICMP || d[ihl] != byte(ipv4.ICMPTypeEcho) {
		return netip.Addr{}, 0, 0, false
	}
	dst = netip.AddrFrom4([4]byte(d[16:20]))
	id = binary.BigEndian.Uint16(d[ihl+4:])
	seq = binary.BigEndian.Uint16(d[ihl+6:])
	return dst, id, seq, true
}
