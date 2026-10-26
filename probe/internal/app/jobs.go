package app

import (
	"context"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/probes/httpp"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/probes/stamp"
	"github.com/kgns/heimdall/probe/internal/probes/tcpp"
	"github.com/kgns/heimdall/probe/internal/probes/udpecho"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/scheduler"
	"github.com/kgns/heimdall/probe/internal/target"
)

// env is what the job builders share.
type env struct {
	cfg       config.Config
	rec       *sample.Recorder
	pinger    *icmp.Pinger
	log       *slog.Logger
	userAgent string
}

func maxInFlight(timeout, interval time.Duration) int {
	return int(math.Ceil(float64(timeout)/float64(interval))) + 1
}

func (e *env) icmpJob(t *target.Target) scheduler.Job {
	timeout := e.cfg.ICMP.Timeout
	return scheduler.Job{
		Name:        "icmp/" + t.ID,
		Interval:    t.Interval,
		Budgeted:    true,
		MaxInFlight: maxInFlight(timeout, t.Interval),
		Run: func(ctx context.Context) {
			dst, ok := t.Dst()
			if !ok {
				return
			}
			r := e.pinger.Ping(ctx, dst, t.TTL, timeout)
			if r.Status == "" {
				return
			}
			s := icmpSample(t, dst, r)
			withEndpoint(t, &s)
			if t.TTL > 0 && s.Status == sample.StatusOK {
				if prev, changed := t.ObserveHop(r.From); changed {
					e.log.Info("hop changed", "target", t.ID, "ttl", t.TTL, "from", prev, "to", r.From)
					e.rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
						Category: t.Category, Service: t.Service, DstIP: r.From.String(),
						Extra: map[string]any{"event": "hop_change", "ttl": t.TTL, "via": dst.String(), "prev": prev.String()}})
				}
			}
			e.rec.Emit(s)
		},
	}
}

func (e *env) tcpJob(t *target.Target) scheduler.Job {
	c := e.cfg.TCP
	return scheduler.Job{
		Name:        "tcp/" + t.ID,
		Interval:    c.Interval,
		Budgeted:    true,
		MaxInFlight: maxInFlight(c.Timeout, c.Interval),
		Run: func(ctx context.Context) {
			dst, ok := t.Dst()
			if !ok {
				return
			}
			port := endpointPort(t, t.Port)
			r := tcpp.Connect(ctx, nil, netip.AddrPortFrom(dst, uint16(port)), c.Timeout)
			if ctx.Err() != nil {
				return
			}
			s := sample.Sample{
				TS: r.Sent.UnixMilli(), Kind: sample.KindTCP, Category: t.Category, Service: t.Service,
				TargetID: t.ID, DstIP: dst.String(), DstPort: port, Status: r.Status,
			}
			if r.RTT > 0 {
				s.RTTms = sample.RTT(r.RTT)
			}
			if r.Status != sample.StatusOK {
				s.Extra = map[string]any{"reason": r.Reason}
			}
			withEndpoint(t, &s)
			e.rec.Emit(s)
		},
	}
}

// withEndpoint adds the discovered server behind t to the sample.
func withEndpoint(t *target.Target, s *sample.Sample) {
	ep, ok := t.Endpoint()
	if !ok || ep.Label == "" {
		return
	}
	if s.Extra == nil {
		s.Extra = map[string]any{}
	}
	s.Extra["endpoint"] = ep.Label
}

// endpointPort returns the discovered server's port, or def.
func endpointPort(t *target.Target, def int) int {
	if ep, ok := t.Endpoint(); ok && ep.Port != 0 {
		return ep.Port
	}
	return def
}

// udpJob measures a UDP echo service (proto udp) or a STUN server (stun).
func (e *env) udpJob(t *target.Target, proto string) scheduler.Job {
	c := e.cfg.UDP
	return scheduler.Job{
		Name:        proto + "/" + t.ID,
		Interval:    c.Interval,
		Budgeted:    true,
		MaxInFlight: maxInFlight(c.Timeout, c.Interval),
		Run: func(ctx context.Context) {
			dst, ok := t.Dst()
			if !ok {
				return
			}
			port := endpointPort(t, t.UDPPort)
			ap := netip.AddrPortFrom(dst, uint16(port))
			var r udpecho.Result
			kind := sample.KindUDPEcho
			if proto == config.ProtoSTUN {
				r, kind = udpecho.STUN(ctx, ap, c.Timeout), sample.KindSTUN
			} else {
				r = udpecho.Echo(ctx, ap, c.Timeout)
			}
			if r.Status == "" {
				return
			}
			s := sample.Sample{
				TS: r.Sent.UnixMilli(), Kind: kind, Category: t.Category, Service: t.Service,
				TargetID: t.ID, DstIP: dst.String(), DstPort: port, Status: r.Status,
				Extra: map[string]any{"proto": proto},
			}
			if r.Status == sample.StatusOK {
				s.RTTms = sample.RTT(r.RTT)
				if r.Mapped.IsValid() {
					s.Extra["mapped"] = r.Mapped.String()
				}
			} else {
				s.Extra["reason"] = r.Reason
			}
			withEndpoint(t, &s)
			e.rec.Emit(s)
		},
	}
}

// stampSenders holds one STAMP sender per target, re-dialled when the
// target's address changes.
type stampSenders struct {
	mu   sync.Mutex
	byID map[string]*stampSender
}

type stampSender struct {
	dst netip.AddrPort
	s   *stamp.Sender
}

func (ss *stampSenders) get(id string, dst netip.AddrPort) (*stamp.Sender, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if cur := ss.byID[id]; cur != nil {
		if cur.dst == dst {
			return cur.s, nil
		}
		cur.s.Close()
		delete(ss.byID, id)
	}
	s, err := stamp.Dial(dst)
	if err != nil {
		return nil, err
	}
	if ss.byID == nil {
		ss.byID = map[string]*stampSender{}
	}
	ss.byID[id] = &stampSender{dst: dst, s: s}
	return s, nil
}

func (ss *stampSenders) close() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for id, cur := range ss.byID {
		cur.s.Close()
		delete(ss.byID, id)
	}
}

func (e *env) stampJob(t *target.Target, ss *stampSenders) scheduler.Job {
	c := e.cfg.STAMP
	return scheduler.Job{
		Name:        "stamp/" + t.ID,
		Interval:    c.Interval,
		Budgeted:    true,
		MaxInFlight: maxInFlight(c.Timeout, c.Interval),
		Run: func(ctx context.Context) {
			dst, ok := t.Dst()
			if !ok {
				return
			}
			ap := netip.AddrPortFrom(dst, uint16(c.Port))
			s := sample.Sample{
				Kind: sample.KindUDPEcho, Category: t.Category, Service: t.Service,
				TargetID: t.ID, DstIP: dst.String(), DstPort: c.Port,
			}
			snd, err := ss.get(t.ID, ap)
			if err != nil {
				s.TS = time.Now().UnixMilli()
				s.Status, _ = neterr.Classify(err)
				s.Extra = map[string]any{"proto": "stamp", "error": err.Error()}
				e.rec.Emit(s)
				return
			}
			r := snd.Probe(ctx, c.Timeout)
			if r.Status == "" {
				return
			}
			e.rec.Emit(stampSample(s, r))
		},
	}
}

// stampSample reports the round trip without the reflector's turnaround
// as the RTT. The one-way delays depend on the offset between the two
// clocks and are kept in extra for correction downstream.
func stampSample(s sample.Sample, r stamp.Result) sample.Sample {
	s.TS = r.Sent.UnixMilli()
	s.Status = r.Status
	x := map[string]any{"proto": "stamp", "seq": r.Seq}
	if r.Status == sample.StatusOK {
		s.RTTms = sample.RTT(r.RTT - r.Proc)
		x["refl_seq"] = r.ReflSeq
		x["fwd_ms"] = sample.Millis(r.Fwd)
		x["rev_ms"] = sample.Millis(r.Rev)
		x["proc_ms"] = sample.Millis(r.Proc)
		x["refl_synced"] = r.ReflSynced
		if r.ArrivalTTL > 0 {
			x["fwd_hops"] = r.FwdHops
		}
		if r.LossKnown {
			x["lost_up"] = r.LostUp
			x["lost_down"] = r.LostDown
		}
	} else {
		x["reason"] = r.Reason
	}
	s.Extra = x
	return s
}

func (e *env) httpJob(t *target.Target) scheduler.Job {
	c := e.cfg.HTTP
	return scheduler.Job{
		Name:        "http/" + t.ID,
		Interval:    c.Interval,
		Budgeted:    true,
		MaxInFlight: 1,
		Run: func(ctx context.Context) {
			dst, ok := t.Dst()
			if !ok {
				return
			}
			r := httpp.Probe(ctx, httpp.Request{
				Host: t.Host, Path: t.Path, Dst: netip.AddrPortFrom(dst, uint16(t.Port)),
				Timeout: c.Timeout, UserAgent: e.userAgent, MaxBody: int64(c.MaxBody),
			})
			if ctx.Err() != nil {
				return
			}
			e.rec.Emit(httpSample(t, dst, r))
		},
	}
}

// httpSample reports the time to the first response byte on a fresh
// connection as the RTT, which is what a page load waits for, and keeps
// the phases in extra.
func httpSample(t *target.Target, dst netip.Addr, r httpp.Result) sample.Sample {
	s := sample.Sample{
		TS: r.Sent.UnixMilli(), Kind: sample.KindHTTP, Category: t.Category, Service: t.Service,
		TargetID: t.ID, DstIP: dst.String(), DstPort: t.Port, Status: r.Status,
	}
	x := map[string]any{}
	putMs := func(k string, d time.Duration) {
		if d > 0 {
			x[k] = sample.Millis(d)
		}
	}
	putMs("connect_ms", r.Connect)
	putMs("tls_ms", r.TLS)
	putMs("ttfb_ms", r.TTFB)
	putMs("total_ms", r.Total)
	if r.FirstByte > 0 && r.Status == sample.StatusOK {
		s.RTTms = sample.RTT(r.FirstByte)
	}
	if r.StatusCode != 0 {
		x["code"] = r.StatusCode
		x["proto"] = r.Proto
		x["tls"] = r.TLSVersion
		if r.KeyExchange != "" {
			x["kex"] = r.KeyExchange
		}
		x["bytes"] = r.Bytes
	}
	for k, v := range map[string]string{"cdn": r.Edge.CDN, "pop": r.Edge.PoP, "server": r.Edge.Server, "cache": r.Edge.Cache} {
		if v != "" {
			x[k] = v
		}
	}
	if r.Status != sample.StatusOK {
		x["reason"] = r.Reason
		x["phase"] = r.Phase
	}
	s.Extra = x
	return s
}
