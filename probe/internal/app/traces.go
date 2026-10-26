package app

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/trace"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/scheduler"
	"github.com/kgns/heimdall/probe/internal/target"
)

// tracer traces the targets in turn, one per run.
type tracer struct {
	*env
	pinger  trace.Pinger
	targets []*target.Target

	mu   sync.Mutex
	next int
	// last remembers when each destination was traced, so that targets
	// sharing an address are traced once per round.
	last map[netip.Addr]time.Time
}

func newTracer(e *env, p trace.Pinger, targets []*target.Target) *tracer {
	var ts []*target.Target
	for _, t := range targets {
		// TTL-limited targets measure a router, not a path.
		if t.TTL == 0 {
			ts = append(ts, t)
		}
	}
	return &tracer{env: e, pinger: p, targets: ts, last: map[netip.Addr]time.Time{}}
}

func (tr *tracer) job() scheduler.Job {
	return scheduler.Job{
		Name: "trace", Interval: tr.cfg.Trace.Interval, MaxInFlight: 1,
		Run: func(ctx context.Context) {
			if t, dst, ok := tr.pick(time.Now()); ok {
				tr.trace(ctx, t, dst)
			}
		},
	}
}

// pick returns the next target with an address not traced in the last
// round.
func (tr *tracer) pick(now time.Time) (*target.Target, netip.Addr, bool) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	round := time.Duration(len(tr.targets)) * tr.cfg.Trace.Interval
	for range tr.targets {
		t := tr.targets[tr.next%len(tr.targets)]
		tr.next++
		dst, ok := t.Dst()
		if !ok {
			continue
		}
		if at, seen := tr.last[dst]; seen && now.Sub(at) < round/2 {
			continue
		}
		tr.last[dst] = now
		return t, dst, true
	}
	return nil, netip.Addr{}, false
}

func (tr *tracer) trace(ctx context.Context, t *target.Target, dst netip.Addr) {
	c := tr.cfg.Trace
	r := trace.Run(ctx, tr.pinger, dst, trace.Options{MaxHops: c.MaxHops, Probes: c.Probes, Timeout: c.Timeout, Gap: c.Gap})
	if ctx.Err() != nil {
		return
	}
	s := sample.Sample{
		TS: r.Sent.UnixMilli(), Kind: sample.KindTrace, Category: t.Category, Service: t.Service,
		TargetID: t.ID, DstIP: dst.String(), Status: sample.StatusOK,
		Extra: map[string]any{"hops": r.Hops, "reached": r.Reached, "hop_count": len(r.Hops), "probes": c.Probes},
	}
	if r.Reached {
		s.RTTms = sample.RTT(r.RTT)
	} else {
		s.Status = sample.StatusTimeout
	}
	withEndpoint(t, &s)
	tr.rec.Emit(s)
}
