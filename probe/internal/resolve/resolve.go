// Package resolve keeps hostname targets pointed at a current address,
// resolving through the system resolver the way LAN clients do.
package resolve

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/target"
)

// LookupFunc returns the IPv4 addresses of host.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// SystemLookup resolves through /etc/resolv.conf with Go's resolver. On a
// CPE that is the local dnsmasq, which is also what LAN clients use.
func SystemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, err
}

type state struct {
	failing  bool
	unusable bool
}

// Resolver updates targets that have a Host.
type Resolver struct {
	lookup  LookupFunc
	allowed func(netip.Addr) bool
	emit    func(sample.Sample)
	log     *slog.Logger
	timeout time.Duration

	mu     sync.Mutex
	states map[*target.Target]*state

	// ResolverID, when set, names the upstream resolver currently answering,
	// so that address changes can be tied to resolver changes.
	ResolverID func() string
}

// New returns a resolver. allowed filters addresses the probe may send to;
// emit receives change events.
func New(lookup LookupFunc, allowed func(netip.Addr) bool, emit func(sample.Sample), log *slog.Logger, timeout time.Duration) *Resolver {
	return &Resolver{lookup: lookup, allowed: allowed, emit: emit, log: log, timeout: timeout, states: map[*target.Target]*state{}}
}

// Result is the outcome of one resolution.
type Result struct {
	Answers []netip.Addr
	Chosen  netip.Addr
	// Blocked is set when the chosen address leaves through a non-default
	// route and will not be probed.
	Blocked  bool
	Changed  bool
	Duration time.Duration
	Err      error
}

// Refresh resolves t.Host and updates the target. The current address is
// kept while it is still in the answer, so round-robin DNS does not make
// the target jump between servers on every refresh. Otherwise the first
// usable address the route guard allows is chosen. Lookup failures keep the
// last good address.
func (r *Resolver) Refresh(ctx context.Context, t *target.Target) Result {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	start := time.Now()
	answers, err := r.lookup(ctx, t.Host)
	res := Result{Answers: answers, Duration: time.Since(start), Err: err}

	if err != nil {
		if r.transition(t, failing, true) {
			r.log.Warn("resolve failed", "target", t.ID, "host", t.Host, "err", err)
			r.event(t, "resolve_error", map[string]any{"host": t.Host, "error": err.Error()})
		}
		res.Chosen = t.Addr()
		return res
	}
	if r.transition(t, failing, false) {
		r.event(t, "resolve_recovered", map[string]any{"host": t.Host})
	}

	var usable []netip.Addr
	for _, a := range answers {
		if config.UsableAddr(a) {
			usable = append(usable, a)
		}
	}
	if len(usable) == 0 {
		if r.transition(t, unusable, true) {
			r.log.Warn("resolve returned no usable address", "target", t.ID, "host", t.Host, "answers", answers)
			r.event(t, "resolve_unusable", map[string]any{"host": t.Host, "answers": addrStrings(answers)})
		}
		res.Chosen = t.Addr()
		return res
	}
	r.transition(t, unusable, false)

	cur := t.Addr()
	chosen := cur
	if !slices.Contains(usable, cur) {
		chosen = usable[0]
		for _, a := range usable {
			if r.allowed(a) {
				chosen = a
				break
			}
		}
	}
	res.Chosen = chosen
	res.Blocked = !r.allowed(chosen)
	t.SetBlocked(res.Blocked)
	if t.SetDst(chosen) {
		res.Changed = true
		x := map[string]any{
			"event":      "dst_change",
			"host":       t.Host,
			"answers":    addrStrings(answers),
			"resolve_ms": sample.Millis(res.Duration),
		}
		if cur.IsValid() {
			x["prev"] = cur.String()
		}
		s := sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
			Category: t.Category, Service: t.Service, DstIP: chosen.String(), Extra: x}
		if r.ResolverID != nil {
			s.ResolverID = r.ResolverID()
		}
		r.log.Info("target address set", "target", t.ID, "host", t.Host, "dst", chosen, "prev", cur, "resolver", s.ResolverID)
		r.emit(s)
	}
	return res
}

// transition sets one of the state flags and reports whether it changed.
func (r *Resolver) transition(t *target.Target, flag func(*state) *bool, v bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.states[t]
	if st == nil {
		st = &state{}
		r.states[t] = st
	}
	p := flag(st)
	if *p == v {
		return false
	}
	*p = v
	return true
}

func failing(s *state) *bool  { return &s.failing }
func unusable(s *state) *bool { return &s.unusable }

// RefreshAll resolves all targets with at most concurrency lookups at once.
func (r *Resolver) RefreshAll(ctx context.Context, targets []*target.Target, concurrency int) {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			r.Refresh(ctx, t)
		}()
	}
	wg.Wait()
}

func (r *Resolver) event(t *target.Target, name string, x map[string]any) {
	x["event"] = name
	r.emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
		Category: t.Category, Service: t.Service, Extra: x})
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}
