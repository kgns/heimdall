package app

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/kgns/heimdall/probe/internal/discover"
	"github.com/kgns/heimdall/probe/internal/resolve"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/scheduler"
	"github.com/kgns/heimdall/probe/internal/target"
)

// discoveryGroup is the targets one discoverer fills for one service.
type discoveryGroup struct {
	service, category, name string
	args                    []string
	slots                   []*target.Target
}

// discoverFunc runs a discoverer; tests replace it.
type discoverFunc func(ctx context.Context, name string, env discover.Env) ([]discover.Endpoint, error)

type discovery struct {
	*env
	groups  []*discoveryGroup
	run     discoverFunc
	lookup  resolve.LookupFunc
	allowed func(netip.Addr) bool
	client  *http.Client
}

func newDiscovery(e *env, targets []*target.Target, lookup resolve.LookupFunc, allowed func(netip.Addr) bool, args map[string][]string) *discovery {
	d := &discovery{env: e, run: discover.Run, lookup: lookup, allowed: allowed,
		client: &http.Client{Timeout: e.cfg.Discovery.Timeout}}
	byKey := map[string]*discoveryGroup{}
	for _, t := range targets {
		if t.Discovery == "" {
			continue
		}
		key := t.Service + "/" + t.Discovery
		g := byKey[key]
		if g == nil {
			g = &discoveryGroup{service: t.Service, category: t.Category, name: t.Discovery, args: args[t.ID]}
			byKey[key] = g
			d.groups = append(d.groups, g)
		}
		g.slots = append(g.slots, t)
	}
	return d
}

func (d *discovery) jobs() []scheduler.Job {
	var out []scheduler.Job
	for _, g := range d.groups {
		out = append(out, scheduler.Job{
			Name:     "discover/" + g.service + "/" + g.name,
			Interval: d.cfg.Discovery.Interval,
			// Run at start: the slots measure nothing until discovered.
			NoJitter: true,
			Run:      func(ctx context.Context) { d.discover(ctx, g) },
		})
	}
	return out
}

func (d *discovery) discover(parent context.Context, g *discoveryGroup) {
	c := d.cfg.Discovery
	ctx, cancel := context.WithTimeout(parent, c.Timeout)
	defer cancel()
	start := time.Now()
	eps, err := d.run(ctx, g.name, discover.Env{
		HTTP: d.client, Lookup: d.lookup, Lat: c.Lat, Lon: c.Lon,
		GameLiftRegions: c.GameLiftRegions, STUN: g.args,
	})
	if parent.Err() != nil {
		return
	}
	ev := sample.Sample{
		TS: start.UnixMilli(), Kind: sample.KindEvent, Category: g.category, Service: g.service,
		Status: sample.StatusOK,
	}
	x := map[string]any{"event": "discovery", "discoverer": g.name, "took_ms": sample.Millis(time.Since(start))}
	ev.Extra = x
	if err != nil {
		ev.Status = sample.StatusError
		x["error"] = err.Error()
		d.log.Warn("discovery failed", "service", g.service, "discoverer", g.name, "err", err)
		d.rec.Emit(ev)
		return
	}
	eps = slices.DeleteFunc(eps, func(e discover.Endpoint) bool { return !d.allowed(e.Addr) })
	assigned, changed := assign(g.slots, eps)
	var list []map[string]any
	for i, t := range g.slots {
		if e := assigned[i]; e != nil {
			m := map[string]any{"target_id": t.ID, "label": e.Label, "addr": e.Addr.String()}
			for k, v := range e.Meta {
				m[k] = v
			}
			list = append(list, m)
		}
	}
	x["endpoints"] = list
	x["found"] = len(eps)
	x["changed"] = changed
	if changed {
		labels := make([]string, 0, len(list))
		for _, m := range list {
			labels = append(labels, m["label"].(string)+"="+m["addr"].(string))
		}
		d.log.Info("discovered", "service", g.service, "discoverer", g.name, "endpoints", strings.Join(labels, " "))
	}
	d.rec.Emit(ev)
}

// assign fills the slots with endpoints. A slot keeps its endpoint while
// the discoverer still returns it, so its series stays continuous; free
// slots take the remaining endpoints in the discoverer's order, and slots
// left over are cleared.
func assign(slots []*target.Target, eps []discover.Endpoint) ([]*discover.Endpoint, bool) {
	out := make([]*discover.Endpoint, len(slots))
	used := make([]bool, len(eps))
	key := func(label string, a netip.Addr) string { return label + "|" + a.String() }
	for i, t := range slots {
		cur, ok := t.Endpoint()
		if !ok {
			continue
		}
		for j := range eps {
			if !used[j] && key(eps[j].Label, eps[j].Addr) == key(cur.Label, t.Addr()) {
				out[i], used[j] = &eps[j], true
				break
			}
		}
	}
	next := 0
	for i := range slots {
		if out[i] != nil {
			continue
		}
		for next < len(eps) && used[next] {
			next++
		}
		if next < len(eps) {
			out[i], used[next] = &eps[next], true
		}
	}
	changed := false
	for i, t := range slots {
		cur, had := t.Endpoint()
		if e := out[i]; e != nil {
			if !had || cur.Label != e.Label || cur.Port != e.Port || t.Addr() != e.Addr {
				changed = true
			}
			t.SetEndpoint(target.Endpoint{Label: e.Label, Port: e.Port})
			t.SetDst(e.Addr)
		} else if had || t.Addr().IsValid() {
			changed = true
			t.ClearEndpoint()
			t.SetDst(netip.Addr{})
		}
	}
	return out, changed
}
