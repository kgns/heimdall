// Package netwatch tracks the default route and WAN address, keeps
// gateway-following targets pointed at the current next hop, and suspends
// targets whose traffic would leave through any interface other than the
// default route's.
package netwatch

import (
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"slices"
	"sync"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
	"github.com/kgns/heimdall/probe/internal/target"
)

// State is the WAN view at one point in time.
type State struct {
	Iface   string
	Gateway netip.Addr
	WANIPv4 []netip.Addr
}

func (s State) equal(o State) bool {
	return s.Iface == o.Iface && s.Gateway == o.Gateway && slices.Equal(s.WANIPv4, o.WANIPv4)
}

// Watcher refreshes State and the targets that depend on it.
type Watcher struct {
	fs      fs.FS
	iface   func(string) (sysinfo.Interface, error)
	targets []*target.Target
	emit    func(sample.Sample)
	log     *slog.Logger

	mu          sync.Mutex
	cur         State
	routes      []sysinfo.Route
	def         sysinfo.Route
	hasDef      bool
	initialized bool
}

// Allowed reports whether traffic to a would leave through the default
// route's interface, according to the last refresh.
func (w *Watcher) Allowed(a netip.Addr) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hasDef && egressAllowed(w.routes, w.def, a)
}

// New returns a watcher. emit receives change events.
func New(fsys fs.FS, iface func(string) (sysinfo.Interface, error), targets []*target.Target, emit func(sample.Sample), log *slog.Logger) *Watcher {
	return &Watcher{fs: fsys, iface: iface, targets: targets, emit: emit, log: log}
}

// Current returns the last observed state.
func (w *Watcher) Current() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

// Refresh re-reads the routing table and interface addresses. The first
// call establishes the baseline without emitting a change event.
func (w *Watcher) Refresh() (State, error) {
	routes, err := sysinfo.ReadRoutes(w.fs)
	if err != nil {
		return w.Current(), fmt.Errorf("read routes: %w", err)
	}
	def, hasDef := sysinfo.DefaultRoute(routes)
	var st State
	if hasDef {
		st.Iface, st.Gateway = def.Iface, def.Gateway
		if ifc, err := w.iface(def.Iface); err == nil {
			st.WANIPv4 = ifc.IPv4
		} else {
			w.log.Warn("wan interface lookup failed", "iface", def.Iface, "err", err)
		}
	}

	for _, t := range w.targets {
		if t.Auto == config.AutoGateway {
			if t.SetDst(st.Gateway) {
				w.log.Info("gateway target updated", "target", t.ID, "dst", st.Gateway)
			}
		}
		allowed := hasDef
		if a := t.Addr(); allowed && a.IsValid() {
			allowed = egressAllowed(routes, def, a)
		}
		if t.SetBlocked(!allowed) {
			w.log.Warn("target probing toggled", "target", t.ID, "dst", t.Addr(), "blocked", !allowed)
			w.emit(sample.Sample{
				Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
				Category: t.Category, Service: t.Service, DstIP: addrString(t.Addr()),
				Extra: map[string]any{"event": "target_blocked", "blocked": !allowed},
			})
		}
	}

	w.mu.Lock()
	prev, wasInit := w.cur, w.initialized
	w.cur, w.initialized = st, true
	w.routes, w.def, w.hasDef = routes, def, hasDef
	w.mu.Unlock()

	if wasInit && !st.equal(prev) {
		w.log.Info("wan changed", "iface", st.Iface, "gateway", st.Gateway, "wan_ipv4", st.WANIPv4,
			"prev_iface", prev.Iface, "prev_gateway", prev.Gateway, "prev_wan_ipv4", prev.WANIPv4)
		w.emit(sample.Sample{
			Kind: sample.KindEvent, Status: sample.StatusOK,
			Extra: map[string]any{
				"event":         "wan_change",
				"iface":         st.Iface,
				"gateway":       addrString(st.Gateway),
				"wan_ipv4":      addrStrings(st.WANIPv4),
				"prev_iface":    prev.Iface,
				"prev_gateway":  addrString(prev.Gateway),
				"prev_wan_ipv4": addrStrings(prev.WANIPv4),
			},
		})
	}
	return st, nil
}

// egressAllowed reports whether traffic to a leaves through the default
// route's interface.
func egressAllowed(routes []sysinfo.Route, def sysinfo.Route, a netip.Addr) bool {
	rt, ok := sysinfo.Lookup(routes, a)
	return ok && rt.Iface == def.Iface
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}
