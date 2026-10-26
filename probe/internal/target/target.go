// Package target holds measurement destinations whose address can change at
// runtime, for example when the gateway moves after a PPP reconnect.
package target

import (
	"net/netip"
	"sync/atomic"
	"time"
)

// Target is a destination shared between the probers and the watchers that
// update its address. All methods are safe for concurrent use.
type Target struct {
	ID       string
	Category string
	Service  string
	// Auto names the source of a dynamic address, or is empty for a fixed
	// address.
	Auto string
	// Host is the hostname the address is resolved from, if any.
	Host string
	// TTL, when non-zero, limits the probe's IP TTL so that the router at
	// that hop answers instead of the destination.
	TTL      int
	Interval time.Duration

	dst     atomic.Pointer[netip.Addr]
	blocked atomic.Bool
	hop     atomic.Pointer[netip.Addr]
}

// ObserveHop records the router that answered a TTL-limited probe and
// returns the previously seen one when it changed.
func (t *Target) ObserveHop(a netip.Addr) (prev netip.Addr, changed bool) {
	old := t.hop.Swap(&a)
	if old == nil || *old == a {
		return netip.Addr{}, false
	}
	return *old, true
}

// New returns a target with a fixed or not yet known address.
func New(id, category, service string, dst netip.Addr) *Target {
	t := &Target{ID: id, Category: category, Service: service}
	t.SetDst(dst)
	return t
}

// Dst returns the current address and whether it may be probed now.
func (t *Target) Dst() (netip.Addr, bool) {
	p := t.dst.Load()
	if p == nil || t.blocked.Load() {
		return netip.Addr{}, false
	}
	return *p, true
}

// Addr returns the current address regardless of blocking.
func (t *Target) Addr() netip.Addr {
	if p := t.dst.Load(); p != nil {
		return *p
	}
	return netip.Addr{}
}

// SetDst replaces the address and reports whether it changed. An invalid
// address clears it.
func (t *Target) SetDst(a netip.Addr) bool {
	if !a.IsValid() {
		return t.dst.Swap(nil) != nil
	}
	old := t.dst.Swap(&a)
	return old == nil || *old != a
}

// SetBlocked marks the target as not to be probed and reports whether the
// flag changed.
func (t *Target) SetBlocked(b bool) bool {
	return t.blocked.Swap(b) != b
}

// Blocked reports whether probing is suspended.
func (t *Target) Blocked() bool { return t.blocked.Load() }
