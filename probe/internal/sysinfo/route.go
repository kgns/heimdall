// Package sysinfo reads facts about the host network, DNS and memory setup
// from /proc and configuration files. Every reader takes an fs.FS rooted at
// "/" so that tests can substitute fixture trees.
package sysinfo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

// Route flags from <linux/route.h>.
const (
	RTFUp      = 0x0001
	RTFGateway = 0x0002
	RTFHost    = 0x0004
	RTFReject  = 0x0200
)

// Route is one IPv4 entry of /proc/net/route.
type Route struct {
	Iface   string
	Dest    netip.Prefix
	Gateway netip.Addr // zero value when the route has no gateway
	Flags   uint32
	Metric  int
	MTU     int
}

// Usable reports whether the route is up and not a reject route.
func (r Route) Usable() bool {
	return r.Flags&RTFUp != 0 && r.Flags&RTFReject == 0
}

// HasGateway reports whether the route forwards through a next hop.
func (r Route) HasGateway() bool {
	return r.Flags&RTFGateway != 0 && r.Gateway.IsValid()
}

// ReadRoutes parses proc/net/route from fsys.
func ReadRoutes(fsys fs.FS) ([]Route, error) {
	f, err := fsys.Open("proc/net/route")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseRoutes(f)
}

// ParseRoutes parses the /proc/net/route format. Addresses in that file are
// the raw in-kernel network-order words printed in host byte order.
func ParseRoutes(r io.Reader) ([]Route, error) {
	sc := bufio.NewScanner(r)
	var routes []Route
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Iface") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 8 {
			return nil, fmt.Errorf("route line %q: want at least 8 fields, got %d", line, len(f))
		}
		dest, err := parseHexIPv4(f[1])
		if err != nil {
			return nil, fmt.Errorf("route line %q: destination: %w", line, err)
		}
		gw, err := parseHexIPv4(f[2])
		if err != nil {
			return nil, fmt.Errorf("route line %q: gateway: %w", line, err)
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("route line %q: flags: %w", line, err)
		}
		metric, err := strconv.Atoi(f[6])
		if err != nil {
			return nil, fmt.Errorf("route line %q: metric: %w", line, err)
		}
		mask, err := parseHexIPv4(f[7])
		if err != nil {
			return nil, fmt.Errorf("route line %q: mask: %w", line, err)
		}
		ones, err := maskOnes(mask)
		if err != nil {
			return nil, fmt.Errorf("route line %q: %w", line, err)
		}
		rt := Route{
			Iface:  f[0],
			Dest:   netip.PrefixFrom(dest, ones).Masked(),
			Flags:  uint32(flags),
			Metric: metric,
		}
		if rt.Flags&RTFGateway != 0 && !gw.IsUnspecified() {
			rt.Gateway = gw
		}
		if len(f) > 8 {
			if mtu, err := strconv.Atoi(f[8]); err == nil {
				rt.MTU = mtu
			}
		}
		routes = append(routes, rt)
	}
	return routes, sc.Err()
}

func parseHexIPv4(s string) (netip.Addr, error) {
	if len(s) != 8 {
		return netip.Addr{}, fmt.Errorf("%q is not an 8-digit hex address", s)
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, err
	}
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], uint32(v))
	return netip.AddrFrom4(b), nil
}

func maskOnes(mask netip.Addr) (int, error) {
	b := mask.As4()
	m := binary.BigEndian.Uint32(b[:])
	ones := bits.LeadingZeros32(^m)
	if m != ^uint32(0)<<(32-ones) {
		return 0, fmt.Errorf("non-contiguous netmask %s", mask)
	}
	return ones, nil
}

// DefaultRoute returns the usable 0.0.0.0/0 route with the lowest metric.
func DefaultRoute(routes []Route) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if r.Dest.Bits() != 0 || !r.Usable() {
			continue
		}
		if !found || r.Metric < best.Metric {
			best, found = r, true
		}
	}
	return best, found
}

// Lookup returns the route the kernel would pick for ip using longest-prefix
// match, preferring the lowest metric between equally specific routes.
func Lookup(routes []Route, ip netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if !r.Usable() || !r.Dest.Contains(ip) {
			continue
		}
		if !found || r.Dest.Bits() > best.Dest.Bits() ||
			(r.Dest.Bits() == best.Dest.Bits() && r.Metric < best.Metric) {
			best, found = r, true
		}
	}
	return best, found
}

// SideGatewayRoutes returns gateway routes that leave through an interface
// other than the default route's. On CPEs these usually point at operator
// management networks, which the probe must never send traffic to.
func SideGatewayRoutes(routes []Route, def Route) []Route {
	var out []Route
	for _, r := range routes {
		if !r.Usable() || r.Dest.Bits() == 0 || !r.HasGateway() || r.Iface == def.Iface {
			continue
		}
		out = append(out, r)
	}
	return out
}
