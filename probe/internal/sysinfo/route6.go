package sysinfo

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"strconv"
	"strings"
)

// Route6 is one entry of /proc/net/ipv6_route.
type Route6 struct {
	Iface   string
	Dest    netip.Prefix
	NextHop netip.Addr
	Flags   uint32
	Metric  uint32
}

// Usable reports whether the route is up and not a reject route.
func (r Route6) Usable() bool {
	return r.Flags&RTFUp != 0 && r.Flags&RTFReject == 0
}

// ReadRoutes6 parses proc/net/ipv6_route from fsys. A missing file means the
// kernel has IPv6 disabled and yields no routes.
func ReadRoutes6(fsys fs.FS) ([]Route6, error) {
	f, err := fsys.Open("proc/net/ipv6_route")
	if err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return ParseRoutes6(f)
}

// ParseRoutes6 parses the /proc/net/ipv6_route format.
func ParseRoutes6(r io.Reader) ([]Route6, error) {
	sc := bufio.NewScanner(r)
	var routes []Route6
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 10 {
			return nil, fmt.Errorf("ipv6 route line %q: want 10 fields, got %d", sc.Text(), len(f))
		}
		dest, err := parseHexIPv6(f[0])
		if err != nil {
			return nil, fmt.Errorf("ipv6 route destination: %w", err)
		}
		plen, err := strconv.ParseUint(f[1], 16, 8)
		if err != nil || plen > 128 {
			return nil, fmt.Errorf("ipv6 route prefix length %q", f[1])
		}
		nh, err := parseHexIPv6(f[4])
		if err != nil {
			return nil, fmt.Errorf("ipv6 route next hop: %w", err)
		}
		metric, err := strconv.ParseUint(f[5], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("ipv6 route metric: %w", err)
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil {
			return nil, fmt.Errorf("ipv6 route flags: %w", err)
		}
		routes = append(routes, Route6{
			Iface:   f[9],
			Dest:    netip.PrefixFrom(dest, int(plen)),
			NextHop: nh,
			Flags:   uint32(flags),
			Metric:  uint32(metric),
		})
	}
	return routes, sc.Err()
}

func parseHexIPv6(s string) (netip.Addr, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return netip.Addr{}, fmt.Errorf("%q is not a 32-digit hex address", s)
	}
	return netip.AddrFrom16([16]byte(b)), nil
}

// DefaultRoutes6 returns usable ::/0 routes, ignoring the loopback
// unreachable entry the kernel installs when no real default exists.
func DefaultRoutes6(routes []Route6) []Route6 {
	var out []Route6
	for _, r := range routes {
		if r.Dest.Bits() != 0 || !r.Usable() || r.Iface == "lo" {
			continue
		}
		out = append(out, r)
	}
	return out
}
