package sysinfo

import (
	"fmt"
	"net"
	"net/netip"
)

// UnameInfo is the kernel identification returned by uname(2).
type UnameInfo struct {
	Sysname  string `json:"sysname"`
	Nodename string `json:"nodename"`
	Release  string `json:"release"`
	Version  string `json:"version"`
	Machine  string `json:"machine"`
}

// ICMPCapability records which ICMP socket kinds the process may open.
type ICMPCapability struct {
	Raw        bool   `json:"raw"`
	RawError   string `json:"raw_error,omitempty"`
	Dgram      bool   `json:"dgram"`
	DgramError string `json:"dgram_error,omitempty"`
}

// Mode returns the preferred ICMP socket mode, or "none".
func (c ICMPCapability) Mode() string {
	switch {
	case c.Raw:
		return "raw"
	case c.Dgram:
		return "dgram"
	default:
		return "none"
	}
}

// Interface describes a network interface and its addresses.
type Interface struct {
	Name         string       `json:"name"`
	MTU          int          `json:"mtu"`
	PointToPoint bool         `json:"point_to_point"`
	IPv4         []netip.Addr `json:"ipv4"`
	IPv6Global   []netip.Addr `json:"ipv6_global"`
}

// LookupInterface returns the addresses of the named interface.
func LookupInterface(name string) (Interface, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return Interface{}, err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return Interface{}, err
	}
	info := Interface{
		Name:         ifc.Name,
		MTU:          ifc.MTU,
		PointToPoint: ifc.Flags&net.FlagPointToPoint != 0,
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		switch {
		case ip.Is4():
			info.IPv4 = append(info.IPv4, ip)
		case IsGlobalIPv6(ip):
			info.IPv6Global = append(info.IPv6Global, ip)
		}
	}
	return info, nil
}

// IsGlobalIPv6 reports whether ip is a globally routable IPv6 unicast
// address, excluding link-local and unique local (fc00::/7) ranges.
func IsGlobalIPv6(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && ip.IsGlobalUnicast() && !ip.IsPrivate()
}

// EgressAddr returns the local address the kernel selects to reach dst. It
// connects a UDP socket, which sends no packets.
func EgressAddr(dst netip.AddrPort) (netip.Addr, error) {
	network := "udp4"
	if dst.Addr().Is6() {
		network = "udp6"
	}
	c, err := net.Dial(network, dst.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("unexpected local address type %T", c.LocalAddr())
	}
	return ua.AddrPort().Addr().Unmap(), nil
}
