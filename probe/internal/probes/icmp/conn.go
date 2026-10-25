// Package icmp sends ICMP echo requests over one shared socket and matches
// replies to requests by identifier, sequence number, source address and a
// per-process payload token.
package icmp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Mode is the ICMP socket kind.
type Mode string

const (
	// ModeAuto picks raw when permitted and dgram otherwise.
	ModeAuto Mode = "auto"
	// ModeRaw uses a SOCK_RAW socket. It needs CAP_NET_RAW, sees every ICMP
	// packet delivered to the host and receives ICMP errors (unreachable,
	// time exceeded) for our requests.
	ModeRaw Mode = "raw"
	// ModeDgram uses an unprivileged SOCK_DGRAM ICMP socket, allowed by
	// net.ipv4.ping_group_range. The kernel sets the echo identifier and
	// delivers only our replies; ICMP errors are not delivered.
	ModeDgram Mode = "dgram"
)

// Conn is the socket the pinger uses. ReadFrom returns the ICMP message
// without the IP header, the sender, and the received IP TTL (-1 if
// unknown).
type Conn interface {
	Mode() Mode
	WriteTo(b []byte, dst netip.Addr) error
	ReadFrom(b []byte) (n int, src netip.Addr, ttl int, err error)
	Close() error
}

// ErrClosed is returned by Conn.ReadFrom after Close.
var ErrClosed = net.ErrClosed

type sockConn struct {
	mode Mode
	pc   *xicmp.PacketConn
	p4   *ipv4.PacketConn
}

// Listen opens an IPv4 ICMP socket. With ModeAuto it tries raw first.
func Listen(mode Mode) (Conn, error) {
	switch mode {
	case ModeRaw:
		return listen(ModeRaw, "ip4:icmp")
	case ModeDgram:
		return listen(ModeDgram, "udp4")
	case ModeAuto, "":
		c, rawErr := listen(ModeRaw, "ip4:icmp")
		if rawErr == nil {
			return c, nil
		}
		c, dgramErr := listen(ModeDgram, "udp4")
		if dgramErr == nil {
			return c, nil
		}
		return nil, errors.Join(rawErr, dgramErr)
	default:
		return nil, fmt.Errorf("unknown ICMP mode %q", mode)
	}
}

func listen(mode Mode, network string) (*sockConn, error) {
	pc, err := xicmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("%s socket: %w", mode, err)
	}
	c := &sockConn{mode: mode, pc: pc, p4: pc.IPv4PacketConn()}
	if c.p4 != nil {
		// TTL is informational; a kernel refusing IP_RECVTTL is not fatal.
		_ = c.p4.SetControlMessage(ipv4.FlagTTL, true)
	}
	return c, nil
}

func (c *sockConn) Mode() Mode { return c.mode }

func (c *sockConn) WriteTo(b []byte, dst netip.Addr) error {
	var addr net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if c.mode == ModeDgram {
		addr = &net.UDPAddr{IP: dst.AsSlice()}
	}
	_, err := c.pc.WriteTo(b, addr)
	return err
}

func (c *sockConn) ReadFrom(b []byte) (int, netip.Addr, int, error) {
	if c.p4 == nil {
		n, src, err := c.pc.ReadFrom(b)
		return n, addrOf(src), -1, err
	}
	n, cm, src, err := c.p4.ReadFrom(b)
	ttl := -1
	if cm != nil {
		ttl = cm.TTL
	}
	return n, addrOf(src), ttl, err
}

func (c *sockConn) Close() error { return c.pc.Close() }

func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case *net.IPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		return netip.Addr{}
	}
	out, _ := netip.AddrFromSlice(ip)
	return out.Unmap()
}
