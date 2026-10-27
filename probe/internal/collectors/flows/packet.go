// Package flows measures the connections LAN clients open through the CPE.
// From the packets of each TCP handshake (and of each QUIC handshake) seen
// on the LAN bridge it splits the client's connection setup time into the
// part between the CPE and the client (LAN) and the part between the CPE
// and the server (WAN):
//
//	client          CPE (br0)          server
//	  SYN  ──────────► t0 ───────────────►
//	       ◄────────── t1 ◄─────────── SYN-ACK      wan = t1 - t0
//	  ACK  ──────────► t2                           lan = t2 - t1
//
// The server is named from the TLS ClientHello (SNI), from the DNS answers
// the CPE's resolver gave the client, or not at all.
package flows

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
)

const (
	etherIPv4 = 0x0800
	etherIPv6 = 0x86dd
	etherVLAN = 0x8100
	protoTCP  = 6
	protoUDP  = 17
)

// Packet is the part of a captured frame the tracker needs.
type Packet struct {
	SrcMAC, DstMAC net.HardwareAddr
	Src, Dst       netip.AddrPort
	Proto          uint8
	// TCP only.
	Flags    uint8
	Seq, Ack uint32
	// Payload is the transport payload as far as it was captured.
	Payload []byte
	// PayloadLen is the payload length from the IP header, which can be
	// larger than len(Payload) when the capture was truncated.
	PayloadLen int
}

var errShort = errors.New("truncated packet")

// Parse decodes an Ethernet frame carrying IPv4 or IPv6 with TCP or UDP.
// Fragments other than the first, and IPv6 packets with extension headers,
// are rejected.
func Parse(frame []byte) (Packet, error) {
	var p Packet
	if len(frame) < 14 {
		return p, errShort
	}
	p.DstMAC = net.HardwareAddr(frame[0:6])
	p.SrcMAC = net.HardwareAddr(frame[6:12])
	et := binary.BigEndian.Uint16(frame[12:14])
	b := frame[14:]
	if et == etherVLAN {
		if len(b) < 4 {
			return p, errShort
		}
		et = binary.BigEndian.Uint16(b[2:4])
		b = b[4:]
	}
	var l4 []byte
	var l4len int
	switch et {
	case etherIPv4:
		if len(b) < 20 || b[0]>>4 != 4 {
			return p, errShort
		}
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || len(b) < ihl || total < ihl {
			return p, errShort
		}
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return p, errors.New("non-first fragment")
		}
		p.Proto = b[9]
		src, _ := netip.AddrFromSlice(b[12:16])
		dst, _ := netip.AddrFromSlice(b[16:20])
		p.Src, p.Dst = netip.AddrPortFrom(src, 0), netip.AddrPortFrom(dst, 0)
		l4, l4len = b[ihl:], total-ihl
	case etherIPv6:
		if len(b) < 40 || b[0]>>4 != 6 {
			return p, errShort
		}
		p.Proto = b[6]
		src, _ := netip.AddrFromSlice(b[8:24])
		dst, _ := netip.AddrFromSlice(b[24:40])
		p.Src, p.Dst = netip.AddrPortFrom(src, 0), netip.AddrPortFrom(dst, 0)
		l4, l4len = b[40:], int(binary.BigEndian.Uint16(b[4:6]))
	default:
		return p, errors.New("not IP")
	}
	switch p.Proto {
	case protoTCP:
		if len(l4) < 20 {
			return p, errShort
		}
		off := int(l4[12]>>4) * 4
		if off < 20 || l4len < off {
			return p, errShort
		}
		p.Src = netip.AddrPortFrom(p.Src.Addr(), binary.BigEndian.Uint16(l4[0:2]))
		p.Dst = netip.AddrPortFrom(p.Dst.Addr(), binary.BigEndian.Uint16(l4[2:4]))
		p.Seq = binary.BigEndian.Uint32(l4[4:8])
		p.Ack = binary.BigEndian.Uint32(l4[8:12])
		p.Flags = l4[13]
		p.PayloadLen = l4len - off
		if len(l4) > off {
			p.Payload = l4[off:min(len(l4), l4len)]
		}
	case protoUDP:
		if len(l4) < 8 {
			return p, errShort
		}
		p.Src = netip.AddrPortFrom(p.Src.Addr(), binary.BigEndian.Uint16(l4[0:2]))
		p.Dst = netip.AddrPortFrom(p.Dst.Addr(), binary.BigEndian.Uint16(l4[2:4]))
		p.PayloadLen = l4len - 8
		if len(l4) > 8 {
			p.Payload = l4[8:min(len(l4), max(l4len, 8))]
		}
	default:
		return p, errors.New("not TCP or UDP")
	}
	return p, nil
}
