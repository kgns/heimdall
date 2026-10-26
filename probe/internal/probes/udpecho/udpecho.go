// Package udpecho measures round trips to UDP echo services, which send
// every datagram back unchanged (for example the AWS GameLift ping beacons
// on port 7770), and to STUN servers (RFC 8489 Binding requests), which
// also report the public address the request came from.
package udpecho

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// Result is one request.
type Result struct {
	Status sample.Status
	Reason string
	Sent   time.Time
	RTT    time.Duration
	// Mapped is the source address the STUN server saw, after any NAT.
	Mapped netip.AddrPort
}

// exchange sends req from a fresh socket and waits for a datagram accepted
// by match. A fresh socket per request keeps a late answer to an earlier
// request from being counted.
func exchange(ctx context.Context, dst netip.AddrPort, req []byte, timeout time.Duration, match func([]byte) bool) (Result, []byte) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	sent := time.Now()
	r := Result{Sent: sent}
	c, err := d.DialContext(ctx, "udp4", dst.String())
	if err != nil {
		r.Status, r.Reason = neterr.Classify(err)
		return r, nil
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	sent = time.Now()
	r.Sent = sent
	if _, err := c.Write(req); err != nil {
		r.Status, r.Reason = neterr.Classify(err)
		return r, nil
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return Result{}, nil
			}
			r.Status, r.Reason = neterr.Classify(err)
			return r, nil
		}
		if match(buf[:n]) {
			r.RTT = time.Since(sent)
			r.Status = sample.StatusOK
			return r, buf[:n]
		}
	}
}

// Echo sends a datagram with a random token and waits for it to come back.
func Echo(ctx context.Context, dst netip.AddrPort, timeout time.Duration) Result {
	req := make([]byte, 16)
	copy(req, "heimdall")
	_, _ = rand.Read(req[8:])
	r, _ := exchange(ctx, dst, req, timeout, func(b []byte) bool { return bytes.Equal(b, req) })
	if ctx.Err() != nil {
		return Result{}
	}
	return r
}

const (
	stunMagic           = 0x2112A442
	stunBindingRequest  = 0x0001
	stunBindingSuccess  = 0x0101
	stunXorMappedAddr   = 0x0020
	stunMappedAddr      = 0x0001
	stunHeaderLen       = 20
	stunFamilyIPv4      = 0x01
	stunMappedIPv4Bytes = 8
)

// STUN sends a Binding request and waits for the success response with the
// same transaction ID.
func STUN(ctx context.Context, dst netip.AddrPort, timeout time.Duration) Result {
	req := make([]byte, stunHeaderLen)
	binary.BigEndian.PutUint16(req[0:2], stunBindingRequest)
	binary.BigEndian.PutUint32(req[4:8], stunMagic)
	_, _ = rand.Read(req[8:20])
	tid := req[8:20]
	r, resp := exchange(ctx, dst, req, timeout, func(b []byte) bool {
		return len(b) >= stunHeaderLen && binary.BigEndian.Uint16(b[0:2]) == stunBindingSuccess &&
			binary.BigEndian.Uint32(b[4:8]) == stunMagic && bytes.Equal(b[8:20], tid)
	})
	if ctx.Err() != nil {
		return Result{}
	}
	if resp != nil {
		r.Mapped = mappedAddress(resp)
	}
	return r
}

// mappedAddress returns the IPv4 XOR-MAPPED-ADDRESS, or MAPPED-ADDRESS
// from servers that only send the older attribute.
func mappedAddress(b []byte) netip.AddrPort {
	n := int(binary.BigEndian.Uint16(b[2:4]))
	attrs := b[stunHeaderLen:]
	if n < len(attrs) {
		attrs = attrs[:n]
	}
	var plain netip.AddrPort
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		if l >= stunMappedIPv4Bytes && v[1] == stunFamilyIPv4 {
			port := binary.BigEndian.Uint16(v[2:4])
			ip := [4]byte(v[4:8])
			switch typ {
			case stunXorMappedAddr:
				port ^= uint16(stunMagic >> 16)
				var m [4]byte
				binary.BigEndian.PutUint32(m[:], stunMagic)
				for i := range ip {
					ip[i] ^= m[i]
				}
				return netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			case stunMappedAddr:
				plain = netip.AddrPortFrom(netip.AddrFrom4(ip), port)
			}
		}
		// Attributes are padded to four bytes.
		adv := 4 + (l+3)&^3
		if adv > len(attrs) {
			break
		}
		attrs = attrs[adv:]
	}
	return plain
}
