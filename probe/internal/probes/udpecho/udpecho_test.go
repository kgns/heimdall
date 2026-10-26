package udpecho

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func serve(t *testing.T, h func(req []byte, from *net.UDPAddr) []byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			if resp := h(append([]byte(nil), b[:n]...), from.(*net.UDPAddr)); resp != nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestEcho(t *testing.T) {
	dst := serve(t, func(req []byte, _ *net.UDPAddr) []byte { return req })
	r := Echo(context.Background(), dst, time.Second)
	if r.Status != sample.StatusOK || r.RTT <= 0 {
		t.Fatalf("%+v", r)
	}
	silent := serve(t, func([]byte, *net.UDPAddr) []byte { return nil })
	if r := Echo(context.Background(), silent, 50*time.Millisecond); r.Status != sample.StatusTimeout {
		t.Fatalf("%+v", r)
	}
	wrong := serve(t, func([]byte, *net.UDPAddr) []byte { return []byte("something else") })
	if r := Echo(context.Background(), wrong, 50*time.Millisecond); r.Status != sample.StatusTimeout {
		t.Fatalf("mismatched echo accepted: %+v", r)
	}
}

// stunServer answers Binding requests with XOR-MAPPED-ADDRESS, as RFC 8489
// servers do, preceded by an unknown attribute that must be skipped.
func stunServer(t *testing.T) netip.AddrPort {
	return serve(t, func(req []byte, from *net.UDPAddr) []byte {
		if len(req) < 20 || binary.BigEndian.Uint16(req) != 1 {
			return nil
		}
		resp := make([]byte, 20, 64)
		binary.BigEndian.PutUint16(resp[0:2], 0x0101)
		copy(resp[4:20], req[4:20])
		resp = append(resp, 0x80, 0x22, 0, 3, 'a', 'b', 'c', 0) // SOFTWARE, padded
		attr := make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:2], 0x0020)
		binary.BigEndian.PutUint16(attr[2:4], 8)
		attr[5] = 1
		binary.BigEndian.PutUint16(attr[6:8], uint16(from.Port)^0x2112)
		ip := from.IP.To4()
		for i := range 4 {
			attr[8+i] = ip[i] ^ []byte{0x21, 0x12, 0xA4, 0x42}[i]
		}
		resp = append(resp, attr...)
		binary.BigEndian.PutUint16(resp[2:4], uint16(len(resp)-20))
		return resp
	})
}

func TestSTUN(t *testing.T) {
	dst := stunServer(t)
	r := STUN(context.Background(), dst, time.Second)
	if r.Status != sample.StatusOK || r.Mapped.Addr().String() != "127.0.0.1" || r.Mapped.Port() == 0 {
		t.Fatalf("%+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := STUN(ctx, dst, time.Second); r.Status != "" {
		t.Fatalf("cancelled request returned %+v", r)
	}
}
