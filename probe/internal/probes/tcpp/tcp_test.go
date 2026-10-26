package tcpp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func TestConnectOK(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	r := Connect(context.Background(), nil, netip.MustParseAddrPort(ln.Addr().String()), time.Second)
	if r.Status != sample.StatusOK || r.RTT <= 0 || r.RTT > time.Second {
		t.Fatalf("%+v", r)
	}
}

func TestConnectRefused(t *testing.T) {
	ln, _ := net.Listen("tcp4", "127.0.0.1:0")
	addr := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	r := Connect(context.Background(), nil, addr, time.Second)
	if r.Status != sample.StatusRefused || r.RTT <= 0 {
		t.Fatalf("%+v", r)
	}
}

func TestConnectTimeout(t *testing.T) {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, &net.OpError{Op: "dial", Err: ctx.Err()}
	}
	start := time.Now()
	r := Connect(context.Background(), dial, netip.MustParseAddrPort("192.0.2.1:443"), 50*time.Millisecond)
	if r.Status != sample.StatusTimeout || r.RTT != 0 || time.Since(start) > time.Second {
		t.Fatalf("%+v", r)
	}
}

func TestConnectOtherError(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("weird") }
	r := Connect(context.Background(), dial, netip.MustParseAddrPort("192.0.2.1:443"), time.Second)
	if r.Status != sample.StatusError || r.Reason != "error" || r.Err == nil {
		t.Fatalf("%+v", r)
	}
}
