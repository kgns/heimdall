package clock

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestNTPConversion(t *testing.T) {
	ts := time.Date(2026, 10, 26, 12, 0, 0, 500_000_000, time.UTC)
	back := fromNTP(toNTP(ts))
	if d := back.Sub(ts); d < -time.Microsecond || d > time.Microsecond {
		t.Fatalf("round trip off by %v", d)
	}
}

func TestCompute(t *testing.T) {
	base := time.Unix(1_800_000_000, 0)
	// Local clock 250 ms behind; 20 ms each way; server holds 1 ms.
	t1 := base
	t2 := base.Add(250*time.Millisecond + 20*time.Millisecond)
	t3 := t2.Add(time.Millisecond)
	t4 := base.Add(41 * time.Millisecond)
	off, delay := Compute(t1, t2, t3, t4, 41*time.Millisecond)
	if off != 250*time.Millisecond || delay != 40*time.Millisecond {
		t.Fatalf("offset %v delay %v", off, delay)
	}
}

// fakeServer answers like an NTP server whose clock is skew ahead of ours.
func fakeServer(t *testing.T, skew time.Duration, stratum byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 128)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			now := time.Now().Add(skew)
			resp := make([]byte, 48)
			resp[0] = 0x24 // version 4, mode 4
			resp[1] = stratum
			copy(resp[12:16], "GPS\x00")
			copy(resp[24:32], buf[40:48])
			binary.BigEndian.PutUint64(resp[32:40], toNTP(now))
			binary.BigEndian.PutUint64(resp[40:48], toNTP(now))
			// A reply that does not echo our nonce must be ignored.
			bogus := append([]byte(nil), resp...)
			bogus[24] ^= 0xff
			pc.WriteTo(bogus, addr)
			pc.WriteTo(resp, addr)
		}
	}()
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}

func TestQuery(t *testing.T) {
	srv := fakeServer(t, 3*time.Second, 1)
	r, err := Query(context.Background(), srv, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if d := r.Offset - 3*time.Second; d < -50*time.Millisecond || d > 50*time.Millisecond {
		t.Fatalf("offset %v", r.Offset)
	}
	if r.Stratum != 1 || r.RefID != "GPS" || r.Delay < 0 || r.Delay > 100*time.Millisecond {
		t.Fatalf("%+v", r)
	}
}

func TestQueryKissOfDeath(t *testing.T) {
	srv := fakeServer(t, 0, 0)
	if _, err := Query(context.Background(), srv, time.Second); err == nil {
		t.Fatal("stratum 0 accepted")
	}
}

func TestQueryTimeout(t *testing.T) {
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer pc.Close()
	start := time.Now()
	_, err := Query(context.Background(), netip.MustParseAddrPort(pc.LocalAddr().String()), 100*time.Millisecond)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}
