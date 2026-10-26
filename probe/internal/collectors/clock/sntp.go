// Package clock measures how far the local wall clock is from an NTP
// server with a single SNTP exchange. It never changes the clock.
package clock

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ntpEpochOffset is the number of seconds between 1900-01-01 and 1970-01-01.
const ntpEpochOffset = 2208988800

// Result is one exchange. Offset is server time minus local time: a
// positive value means the local clock is behind.
type Result struct {
	Sent    time.Time
	Offset  time.Duration
	Delay   time.Duration
	Stratum int
	RefID   string
}

func toNTP(t time.Time) uint64 {
	secs := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) << 32 / 1e9
	return secs<<32 | frac
}

func fromNTP(v uint64) time.Time {
	secs := int64(v>>32) - ntpEpochOffset
	nanos := (int64(v&0xffffffff) * 1e9) >> 32
	return time.Unix(secs, nanos)
}

// Compute derives offset and delay from the four NTP timestamps: t1 client
// send, t2 server receive, t3 server send, t4 client receive. The delay is
// taken from the monotonic clock (rtt) so that a clock step during the
// exchange cannot distort it.
func Compute(t1, t2, t3, t4 time.Time, rtt time.Duration) (offset, delay time.Duration) {
	offset = (t2.Sub(t1) + t3.Sub(t4)) / 2
	delay = rtt - t3.Sub(t2)
	if delay < 0 {
		delay = 0
	}
	return offset, delay
}

// Query performs one SNTP exchange with server.
func Query(ctx context.Context, server netip.AddrPort, timeout time.Duration) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", server.String())
	if err != nil {
		return Result{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}

	req := make([]byte, 48)
	req[0] = 0x23 // LI 0, version 4, mode 3 (client)
	// A random transmit timestamp lets the reply be matched without
	// revealing the local clock; t1 is kept locally.
	var nonce [8]byte
	rand.Read(nonce[:])
	copy(req[40:48], nonce[:])

	t1 := time.Now()
	if _, err := c.Write(req); err != nil {
		return Result{}, err
	}
	resp := make([]byte, 128)
	for {
		n, err := c.Read(resp)
		t4 := time.Now()
		if err != nil {
			return Result{}, err
		}
		if n < 48 || resp[0]&0x7 != 4 || [8]byte(resp[24:32]) != nonce {
			continue
		}
		stratum := int(resp[1])
		if stratum == 0 {
			return Result{}, fmt.Errorf("kiss-o'-death %q", string(resp[12:16]))
		}
		if resp[0]>>6 == 3 {
			return Result{}, errors.New("server clock not synchronized")
		}
		t2 := fromNTP(binary.BigEndian.Uint64(resp[32:40]))
		t3 := fromNTP(binary.BigEndian.Uint64(resp[40:48]))
		off, delay := Compute(t1, t2, t3, t4, t4.Sub(t1))
		ref := ""
		if stratum == 1 {
			ref = string(trimZero(resp[12:16]))
		} else {
			ref = netip.AddrFrom4([4]byte(resp[12:16])).String()
		}
		return Result{Sent: t1, Offset: off, Delay: delay, Stratum: stratum, RefID: ref}, nil
	}
}

func trimZero(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
