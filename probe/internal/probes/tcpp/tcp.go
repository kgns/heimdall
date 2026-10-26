// Package tcpp measures TCP connection setup time, which is one network
// round trip (SYN to SYN-ACK) plus local processing.
package tcpp

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// DialFunc opens a connection. Tests replace it.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Result is one connection attempt.
type Result struct {
	Status sample.Status
	Reason string
	Sent   time.Time
	RTT    time.Duration
	Err    error
}

// Connect opens and immediately aborts a TCP connection to dst. A refused
// connection still yields an RTT, since the reset answers the SYN.
func Connect(ctx context.Context, dial DialFunc, dst netip.AddrPort, timeout time.Duration) Result {
	if dial == nil {
		var d net.Dialer
		dial = d.DialContext
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	c, err := dial(ctx, "tcp4", dst.String())
	rtt := time.Since(start)
	if err != nil {
		st, reason := neterr.Classify(err)
		r := Result{Status: st, Reason: reason, Sent: start, Err: err}
		if st == sample.StatusRefused {
			r.RTT = rtt
		}
		return r
	}
	// An abortive close sends RST instead of FIN, so neither side keeps
	// TIME_WAIT or conntrack state for a connection that carried no data.
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
	return Result{Status: sample.StatusOK, Sent: start, RTT: rtt}
}
