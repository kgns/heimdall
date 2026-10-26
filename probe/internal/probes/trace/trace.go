// Package trace runs ICMP traceroutes with the probe's shared pinger: echo
// requests with increasing IP TTL, where each router on the path answers
// with time exceeded and the destination with an echo reply.
package trace

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// Pinger is the part of icmp.Pinger a trace needs.
type Pinger interface {
	Ping(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) icmp.Result
}

// Options bound one trace.
type Options struct {
	MaxHops int
	// Probes per hop; the hop's RTT is the lowest answer.
	Probes  int
	Timeout time.Duration
	// Gap between sending successive TTLs, so that routers that rate-limit
	// time exceeded messages see a spread-out load.
	Gap time.Duration
}

// Hop is one TTL of a trace.
type Hop struct {
	TTL int `json:"ttl"`
	// IP is the router (or the destination) that answered; empty when
	// nothing answered.
	IP string `json:"ip,omitempty"`
	// RTTms is the lowest answer, nil without an answer.
	RTTms   *float64 `json:"rtt_ms"`
	Answers int      `json:"answers"`
	// Other lists further addresses that answered at this TTL, which
	// happens with per-packet load balancing.
	Other []string `json:"other,omitempty"`
}

// Result is a whole trace.
type Result struct {
	Sent time.Time
	Hops []Hop
	// Reached is true when the destination answered; Hops then ends with
	// it.
	Reached bool
	RTT     time.Duration
}

type answer struct {
	ttl  int
	from netip.Addr
	rtt  time.Duration
	dest bool
}

// Run traces the path to dst. All TTLs are probed concurrently, spaced by
// Gap, and the hops beyond the first that the destination answered are
// dropped.
func Run(ctx context.Context, p Pinger, dst netip.Addr, o Options) Result {
	res := Result{Sent: time.Now()}
	var (
		mu  sync.Mutex
		ans []answer
		wg  sync.WaitGroup
	)
	t := time.NewTicker(max(o.Gap, time.Millisecond))
	defer t.Stop()
send:
	for ttl := 1; ttl <= o.MaxHops; ttl++ {
		for range o.Probes {
			wg.Add(1)
			go func(ttl int) {
				defer wg.Done()
				r := p.Ping(ctx, dst, ttl, o.Timeout)
				var a answer
				switch r.Status {
				case sample.StatusTimeExceeded:
					a = answer{ttl: ttl, from: r.From, rtt: r.RTT}
				case sample.StatusOK:
					a = answer{ttl: ttl, from: dst, rtt: r.RTT, dest: true}
				case sample.StatusUnreachable:
					// An unreachable from a router ends the path there.
					a = answer{ttl: ttl, from: r.From, rtt: r.RTT}
				default:
					return
				}
				mu.Lock()
				ans = append(ans, a)
				mu.Unlock()
			}(ttl)
		}
		select {
		case <-ctx.Done():
			break send
		case <-t.C:
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return Result{}
	}

	last := o.MaxHops
	for _, a := range ans {
		if a.dest && a.ttl < last {
			last = a.ttl
		}
	}
	hops := make([]Hop, last)
	for i := range hops {
		hops[i].TTL = i + 1
	}
	for _, a := range ans {
		if a.ttl > last {
			continue
		}
		h := &hops[a.ttl-1]
		ip := a.from.String()
		h.Answers++
		switch {
		case h.IP == "":
			h.IP = ip
			h.RTTms = sample.RTT(a.rtt)
		case h.IP == ip:
			if ms := sample.Millis(a.rtt); ms < *h.RTTms {
				h.RTTms = sample.RTT(a.rtt)
			}
		default:
			if !contains(h.Other, ip) {
				h.Other = append(h.Other, ip)
			}
		}
		if a.dest && a.ttl == last {
			res.Reached = true
			if res.RTT == 0 || a.rtt < res.RTT {
				res.RTT = a.rtt
			}
		}
	}
	if !res.Reached {
		// Trim the run of silent hops at the end.
		for len(hops) > 0 && hops[len(hops)-1].IP == "" {
			hops = hops[:len(hops)-1]
		}
	}
	res.Hops = hops
	return res
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
