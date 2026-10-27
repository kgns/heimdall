package flows

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Collector reads the capture, tracks handshakes and hands finished flows
// to OnFlow.
type Collector struct {
	cap       Capture
	routerMAC net.HardwareAddr
	tracker   *Tracker
	onFlow    func(Flow)
	now       func() time.Time

	mu       sync.Mutex
	stats    Stats
	trackerS TrackerStats
}

// Stats counts the collector's work.
type Stats struct {
	Frames      uint64       `json:"frames"`
	ParseErrors uint64       `json:"parse_errors"`
	KernelDrops uint64       `json:"kernel_drops"`
	Tracker     TrackerStats `json:"tracker"`
}

// NewCollector returns a collector over cap. routerMAC is the bridge's own
// address.
func NewCollector(cap Capture, routerMAC net.HardwareAddr, opt TrackerOptions, onFlow func(Flow)) *Collector {
	return &Collector{cap: cap, routerMAC: routerMAC, tracker: NewTracker(opt), onFlow: onFlow, now: time.Now}
}

// Stats returns a snapshot of the counters.
func (c *Collector) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Tracker = c.trackerS
	return s
}

// Run reads until ctx is done or the capture fails, then closes it.
func (c *Collector) Run(ctx context.Context) error {
	defer c.cap.Close()
	const tick = 250 * time.Millisecond
	next := c.now().Add(tick)
	var frames, parseErrs uint64
	for ctx.Err() == nil {
		frame, ts, err := c.cap.Read()
		switch {
		case err == nil:
			frames++
			p, perr := Parse(frame)
			if perr != nil {
				parseErrs++
				break
			}
			c.tracker.Observe(p, ts, bytes.Equal(p.SrcMAC, c.routerMAC))
		case errors.Is(err, ErrTimeout):
		default:
			return err
		}
		if now := c.now(); !now.Before(next) {
			next = now.Add(tick)
			for _, f := range c.tracker.Ready(now) {
				c.onFlow(f)
			}
			drops := c.cap.Drops()
			c.mu.Lock()
			c.stats.Frames += frames
			c.stats.ParseErrors += parseErrs
			c.stats.KernelDrops += drops
			c.trackerS = c.tracker.Stats()
			c.mu.Unlock()
			frames, parseErrs = 0, 0
		}
	}
	return nil
}
