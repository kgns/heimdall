// Package scheduler runs periodic jobs with jittered phases and a global
// probe budget.
package scheduler

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token bucket shared by all budgeted jobs. It caps the number
// of probes the device sends per second regardless of how many targets are
// configured.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// NewLimiter returns a limiter allowing rate events per second with the
// given burst. The bucket starts full.
func NewLimiter(rate float64, burst int, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{rate: rate, burst: float64(burst), tokens: float64(burst), last: now(), now: now}
}

// Reserve takes one token and returns how long the caller must wait before
// acting on it.
func (l *Limiter) Reserve() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if el := now.Sub(l.last); el > 0 {
		l.tokens += el.Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
	l.last = now
	l.tokens--
	if l.tokens >= 0 {
		return 0
	}
	return time.Duration(-l.tokens / l.rate * float64(time.Second))
}

// Wait blocks until a token is available or ctx is done.
func (l *Limiter) Wait(ctx context.Context) error {
	d := l.Reserve()
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
