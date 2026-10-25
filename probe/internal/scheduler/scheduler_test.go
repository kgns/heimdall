package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLimiterReserve(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(10, 2, func() time.Time { return now })

	if d := l.Reserve(); d != 0 {
		t.Fatalf("first token waited %v", d)
	}
	if d := l.Reserve(); d != 0 {
		t.Fatalf("burst token waited %v", d)
	}
	if d := l.Reserve(); d != 100*time.Millisecond {
		t.Fatalf("third token wait %v, want 100ms", d)
	}
	if d := l.Reserve(); d != 200*time.Millisecond {
		t.Fatalf("fourth token wait %v, want 200ms", d)
	}

	now = now.Add(10 * time.Second)
	if d := l.Reserve(); d != 0 {
		t.Fatalf("after refill waited %v", d)
	}
	if d := l.Reserve(); d != 0 {
		t.Fatalf("refill exceeded burst? waited %v", d)
	}
	if d := l.Reserve(); d == 0 {
		t.Fatal("bucket refilled beyond burst")
	}
}

func TestLimiterWaitCancelled(t *testing.T) {
	l := NewLimiter(0.001, 1, nil)
	l.Reserve()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("wait succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("wait ignored cancellation")
	}
}

func TestJobSpacing(t *testing.T) {
	s := New(nil, 1)
	var mu sync.Mutex
	var times []time.Time
	s.Add(Job{Name: "a", Interval: 20 * time.Millisecond, Run: func(context.Context) {
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 430*time.Millisecond)
	defer cancel()
	begin := time.Now()
	s.Run(ctx)

	if n := len(times); n < 18 || n > 23 {
		t.Fatalf("%d runs in 430ms at 20ms interval", n)
	}
	if first := times[0].Sub(begin); first > 25*time.Millisecond {
		t.Fatalf("first run after %v, beyond one interval of jitter", first)
	}
	for i := 1; i < len(times); i++ {
		gap := times[i].Sub(times[i-1])
		if gap < 5*time.Millisecond || gap > 60*time.Millisecond {
			t.Fatalf("gap %d = %v", i, gap)
		}
	}
}

func TestJitterSpreadsPhases(t *testing.T) {
	s := New(nil, 7)
	var mu sync.Mutex
	firsts := map[string]time.Time{}
	for _, name := range []string{"a", "b", "c", "d", "e", "f"} {
		s.Add(Job{Name: name, Interval: 200 * time.Millisecond, Run: func(context.Context) {
			mu.Lock()
			if _, ok := firsts[name]; !ok {
				firsts[name] = time.Now()
			}
			mu.Unlock()
		}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	var lo, hi time.Time
	for _, ts := range firsts {
		if lo.IsZero() || ts.Before(lo) {
			lo = ts
		}
		if ts.After(hi) {
			hi = ts
		}
	}
	if len(firsts) != 6 || hi.Sub(lo) < 20*time.Millisecond {
		t.Fatalf("phases not spread: %d jobs, spread %v", len(firsts), hi.Sub(lo))
	}
}

func TestBudgetCapsTotalRate(t *testing.T) {
	lim := NewLimiter(100, 1, nil)
	s := New(lim, 3)
	var runs atomic.Int64
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		s.Add(Job{Name: name, Interval: 10 * time.Millisecond, Budgeted: true, MaxInFlight: 100, Run: func(context.Context) {
			runs.Add(1)
		}})
	}
	s.Add(Job{Name: "free", Interval: 10 * time.Millisecond, Run: func(context.Context) {}})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	s.Run(ctx)

	// Unbudgeted these five jobs would run about 200 times.
	if n := runs.Load(); n < 25 || n > 50 {
		t.Fatalf("%d budgeted runs in 400ms at 100/s", n)
	}
	if st := s.Stats()["free"]; st.Runs < 30 {
		t.Fatalf("unbudgeted job throttled: %+v", st)
	}
}

func TestMaxInFlightSkips(t *testing.T) {
	s := New(nil, 1)
	var concurrent, peak atomic.Int64
	s.Add(Job{Name: "slow", Interval: 10 * time.Millisecond, MaxInFlight: 2, NoJitter: true, Run: func(ctx context.Context) {
		c := concurrent.Add(1)
		for {
			p := peak.Load()
			if c <= p || peak.CompareAndSwap(p, c) {
				break
			}
		}
		select {
		case <-time.After(55 * time.Millisecond):
		case <-ctx.Done():
		}
		concurrent.Add(-1)
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	st := s.Stats()["slow"]
	if peak.Load() != 2 || st.Skipped == 0 {
		t.Fatalf("peak %d stats %+v", peak.Load(), st)
	}
}

func TestShutdownWaitsForInFlight(t *testing.T) {
	s := New(nil, 1)
	var finished atomic.Int64
	s.Add(Job{Name: "x", Interval: 5 * time.Millisecond, MaxInFlight: 10, NoJitter: true, Run: func(ctx context.Context) {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		finished.Add(1)
	}})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	s.Run(ctx)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("shutdown took %v", el)
	}
	if got, want := finished.Load(), int64(s.Totals().Runs); got != want || got == 0 {
		t.Fatalf("finished %d of %d runs before Run returned", got, want)
	}
}
