package scheduler

import (
	"context"
	"math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Job is a periodic task. Each tick runs Run in its own goroutine, so a slow
// run does not delay the next tick; MaxInFlight bounds how many runs may
// overlap, and ticks beyond it are skipped.
type Job struct {
	Name     string
	Interval time.Duration
	// Budgeted jobs take a token from the shared limiter before each run.
	Budgeted bool
	// MaxInFlight defaults to 1.
	MaxInFlight int
	// NoJitter starts the job immediately instead of at a random phase.
	NoJitter bool
	Run      func(ctx context.Context)
}

// JobStats are counters for one job.
type JobStats struct {
	Runs    uint64 `json:"runs"`
	Skipped uint64 `json:"skipped"`
}

type jobState struct {
	Job
	runs, skipped atomic.Uint64
	inflight      atomic.Int64
}

// Scheduler runs jobs until its context is cancelled.
type Scheduler struct {
	limiter *Limiter
	mu      sync.Mutex
	rnd     *rand.Rand
	jobs    []*jobState
}

// New returns a scheduler using limiter for budgeted jobs. limiter may be
// nil, in which case Budgeted is ignored.
func New(limiter *Limiter, seed uint64) *Scheduler {
	return &Scheduler{limiter: limiter, rnd: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// Add registers a job. It must be called before Run.
func (s *Scheduler) Add(j Job) {
	if j.MaxInFlight < 1 {
		j.MaxInFlight = 1
	}
	s.jobs = append(s.jobs, &jobState{Job: j})
}

// Stats returns counters per job name.
func (s *Scheduler) Stats() map[string]JobStats {
	out := make(map[string]JobStats, len(s.jobs))
	for _, j := range s.jobs {
		out[j.Name] = JobStats{Runs: j.runs.Load(), Skipped: j.skipped.Load()}
	}
	return out
}

// Totals returns counters summed over all jobs.
func (s *Scheduler) Totals() JobStats {
	var t JobStats
	for _, j := range s.jobs {
		t.Runs += j.runs.Load()
		t.Skipped += j.skipped.Load()
	}
	return t
}

// Names returns the registered job names, sorted.
func (s *Scheduler) Names() []string {
	out := make([]string, len(s.jobs))
	for i, j := range s.jobs {
		out[i] = j.Name
	}
	sort.Strings(out)
	return out
}

// Run starts every job and blocks until ctx is done and all in-flight runs
// have returned.
func (s *Scheduler) Run(ctx context.Context) {
	var loops, runs sync.WaitGroup
	for _, j := range s.jobs {
		var phase time.Duration
		if !j.NoJitter && j.Interval > 0 {
			s.mu.Lock()
			phase = time.Duration(s.rnd.Int64N(int64(j.Interval)))
			s.mu.Unlock()
		}
		loops.Add(1)
		go func() {
			defer loops.Done()
			s.loop(ctx, j, phase, &runs)
		}()
	}
	loops.Wait()
	runs.Wait()
}

func (s *Scheduler) loop(ctx context.Context, j *jobState, phase time.Duration, runs *sync.WaitGroup) {
	start := time.Now().Add(phase)
	if !sleepUntil(ctx, start) {
		return
	}
	for k := int64(0); ; {
		if j.inflight.Load() >= int64(j.MaxInFlight) {
			j.skipped.Add(1)
		} else {
			if j.Budgeted && s.limiter != nil {
				if s.limiter.Wait(ctx) != nil {
					return
				}
			}
			if ctx.Err() != nil {
				return
			}
			j.inflight.Add(1)
			j.runs.Add(1)
			runs.Add(1)
			go func() {
				defer runs.Done()
				defer j.inflight.Add(-1)
				j.Run(ctx)
			}()
		}

		k++
		next := start.Add(time.Duration(k) * j.Interval)
		if now := time.Now(); now.After(next) {
			missed := int64(now.Sub(next)/j.Interval) + 1
			j.skipped.Add(uint64(missed))
			k += missed
			next = start.Add(time.Duration(k) * j.Interval)
		}
		if !sleepUntil(ctx, next) {
			return
		}
	}
}

func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}
