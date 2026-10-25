// Package self reports the probe's own resource use, so that measurement
// overhead on the CPE is visible next to the measurements.
package self

import (
	"bufio"
	"io/fs"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// Collector produces "self" samples.
type Collector struct {
	fs      fs.FS
	now     func() time.Time
	extra   func() map[string]any
	start   time.Time
	prevCPU time.Duration
	prevAt  time.Time
}

// New returns a collector reading proc/self from fsys. extra, if not nil,
// adds component counters to every sample.
func New(fsys fs.FS, now func() time.Time, extra func() map[string]any) *Collector {
	if now == nil {
		now = time.Now
	}
	t := now()
	return &Collector{fs: fsys, now: now, extra: extra, start: t, prevAt: t}
}

// Collect returns one sample. It is not safe for concurrent use.
func (c *Collector) Collect() sample.Sample {
	now := c.now()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	x := map[string]any{
		"uptime_s":    int64(now.Sub(c.start).Seconds()),
		"goroutines":  runtime.NumGoroutine(),
		"gomaxprocs":  runtime.GOMAXPROCS(0),
		"heap_alloc":  ms.HeapAlloc,
		"heap_sys":    ms.HeapSys,
		"go_sys":      ms.Sys,
		"num_gc":      ms.NumGC,
		"mem_limit":   debug.SetMemoryLimit(-1),
		"go_released": ms.HeapReleased,
	}
	if st, err := readStatus(c.fs); err == nil {
		for k, v := range st {
			x[k] = v
		}
	}
	if user, sys, ok := cpuTimes(); ok {
		x["cpu_user_s"] = user.Seconds()
		x["cpu_sys_s"] = sys.Seconds()
		total := user + sys
		if el := now.Sub(c.prevAt); el > 0 && c.prevCPU > 0 {
			x["cpu_pct"] = float64(total-c.prevCPU) / float64(el) * 100
		}
		c.prevCPU, c.prevAt = total, now
	}
	if c.extra != nil {
		for k, v := range c.extra() {
			x[k] = v
		}
	}
	return sample.Sample{TS: now.UnixMilli(), Kind: sample.KindSelf, Status: sample.StatusOK, Extra: x}
}

// readStatus extracts resident and peak memory from proc/self/status.
func readStatus(fsys fs.FS) (map[string]any, error) {
	f, err := fsys.Open("proc/self/status")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	keys := map[string]string{"VmRSS": "rss_kb", "VmHWM": "rss_peak_kb", "RssAnon": "rss_anon_kb", "Threads": "threads"}
	out := map[string]any{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		name, wanted := keys[k]
		if !ok || !wanted {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
			out[name] = n
		}
	}
	return out, sc.Err()
}
