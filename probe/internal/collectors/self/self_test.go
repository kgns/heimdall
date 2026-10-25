package self

import (
	"testing"
	"testing/fstest"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func TestCollect(t *testing.T) {
	fsys := fstest.MapFS{"proc/self/status": {Data: []byte(
		"Name:\theimdall-probe\nVmHWM:\t   14200 kB\nVmRSS:\t   12100 kB\nRssAnon:\t    6000 kB\nThreads:\t5\n")}}
	now := time.Unix(1000, 0)
	c := New(fsys, func() time.Time { return now }, func() map[string]any { return map[string]any{"icmp_sent": 7} })

	s := c.Collect()
	if s.Kind != sample.KindSelf || s.Extra["rss_kb"] != uint64(12100) || s.Extra["rss_peak_kb"] != uint64(14200) ||
		s.Extra["threads"] != uint64(5) || s.Extra["icmp_sent"] != 7 {
		t.Fatalf("extra %+v", s.Extra)
	}
	if _, ok := s.Extra["cpu_user_s"]; !ok {
		t.Fatal("cpu time missing")
	}
	if _, ok := s.Extra["cpu_pct"]; ok {
		t.Fatal("cpu_pct reported without a previous sample")
	}

	for start := time.Now(); time.Since(start) < 20*time.Millisecond; {
	}
	now = now.Add(time.Second)
	s = c.Collect()
	pct, ok := s.Extra["cpu_pct"].(float64)
	if !ok || pct < 0 {
		t.Fatalf("cpu_pct %v", s.Extra["cpu_pct"])
	}
	if s.Extra["uptime_s"] != int64(1) {
		t.Fatalf("uptime %v", s.Extra["uptime_s"])
	}
}

func TestCollectWithoutProc(t *testing.T) {
	s := New(fstest.MapFS{}, nil, nil).Collect()
	if _, ok := s.Extra["rss_kb"]; ok {
		t.Fatal("rss without proc")
	}
	if _, ok := s.Extra["heap_alloc"]; !ok {
		t.Fatal("runtime stats missing")
	}
}
