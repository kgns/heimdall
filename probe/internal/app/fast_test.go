package app

import (
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/detect"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// The fast detector reports only while asked to, starts with fresh
// incidents and ends the open ones when it stops reporting.
func TestFastDetectorSwitch(t *testing.T) {
	f := &fastDetector{det: detect.New(detect.FastOptions()), tick: 5 * time.Second}
	t0 := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	at := t0
	step := func(lan float64) ([]sample.Sample, string) {
		for i := range 10 {
			f.det.Write(&sample.Sample{TS: at.Add(time.Duration(i) * 500 * time.Millisecond).UnixMilli(),
				Kind: sample.KindFlow, TargetID: "flow/aaa", Status: sample.StatusOK,
				Extra: map[string]any{"proto": "tcp", "client": "aaa", "lan_ms": lan}})
		}
		at = at.Add(5 * time.Second)
		return f.tick1(at)
	}
	count := func(evs []sample.Sample, name string) int {
		n := 0
		for _, ev := range evs {
			if ev.Extra["event"] == name {
				n++
			}
		}
		return n
	}
	for range 36 {
		step(2)
	}
	// Slow while not asked: nothing reported.
	for range 6 {
		if evs, change := step(40); len(evs) != 0 || change != "" {
			t.Fatalf("reported while off: %v %q", evs, change)
		}
	}
	// Asked: the ongoing slowdown is reported as a new incident at once.
	f.until.Store(at.Add(time.Minute).UnixMilli())
	evs, change := step(40)
	if change != "on" || count(evs, "incident_start") != 1 {
		t.Fatalf("%q %v", change, evs)
	}
	// No longer asked: the open incident ends.
	f.until.Store(0)
	evs, change = step(40)
	if change != "off" || count(evs, "incident_end") != 1 || evs[0].Extra["reason"] != "fast_off" {
		t.Fatalf("%q %v", change, evs)
	}
}
