package detect

import (
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

var t0 = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

type feed struct {
	target, service, category, dst string
	kind                           sample.Kind
	perMinute                      int
	rtt                            float64
	// lossEvery marks every n-th sample as lost; 0 means none.
	lossEvery int
	extra     map[string]any
	status    sample.Status
}

func (f feed) minute(d *Detector, m int) {
	for i := range f.perMinute {
		s := sample.Sample{
			TS: t0.Add(time.Duration(m)*time.Minute + time.Duration(i)*time.Second).UnixMilli(), Kind: f.kind,
			TargetID: f.target, Service: f.service, Category: f.category, DstIP: f.dst, Status: sample.StatusOK, Extra: f.extra,
		}
		if f.status != "" {
			s.Status = f.status
		}
		if f.lossEvery > 0 && i%f.lossEvery == 0 {
			s.Status = sample.StatusTimeout
		} else if s.Status == sample.StatusOK {
			v := f.rtt + float64(i%3)
			s.RTTms = &v
		}
		d.Write(&s)
	}
}

// run feeds every stream for minutes [from, to) and ticks after each, and
// returns the events by name.
func run(d *Detector, from, to int, feeds ...feed) map[string][]sample.Sample {
	out := map[string][]sample.Sample{}
	for m := from; m < to; m++ {
		for _, f := range feeds {
			f.minute(d, m)
		}
		for _, ev := range d.Tick(t0.Add(time.Duration(m+1) * time.Minute)) {
			name := ev.Extra["event"].(string)
			out[name] = append(out[name], ev)
		}
	}
	return out
}

func icmp(target, service, category string, rtt float64) feed {
	return feed{target: target, service: service, category: category, dst: "203.0.113.1", kind: sample.KindICMP, perMinute: 60, rtt: rtt}
}

func TestServiceLatencyIncident(t *testing.T) {
	d := New(DefaultOptions())
	a := icmp("netflix/www.netflix.com", "netflix", "streaming", 20)
	b := icmp("youtube/www.youtube.com", "youtube", "streaming", 15)
	if ev := run(d, 0, 30, a, b); len(ev) != 0 {
		t.Fatalf("events during a steady half hour: %v", ev)
	}
	slow := a
	slow.rtt = 80
	ev := run(d, 30, 35, slow, b)
	if len(ev["anomaly_start"]) != 1 || len(ev["incident_start"]) != 1 {
		t.Fatalf("%v", ev)
	}
	inc := ev["incident_start"][0]
	if inc.Extra["scope"] != "service" || inc.Extra["cause"] != "path" || inc.Service != "netflix" {
		t.Fatalf("%+v", inc)
	}
	tg := inc.Extra["targets"].([]map[string]any)[0]
	if tg["reason"] != "latency" || tg["current_ms"].(float64) < 79 || tg["baseline_ms"].(float64) > 22 {
		t.Fatalf("%+v", tg)
	}
	ev = run(d, 35, 40, a, b)
	if len(ev["anomaly_end"]) != 1 || len(ev["incident_end"]) != 1 ||
		ev["incident_end"][0].Extra["incident_id"] != inc.Extra["incident_id"] {
		t.Fatalf("%v", ev)
	}
}

func TestBriefSpikeIgnored(t *testing.T) {
	d := New(DefaultOptions())
	a := icmp("netflix/www.netflix.com", "netflix", "streaming", 20)
	run(d, 0, 30, a)
	slow := a
	slow.rtt = 200
	// One slow minute moves the 3-minute median for at most one tick.
	ev := run(d, 30, 31, slow)
	ev2 := run(d, 31, 36, a)
	if len(ev)+len(ev2) != 0 {
		t.Fatalf("%v %v", ev, ev2)
	}
}

func TestWarmup(t *testing.T) {
	d := New(DefaultOptions())
	slow := icmp("netflix/www.netflix.com", "netflix", "streaming", 20)
	run(d, 0, 5, slow)
	slow.rtt = 200
	if ev := run(d, 5, 10, slow); len(ev) != 0 {
		t.Fatalf("judged before warmup: %v", ev)
	}
}

func TestDestinationChange(t *testing.T) {
	d := New(DefaultOptions())
	a := icmp("steam/store.steampowered.com", "steam", "gaming", 5)
	run(d, 0, 30, a)
	// The new address is a new series: no anomaly however far it is.
	moved := a
	moved.dst, moved.rtt = "203.0.113.99", 196
	if ev := run(d, 30, 40, moved); len(ev) != 0 {
		t.Fatalf("%v", ev)
	}
	// An anomaly on a known destination soon after a change names it.
	d.Write(&sample.Sample{TS: t0.Add(40 * time.Minute).UnixMilli(), Kind: sample.KindEvent, Service: "steam",
		Extra: map[string]any{"event": "dst_change"}})
	slow := a
	slow.rtt = 60
	ev := run(d, 40, 43, slow, moved)
	if len(ev["incident_start"]) != 1 || ev["incident_start"][0].Extra["cause"] != "destination_change" {
		t.Fatalf("%v", ev)
	}
}

func TestAccessIncident(t *testing.T) {
	d := New(DefaultOptions())
	hop := icmp("isp-hop2", "isp-hop", "infra", 4)
	hop.extra = map[string]any{"ttl_limit": 2}
	svcs := []feed{
		icmp("a/x", "a", "browsing", 20), icmp("b/x", "b", "social", 30),
		icmp("c/x", "c", "gaming", 40), icmp("d/x", "d", "streaming", 10),
	}
	run(d, 0, 30, append(svcs, hop)...)
	slowHop := hop
	slowHop.rtt = 40
	var slow []feed
	for _, f := range svcs {
		f.rtt += 40
		slow = append(slow, f)
	}
	ev := run(d, 30, 34, append(slow, slowHop)...)
	if len(ev["incident_start"]) != 1 {
		t.Fatalf("%v", ev["incident_start"])
	}
	inc := ev["incident_start"][0]
	if inc.Extra["scope"] != "access" || len(inc.Extra["services"].([]string)) != 5 || inc.Extra["anomalous_series"] != 5 {
		t.Fatalf("%+v", inc.Extra)
	}
}

func TestBroadIncidentWithoutHops(t *testing.T) {
	d := New(DefaultOptions())
	svcs := []feed{icmp("a/x", "a", "browsing", 20), icmp("b/x", "b", "social", 30), icmp("c/x", "c", "gaming", 40)}
	run(d, 0, 30, svcs...)
	var slow []feed
	for _, f := range svcs {
		f.rtt *= 3
		slow = append(slow, f)
	}
	ev := run(d, 30, 33, slow...)
	if len(ev["incident_start"]) != 1 || ev["incident_start"][0].Extra["scope"] != "access" {
		t.Fatalf("%v", ev)
	}
}

func TestLossAndRateLimitedHops(t *testing.T) {
	d := New(DefaultOptions())
	a := icmp("a/x", "a", "browsing", 20)
	hop := icmp("isp-hop3", "isp-hop", "infra", 6)
	hop.extra = map[string]any{"ttl_limit": 3}
	run(d, 0, 30, a, hop)
	lossy := a
	lossy.lossEvery = 4
	lossyHop := hop
	lossyHop.lossEvery = 2
	ev := run(d, 30, 33, lossy, lossyHop)
	if len(ev["anomaly_start"]) != 1 || ev["anomaly_start"][0].TargetID != "a/x" || ev["anomaly_start"][0].Extra["reason"] != "loss" {
		t.Fatalf("%v", ev["anomaly_start"])
	}
	if inc := ev["incident_start"]; len(inc) != 1 || inc[0].Extra["scope"] != "service" {
		t.Fatalf("hop loss made an access incident: %v", inc)
	}
}

func TestTLSBlocked(t *testing.T) {
	d := New(DefaultOptions())
	blocked := feed{target: "discord/discord.com", service: "discord", category: "voice", dst: "162.159.135.232",
		kind: sample.KindHTTP, perMinute: 1, status: sample.StatusTimeout,
		extra: map[string]any{"phase": "tls", "reason": "timeout"}}
	ok := feed{target: "github/github.com", service: "github", category: "cloud_work", dst: "140.82.121.4",
		kind: sample.KindHTTP, perMinute: 1, rtt: 120}
	ev := run(d, 0, 12, blocked, ok)
	if len(ev["incident_start"]) != 1 {
		t.Fatalf("%v", ev)
	}
	inc := ev["incident_start"][0]
	if inc.Extra["cause"] != "tls_blocked" || inc.Service != "discord" || inc.Category != "voice" {
		t.Fatalf("%+v", inc)
	}
	if got := d.Active(); len(got) != 1 || got[0] != "tls:discord" {
		t.Fatalf("active %v", got)
	}
}
