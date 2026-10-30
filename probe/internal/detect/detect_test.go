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
	ends := d.Flush(t0.Add(13 * time.Minute))
	if len(ends) != 1 || ends[0].Extra["event"] != "incident_end" || ends[0].Extra["reason"] != "probe_stopped" ||
		ends[0].Extra["incident_id"] != inc.Extra["incident_id"] || len(d.Active()) != 0 {
		t.Fatalf("%+v", ends)
	}
}

func flow(client string, lan float64) feed {
	return feed{target: "flow/" + client, service: "other", category: "unclassified", kind: sample.KindFlow, perMinute: 10,
		extra: map[string]any{"proto": "tcp", "client": client, "lan_ms": lan}}
}

func TestClientIncident(t *testing.T) {
	d := New(DefaultOptions())
	d.SetClientContext(func(c string) map[string]any {
		if c == "aaa" {
			return map[string]any{"node": "cpe", "medium": "wifi", "rssi": -80, "band": "5GHz"}
		}
		return map[string]any{"node": "cpe", "medium": "wired"}
	})
	a, b, c := flow("aaa", 3), flow("bbb", 1.5), flow("ccc", 2)
	if ev := run(d, 0, 30, a, b, c); len(ev) != 0 {
		t.Fatalf("events during a steady half hour: %v", ev)
	}
	slow := flow("aaa", 40)
	ev := run(d, 30, 36, slow, b, c)
	if len(ev["incident_start"]) != 1 {
		t.Fatalf("%v", ev)
	}
	inc := ev["incident_start"][0]
	if inc.Extra["scope"] != "client" || inc.Extra["cause"] != "weak_signal" || inc.Category != "home" {
		t.Fatalf("%+v", inc.Extra)
	}
	if svcs := inc.Extra["services"].([]string); len(svcs) != 1 || svcs[0] != "aaa" {
		t.Fatalf("services %v", svcs)
	}
	if cx := inc.Extra["clients"].(map[string]map[string]any)["aaa"]; cx["rssi"] != -80 {
		t.Fatalf("context %v", inc.Extra["clients"])
	}
	ev = run(d, 36, 50, a, b, c)
	if len(ev["incident_end"]) != 1 {
		t.Fatalf("no end: %v", ev)
	}
}

func TestHomeIncident(t *testing.T) {
	d := New(DefaultOptions())
	d.SetClientContext(func(string) map[string]any {
		return map[string]any{"node": "WX5600", "medium": "wifi", "tx_rate_mbps": 300.0}
	})
	a, b, c := flow("aaa", 3), flow("bbb", 2), flow("ccc", 2)
	run(d, 0, 30, a, b, c)
	ev := run(d, 30, 36, flow("aaa", 30), flow("bbb", 25), c)
	if len(ev["incident_start"]) != 1 {
		t.Fatalf("%v", ev)
	}
	inc := ev["incident_start"][0]
	if inc.Extra["scope"] != "home" || inc.Extra["cause"] != "extender" {
		t.Fatalf("%+v", inc.Extra)
	}
	if svcs := inc.Extra["services"].([]string); len(svcs) != 2 {
		t.Fatalf("services %v", svcs)
	}
}

func TestClientFlowsFiltered(t *testing.T) {
	d := New(DefaultOptions())
	q := flow("aaa", 3)
	q.extra = map[string]any{"proto": "quic", "client": "aaa", "lan_ms": 3.0}
	to := flow("bbb", 3)
	to.status = sample.StatusTimeout
	run(d, 0, 2, q, to)
	if len(d.series) != 0 {
		t.Fatalf("series from QUIC or unanswered flows: %v", d.series)
	}
}

func TestClientCause(t *testing.T) {
	now := float64(time.Now().UnixMilli())
	cases := []struct {
		cx   map[string]any
		want string
	}{
		{map[string]any{"node": "cpe", "rssi": -60, "last_roam_ms": now}, "roaming"},
		{map[string]any{"node": "WX5600", "rssi": -80, "tx_rate_mbps": 380.0}, "extender"},
		{map[string]any{"node": "WX5600", "tx_rate_mbps": 24.0}, "weak_link_extender"},
		{map[string]any{"node": "cpe", "rssi": -60, "retry_pct": 35.0}, "retransmissions"},
		{map[string]any{"node": "cpe", "rssi": -60, "radio_busy": int64(75)}, "channel_busy"},
		{map[string]any{"node": "cpe", "medium": "wired"}, "wired_lan"},
		{map[string]any{"node": "cpe", "rssi": -50}, "lan_latency"},
	}
	for _, c := range cases {
		if got := clientCause("client", map[string]map[string]any{"x": c.cx}, "cpe"); got != c.want {
			t.Errorf("%v: got %s, want %s", c.cx, got, c.want)
		}
	}
	// On the extender, its own clients are judged by its own readings.
	ext := []struct {
		cx   map[string]any
		want string
	}{
		{map[string]any{"node": "WX5600", "rssi": -80, "tx_rate_mbps": 380.0}, "weak_signal"},
		{map[string]any{"node": "WX5600", "rssi": -50, "radio_retrans_pct": 30.0}, "radio_retransmissions"},
		{map[string]any{"node": "WX5600", "medium": "wired"}, "wired_lan"},
		{map[string]any{"node": "WX5600", "rssi": -50}, "lan_latency"},
	}
	for _, c := range ext {
		if got := clientCause("client", map[string]map[string]any{"x": c.cx}, "WX5600"); got != c.want {
			t.Errorf("on the extender %v: got %s, want %s", c.cx, got, c.want)
		}
	}
	home := map[string]map[string]any{"a": {"node": "WX5600"}, "b": {"node": "WX5600"}}
	if got := clientCause("home", home, "WX5600"); got != "extender_wide" {
		t.Errorf("home on the extender: %s", got)
	}
	if got := clientCause("home", home, "cpe"); got != "extender" {
		t.Errorf("home of extender clients on the CPE: %s", got)
	}
}

func TestDelegatedNodes(t *testing.T) {
	opt := DefaultOptions()
	opt.DelegatedNodes = []string{"WX5600"}
	d := New(opt)
	d.SetClientContext(func(c string) map[string]any {
		if c == "aaa" {
			return map[string]any{"node": "WX5600", "medium": "wifi"}
		}
		return map[string]any{"node": "cpe", "medium": "wifi", "rssi": -50}
	})
	a, b, c := flow("aaa", 3), flow("bbb", 2), flow("ccc", 2)
	run(d, 0, 30, a, b, c)
	if ev := run(d, 30, 36, flow("aaa", 40), b, c); len(ev["incident_start"]) != 0 {
		t.Fatalf("client of a delegated node raised an incident: %v", ev["incident_start"])
	}
	ev := run(d, 36, 42, flow("aaa", 40), flow("bbb", 30), c)
	if len(ev["incident_start"]) != 1 || ev["incident_start"][0].Extra["scope"] != "home" {
		t.Fatalf("delegated clients must still count towards home incidents: %v", ev)
	}
}

func TestBackhaulIncident(t *testing.T) {
	d := New(DefaultOptions())
	up := icmp("uplink", "backhaul", "home", 1)
	run(d, 0, 30, up)
	slow := up
	slow.rtt = 40
	ev := run(d, 30, 36, slow)
	if len(ev["incident_start"]) != 1 {
		t.Fatalf("%v", ev)
	}
	inc := ev["incident_start"][0]
	if inc.Extra["scope"] != "backhaul" || inc.Extra["cause"] != "backhaul" || inc.Extra["confirmed"] != false {
		t.Fatalf("%+v", inc.Extra)
	}
	if svcs := inc.Extra["services"].([]string); len(svcs) != 1 || svcs[0] != "backhaul" {
		t.Fatalf("services %v", svcs)
	}
}

func TestIncidentConfirmation(t *testing.T) {
	d := New(DefaultOptions())
	a := icmp("netflix/www.netflix.com", "netflix", "streaming", 20)
	b := icmp("youtube/www.youtube.com", "youtube", "streaming", 15)
	run(d, 0, 30, a, b)
	slow := a
	slow.rtt = 80

	// A short blip starts and ends unconfirmed: nothing to notify.
	ev := run(d, 30, 34, slow, b)
	ev2 := run(d, 34, 45, a, b)
	if len(ev["incident_start"]) != 1 || ev["incident_start"][0].Extra["confirmed"] != false {
		t.Fatalf("start %v", ev["incident_start"])
	}
	if len(ev2["incident_end"]) != 1 || ev2["incident_end"][0].Extra["confirmed"] != false || len(ev2["incident_confirmed"]) != 0 {
		t.Fatalf("blip %v", ev2)
	}

	// A lasting one is confirmed once, ConfirmAfter after its start, and
	// its end is confirmed too.
	ev = run(d, 45, 70, slow, b)
	if len(ev["incident_confirmed"]) != 1 {
		t.Fatalf("no confirmation: %v", ev)
	}
	c := ev["incident_confirmed"][0]
	detected := time.UnixMilli(c.Extra["detected_ms"].(int64))
	if got := time.UnixMilli(c.TS).Sub(detected); got < 10*time.Minute || got > 11*time.Minute {
		t.Fatalf("confirmed after %v", got)
	}
	ev = run(d, 70, 80, a, b)
	if len(ev["incident_end"]) != 1 || ev["incident_end"][0].Extra["confirmed"] != true {
		t.Fatalf("end %v", ev["incident_end"])
	}
}

func TestAccessIncidentConfirmedAtOnce(t *testing.T) {
	d := New(DefaultOptions())
	hop := icmp("isp-hop2", "isp-hop", "infra", 4)
	run(d, 0, 30, hop)
	slow := hop
	slow.rtt = 40
	ev := run(d, 30, 34, slow)
	if len(ev["incident_start"]) != 1 || ev["incident_start"][0].Extra["confirmed"] != true {
		t.Fatalf("%v", ev["incident_start"])
	}
}

func TestIncidentTimesFollowDegradedMinutes(t *testing.T) {
	d := New(DefaultOptions())
	a := icmp("netflix/www.netflix.com", "netflix", "streaming", 20)
	b := icmp("youtube/www.youtube.com", "youtube", "streaming", 15)
	run(d, 0, 30, a, b)
	slow := a
	slow.rtt = 80
	ev := run(d, 30, 50, slow, b)
	ev2 := run(d, 50, 60, a, b)
	if len(ev["incident_start"]) != 1 || len(ev2["incident_end"]) != 1 {
		t.Fatalf("%v %v", ev, ev2)
	}
	start, end := ev["incident_start"][0], ev2["incident_end"][0]
	if got := time.UnixMilli(start.Extra["started_ms"].(int64)); !got.Equal(t0.Add(30 * time.Minute)) {
		t.Errorf("started %v, want the first slow minute", got.Sub(t0))
	}
	if got := time.UnixMilli(start.Extra["detected_ms"].(int64)); !got.After(t0.Add(31 * time.Minute)) {
		t.Errorf("detected %v, before the window could see it", got.Sub(t0))
	}
	if got := time.UnixMilli(end.Extra["ended_ms"].(int64)); !got.Equal(t0.Add(50 * time.Minute)) {
		t.Errorf("ended %v, want the end of the last slow minute", got.Sub(t0))
	}
	if got := end.Extra["duration_s"].(int64); got != 20*60 {
		t.Errorf("duration %ds, want 1200", got)
	}
	if !time.UnixMilli(end.TS).After(t0.Add(51 * time.Minute)) {
		t.Errorf("end event at %v, before the window recovered", time.UnixMilli(end.TS).Sub(t0))
	}
}

// A client that stops talking ends its incident at its last slow minute,
// not when the empty window lets the incident go.
func TestClientIncidentEndsAtLastSlowMinute(t *testing.T) {
	d := New(DefaultOptions())
	a := flow("aaa", 2)
	run(d, 0, 30, a)
	slow := a
	slow.extra = map[string]any{"proto": "tcp", "client": "aaa", "lan_ms": 40.0}
	ev := run(d, 30, 45, slow)
	ev2 := run(d, 45, 60)
	if len(ev["incident_start"]) != 1 || len(ev2["incident_end"]) != 1 {
		t.Fatalf("%v %v", ev, ev2)
	}
	end := ev2["incident_end"][0]
	if got := time.UnixMilli(end.Extra["ended_ms"].(int64)); !got.Equal(t0.Add(45 * time.Minute)) {
		t.Errorf("ended %v", got.Sub(t0))
	}
	if got := end.Extra["duration_s"].(int64); got != 15*60 {
		t.Errorf("duration %ds, want 900", got)
	}
}
