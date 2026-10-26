// Package detect finds latency and loss anomalies in the probe's own
// samples as they are produced, and groups them into incidents with a
// scope (the access network, one service, DNS) and a likely cause.
//
// Every (target, kind, destination) series keeps one-minute buckets and an
// exponentially weighted baseline of its per-minute median and loss. A
// series is anomalous when the last few minutes are well above its
// baseline; the baseline stops learning while it is. A new destination
// starts a new series, so a DNS-driven move to a farther server is not an
// anomaly but a destination change.
package detect

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// rule holds the thresholds for one sample kind. A window is a number of
// one-minute buckets.
type rule struct {
	window     int
	minSamples int
	// Latency is anomalous above baseline*ratio and baseline+delta (ms).
	ratio, delta float64
	// Loss is anomalous at minLost or more losses and a loss rate at least
	// lossAbs above the baseline and three times it.
	minLost int
	lossAbs float64
}

var rules = map[sample.Kind]rule{
	sample.KindICMP:    {window: 3, minSamples: 20, ratio: 1.5, delta: 10, minLost: 5, lossAbs: 0.05},
	sample.KindUDPEcho: {window: 3, minSamples: 20, ratio: 1.5, delta: 10, minLost: 5, lossAbs: 0.05},
	sample.KindTCP:     {window: 3, minSamples: 10, ratio: 1.5, delta: 15, minLost: 3, lossAbs: 0.10},
	sample.KindSTUN:    {window: 5, minSamples: 20, ratio: 1.5, delta: 15, minLost: 3, lossAbs: 0.10},
	sample.KindHTTP:    {window: 10, minSamples: 6, ratio: 2.0, delta: 50, minLost: 3, lossAbs: 0.30},
	sample.KindDNS:     {window: 5, minSamples: 6, ratio: 3.0, delta: 50, minLost: 3, lossAbs: 0.30},
}

const (
	maxBuckets = 10
	// Values kept per bucket; ICMP at 1/s fills 60.
	maxValues = 120
	// baselineAlpha weights each minute so that the baseline follows about
	// the last hour.
	baselineAlpha = 1.0 / 60
	enterTicks    = 2
	exitTicks     = 3
	// dstChangeWindow links a service anomaly to a destination change
	// that happened shortly before it.
	dstChangeWindow = 10 * time.Minute
	// updateEvery throttles incident_update events.
	updateEvery = 5 * time.Minute
)

// Options configure a Detector.
type Options struct {
	// Warmup is how much history a series needs before it is judged.
	Warmup time.Duration
	// AccessServices are services that measure the access network itself
	// (the ISP hops, the gateway); an anomaly there is an access incident.
	AccessServices []string
	// AccessFraction of the measured services anomalous at once also makes
	// an access incident, with at least AccessMin of them.
	AccessFraction float64
	AccessMin      int
}

// DefaultOptions are tuned for a CPE measuring a few dozen services.
func DefaultOptions() Options {
	return Options{
		Warmup: 15 * time.Minute, AccessServices: []string{"isp-hop", "isp-gateway"},
		AccessFraction: 0.3, AccessMin: 3,
	}
}

type key struct {
	target string
	kind   sample.Kind
	dst    string
}

type bucket struct {
	values []float32
	total  int
	lost   int
}

type series struct {
	key      key
	service  string
	category string
	noLoss   bool
	buckets  []bucket // oldest first, the last is the open minute
	minutes  int
	base     float64
	baseLoss float64
	haveBase bool
	lastSeen time.Time

	anomalous bool
	hits      int // consecutive ticks with the condition
	misses    int // consecutive ticks without it while anomalous
	since     time.Time
	cur       float64
	curLoss   float64
	reason    string
}

// tlsStat counts HTTPS attempts of a service over the last minutes, to spot
// handshakes that fail after TCP connected.
type tlsStat struct {
	attempts, tlsFail []int // per minute, oldest first
}

// Incident is a group of anomalies with one scope.
type Incident struct {
	ID       string
	Scope    string // access, service, dns
	Cause    string
	Service  string
	Category string
	Started  time.Time
	services []string
	lastSent time.Time
}

// Detector consumes samples and reports anomalies and incidents through
// the samples it returns from Tick.
type Detector struct {
	opt Options

	mu         sync.Mutex
	series     map[key]*series
	dstChanges map[string]time.Time
	tls        map[string]*tlsStat
	services   map[string]string // service -> category, of every measured service
	incidents  map[string]*Incident
	started    time.Time
}

// New returns a detector.
func New(opt Options) *Detector {
	return &Detector{
		opt: opt, series: map[key]*series{}, dstChanges: map[string]time.Time{},
		tls: map[string]*tlsStat{}, services: map[string]string{}, incidents: map[string]*Incident{},
	}
}

// Write implements sample.Sink. It only files the sample; the analysis
// runs in Tick.
func (d *Detector) Write(s *sample.Sample) error {
	if s.Kind == sample.KindEvent {
		if s.Extra["event"] == "dst_change" && s.Service != "" {
			d.mu.Lock()
			d.dstChanges[s.Service] = time.UnixMilli(s.TS)
			d.mu.Unlock()
		}
		return nil
	}
	if _, ok := rules[s.Kind]; !ok || s.TargetID == "" || s.Kind == sample.KindDNS && dnsLayerSkipped(s) {
		return nil
	}
	k := key{target: s.TargetID, kind: s.Kind, dst: s.DstIP}
	d.mu.Lock()
	defer d.mu.Unlock()
	sr := d.series[k]
	if sr == nil {
		sr = &series{key: k, service: s.Service, category: s.Category, buckets: []bucket{{}}}
		// TTL-limited probes measure routers that rate-limit their
		// time exceeded replies, so their losses say little.
		_, sr.noLoss = s.Extra["ttl_limit"]
		d.series[k] = sr
	}
	sr.lastSeen = time.UnixMilli(s.TS)
	b := &sr.buckets[len(sr.buckets)-1]
	b.total++
	if s.Status == sample.StatusOK || s.Status == sample.StatusRefused && s.RTTms != nil {
		if s.RTTms != nil && len(b.values) < maxValues {
			b.values = append(b.values, float32(*s.RTTms))
		}
	} else {
		b.lost++
	}
	if s.Service != "" && s.Category != "infra" && s.Category != "home" {
		d.services[s.Service] = s.Category
	}
	if s.Kind == sample.KindHTTP && s.Service != "" {
		ts := d.tls[s.Service]
		if ts == nil {
			ts = &tlsStat{attempts: []int{0}, tlsFail: []int{0}}
			d.tls[s.Service] = ts
		}
		ts.attempts[len(ts.attempts)-1]++
		if s.Status != sample.StatusOK && s.Extra["phase"] == "tls" &&
			(s.Extra["reason"] == "timeout" || s.Extra["reason"] == "reset") {
			ts.tlsFail[len(ts.tlsFail)-1]++
		}
	}
	return nil
}

// Close implements sample.Sink.
func (d *Detector) Close() error { return nil }

// dnsLayerSkipped leaves out the identity and uncached layers, whose
// latency depends on which resolver of a rotating pool answered.
func dnsLayerSkipped(s *sample.Sample) bool {
	l, _ := s.Extra["layer"].(string)
	return l == "identity" || l == "uncached"
}

// Tick closes the current minute, re-evaluates every series and returns
// the anomaly and incident events to record. Call it once a minute.
func (d *Detector) Tick(now time.Time) []sample.Sample {
	d.mu.Lock()
	if d.started.IsZero() {
		d.started = now
	}
	var out []sample.Sample
	for k, sr := range d.series {
		if now.Sub(sr.lastSeen) > time.Hour {
			delete(d.series, k)
			continue
		}
		if ev, ok := d.evaluate(sr, now); ok {
			out = append(out, ev)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TargetID != out[j].TargetID {
			return out[i].TargetID < out[j].TargetID
		}
		return out[i].DstIP < out[j].DstIP
	})
	for _, ts := range d.tls {
		ts.attempts = rollInts(ts.attempts)
		ts.tlsFail = rollInts(ts.tlsFail)
	}
	out = append(out, d.correlate(now)...)
	d.mu.Unlock()
	return out
}

func rollInts(s []int) []int {
	s = append(s, 0)
	if len(s) > maxBuckets+1 {
		s = s[len(s)-maxBuckets-1:]
	}
	return s
}

// evaluate closes the open bucket of sr and updates its state, returning an
// anomaly_start or anomaly_end event on a transition.
func (d *Detector) evaluate(sr *series, now time.Time) (sample.Sample, bool) {
	r := rules[sr.key.kind]
	closed := sr.buckets[len(sr.buckets)-1]
	if closed.total > 0 {
		sr.minutes++
	}
	sr.buckets = append(sr.buckets, bucket{})
	if len(sr.buckets) > maxBuckets+1 {
		sr.buckets = sr.buckets[len(sr.buckets)-maxBuckets-1:]
	}

	// The window is the last r.window closed buckets.
	win := sr.buckets[:len(sr.buckets)-1]
	if len(win) > r.window {
		win = win[len(win)-r.window:]
	}
	var vals []float64
	total, lost := 0, 0
	for _, b := range win {
		for _, v := range b.values {
			vals = append(vals, float64(v))
		}
		total += b.total
		lost += b.lost
	}
	cur := median(vals)
	curLoss := 0.0
	if total > 0 {
		curLoss = float64(lost) / float64(total)
	}
	sr.cur, sr.curLoss = cur, curLoss

	warm := sr.haveBase && time.Duration(sr.minutes)*time.Minute >= d.opt.Warmup
	cond, reason := false, ""
	if warm {
		if len(vals) >= r.minSamples && cur > sr.base*r.ratio && cur-sr.base > r.delta {
			cond, reason = true, "latency"
		}
		if !sr.noLoss && lost >= r.minLost && curLoss >= sr.baseLoss+r.lossAbs && curLoss >= 3*sr.baseLoss {
			if reason == "" {
				reason = "loss"
			} else {
				reason = "latency+loss"
			}
			cond = true
		}
	}

	// Learn from normal minutes only.
	if closed.total > 0 && !sr.anomalous && !cond {
		m := median32(closed.values)
		l := float64(closed.lost) / float64(closed.total)
		switch {
		case !sr.haveBase && !math.IsNaN(m):
			sr.base, sr.baseLoss, sr.haveBase = m, l, true
		case sr.haveBase:
			if !math.IsNaN(m) {
				sr.base += baselineAlpha * (m - sr.base)
			}
			sr.baseLoss += baselineAlpha * (l - sr.baseLoss)
		}
	}

	switch {
	case !sr.anomalous && cond:
		sr.hits++
		if sr.hits >= enterTicks {
			sr.anomalous, sr.misses, sr.since, sr.reason = true, 0, now, reason
			return d.anomalyEvent(sr, "anomaly_start", now), true
		}
	case !sr.anomalous:
		sr.hits = 0
	case sr.anomalous && !cond:
		sr.misses++
		if sr.misses >= exitTicks {
			ev := d.anomalyEvent(sr, "anomaly_end", now)
			sr.anomalous, sr.hits = false, 0
			return ev, true
		}
	default:
		sr.misses = 0
		if reason != "" {
			sr.reason = reason
		}
	}
	return sample.Sample{}, false
}

func (d *Detector) anomalyEvent(sr *series, event string, now time.Time) sample.Sample {
	x := map[string]any{
		"event": event, "kind": string(sr.key.kind), "reason": sr.reason,
		"current_ms": round(sr.cur), "baseline_ms": round(sr.base),
		"loss": round(sr.curLoss), "baseline_loss": round(sr.baseLoss),
	}
	if event == "anomaly_end" {
		x["duration_s"] = int64(now.Sub(sr.since).Seconds())
	}
	return sample.Sample{
		TS: now.UnixMilli(), Kind: sample.KindEvent, Status: sample.StatusOK, Category: sr.category,
		Service: sr.service, TargetID: sr.key.target, DstIP: sr.key.dst, Extra: x,
	}
}

// correlate groups the anomalous series into incidents.
func (d *Detector) correlate(now time.Time) []sample.Sample {
	byService := map[string][]*series{}
	var access, dns []*series
	for _, sr := range d.series {
		if !sr.anomalous {
			continue
		}
		switch {
		case slices.Contains(d.opt.AccessServices, sr.service):
			access = append(access, sr)
		case sr.key.kind == sample.KindDNS:
			dns = append(dns, sr)
		case sr.category == "home":
		default:
			byService[sr.service] = append(byService[sr.service], sr)
		}
	}
	measured := len(d.services)
	broad := len(byService) >= d.opt.AccessMin && float64(len(byService)) >= d.opt.AccessFraction*float64(measured)

	want := map[string]*Incident{}
	members := map[string][]*series{}
	accessDirect := false
	for _, sr := range access {
		if slices.Contains(d.opt.AccessServices, sr.service) {
			accessDirect = true
		}
	}
	if accessDirect || broad {
		inc := &Incident{Scope: "access", Cause: "access_network", Category: "infra"}
		var all []*series
		all = append(all, access...)
		for _, ss := range byService {
			all = append(all, ss...)
		}
		want["access"], members["access"] = inc, all
	} else {
		for svc, ss := range byService {
			cause := "path"
			if t, ok := d.dstChanges[svc]; ok && now.Sub(t) <= dstChangeWindow {
				cause = "destination_change"
			}
			k := "service:" + svc
			want[k] = &Incident{Scope: "service", Cause: cause, Service: svc, Category: ss[0].category}
			members[k] = ss
		}
	}
	if len(dns) > 0 {
		want["dns"], members["dns"] = &Incident{Scope: "dns", Cause: "dns_latency", Category: "infra", Service: "dns"}, dns
	}
	for svc, ts := range d.tls {
		attempts, fails := sumLast(ts.attempts, 10), sumLast(ts.tlsFail, 10)
		if attempts >= 5 && float64(fails) >= 0.8*float64(attempts) && now.Sub(d.started) >= d.opt.Warmup/3 {
			k := "tls:" + svc
			want[k] = &Incident{Scope: "service", Cause: "tls_blocked", Service: svc, Category: d.services[svc]}
			members[k] = nil
		}
	}

	var out []sample.Sample
	keys := make([]string, 0, len(want)+len(d.incidents))
	for k := range want {
		keys = append(keys, k)
	}
	for k := range d.incidents {
		if _, ok := want[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		w, cur := want[k], d.incidents[k]
		switch {
		case w != nil && cur == nil:
			w.ID, w.Started, w.lastSent = newID(), now, now
			w.services = serviceList(members[k], w.Service)
			d.incidents[k] = w
			out = append(out, d.incidentEvent(w, "incident_start", members[k], now))
		case w != nil:
			svcs := serviceList(members[k], cur.Service)
			if !slices.Equal(svcs, cur.services) && now.Sub(cur.lastSent) >= updateEvery {
				cur.services, cur.lastSent = svcs, now
				out = append(out, d.incidentEvent(cur, "incident_update", members[k], now))
			}
		case cur != nil:
			delete(d.incidents, k)
			out = append(out, d.incidentEvent(cur, "incident_end", nil, now))
		}
	}
	return out
}

func sumLast(s []int, n int) int {
	// The last element is the open minute.
	closed := s[:len(s)-1]
	if len(closed) > n {
		closed = closed[len(closed)-n:]
	}
	t := 0
	for _, v := range closed {
		t += v
	}
	return t
}

func serviceList(ss []*series, fallback string) []string {
	set := map[string]bool{}
	for _, sr := range ss {
		if sr.service != "" {
			set[sr.service] = true
		}
	}
	if len(set) == 0 && fallback != "" {
		set[fallback] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

const maxTargetsInEvent = 12

func (d *Detector) incidentEvent(inc *Incident, event string, ss []*series, now time.Time) sample.Sample {
	x := map[string]any{
		"event": event, "incident_id": inc.ID, "scope": inc.Scope, "cause": inc.Cause,
		"services": inc.services, "started_ms": inc.Started.UnixMilli(),
	}
	if event == "incident_end" {
		x["duration_s"] = int64(now.Sub(inc.Started).Seconds())
	}
	if len(ss) > 0 {
		// The most degraded series first.
		sorted := slices.Clone(ss)
		sort.Slice(sorted, func(i, j int) bool { return severity(sorted[i]) > severity(sorted[j]) })
		var ts []map[string]any
		for _, sr := range sorted[:min(len(sorted), maxTargetsInEvent)] {
			ts = append(ts, map[string]any{
				"target_id": sr.key.target, "kind": string(sr.key.kind), "dst_ip": sr.key.dst, "reason": sr.reason,
				"current_ms": round(sr.cur), "baseline_ms": round(sr.base),
				"loss": round(sr.curLoss), "baseline_loss": round(sr.baseLoss),
			})
		}
		x["targets"] = ts
		x["anomalous_series"] = len(ss)
	}
	if inc.Scope == "access" {
		x["measured_services"] = len(d.services)
	}
	return sample.Sample{
		TS: now.UnixMilli(), Kind: sample.KindEvent, Status: sample.StatusOK, Category: inc.Category,
		Service: inc.Service, Extra: x,
	}
}

func severity(sr *series) float64 {
	s := 0.0
	if sr.base > 0 {
		s = sr.cur / sr.base
	}
	return s + 10*(sr.curLoss-sr.baseLoss)
}

// Flush ends every open incident, for a probe that is stopping; the next
// run starts without them and would otherwise leave them open downstream.
func (d *Detector) Flush(now time.Time) []sample.Sample {
	d.mu.Lock()
	defer d.mu.Unlock()
	keys := make([]string, 0, len(d.incidents))
	for k := range d.incidents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []sample.Sample
	for _, k := range keys {
		ev := d.incidentEvent(d.incidents[k], "incident_end", nil, now)
		ev.Extra["reason"] = "probe_stopped"
		out = append(out, ev)
		delete(d.incidents, k)
	}
	return out
}

// Active returns the open incidents, for heartbeats.
func (d *Detector) Active() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []string
	for k := range d.incidents {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return math.NaN()
	}
	s := slices.Clone(v)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func median32(v []float32) float64 {
	f := make([]float64, len(v))
	for i, x := range v {
		f[i] = float64(x)
	}
	return median(f)
}

func round(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*1000) / 1000
}
