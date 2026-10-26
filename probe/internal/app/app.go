// Package app wires configuration, probers, collectors and sinks into a
// running probe.
package app

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/kgns/heimdall/probe/internal/collectors/self"
	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/netwatch"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/resolve"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/scheduler"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
	"github.com/kgns/heimdall/probe/internal/target"
)

// Host is the probe's access to the machine. Tests replace it.
type Host struct {
	FS         fs.FS
	Interface  func(name string) (sysinfo.Interface, error)
	ListenICMP func(mode icmp.Mode) (icmp.Conn, error)
	Hostname   func() (string, error)
	Lookup     resolve.LookupFunc
	Now        func() time.Time
	Stdout     io.Writer
	ExtraSinks []sample.Sink
}

// LiveHost returns a Host for the real machine.
func LiveHost() Host {
	return Host{
		FS:         os.DirFS("/"),
		Interface:  sysinfo.LookupInterface,
		ListenICMP: icmp.Listen,
		Hostname:   os.Hostname,
		Lookup:     resolve.SystemLookup,
		Now:        time.Now,
		Stdout:     os.Stdout,
	}
}

// Run starts the probe and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg config.Config, version string, h Host, log *slog.Logger) error {
	started := h.Now()
	device := cfg.Device
	if device == "" {
		hn, err := h.Hostname()
		if err != nil {
			return fmt.Errorf("device is not configured and hostname is unavailable: %w", err)
		}
		device = config.DeviceFromHostname(hn)
	}

	sinks := append([]sample.Sink(nil), h.ExtraSinks...)
	if cfg.Output.Stdout {
		sinks = append(sinks, sample.NewStreamSink(h.Stdout))
	}
	if j := cfg.Output.JSONL; j.Enabled {
		rf, err := sample.NewRotatingFile(j.Dir, "samples.jsonl", int64(j.MaxFileSize), j.MaxFiles, h.Now)
		if err != nil {
			return fmt.Errorf("local sample file: %w", err)
		}
		sinks = append(sinks, rf)
	}
	rec := sample.NewRecorder(device, h.Now, sinks...)
	defer rec.Close()

	conn, err := h.ListenICMP(icmp.Mode(cfg.ICMP.Mode))
	if err != nil {
		return fmt.Errorf("ICMP socket: %w", err)
	}
	pinger, err := icmp.New(conn, icmp.Options{PayloadSize: cfg.ICMP.PayloadSize, Now: h.Now})
	if err != nil {
		conn.Close()
		return err
	}
	defer pinger.Close()

	targets := make([]*target.Target, 0, len(cfg.Targets))
	for _, tc := range cfg.Targets {
		var dst netip.Addr
		if tc.IP != "" {
			dst = netip.MustParseAddr(tc.IP)
		}
		t := target.New(tc.ID, tc.Category, tc.Service, dst)
		t.Auto = tc.Auto
		t.Host = tc.Host
		t.TTL = tc.TTL
		t.Interval = cfg.TargetInterval(tc)
		if t.TTL > 0 && pinger.Mode() != icmp.ModeRaw {
			// Datagram ICMP sockets do not deliver time exceeded errors.
			log.Warn("TTL-limited target needs a raw ICMP socket; skipping", "target", t.ID, "icmp_mode", pinger.Mode())
			rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
				Category: t.Category, Service: t.Service,
				Extra: map[string]any{"event": "target_unsupported", "reason": "ttl needs raw icmp", "icmp_mode": string(pinger.Mode())}})
			continue
		}
		targets = append(targets, t)
	}

	nw := netwatch.New(h.FS, h.Interface, targets, rec.Emit, log)
	wan, err := nw.Refresh()
	if err != nil {
		log.Warn("initial network refresh failed", "err", err)
	}

	var hostTargets []*target.Target
	for _, t := range targets {
		if t.Host != "" {
			hostTargets = append(hostTargets, t)
		}
	}
	res := resolve.New(h.Lookup, nw.Allowed, rec.Emit, log, cfg.Catalog.ResolveTimeout)
	if len(hostTargets) > 0 {
		start := time.Now()
		res.RefreshAll(ctx, hostTargets, 4)
		resolved := 0
		for _, t := range hostTargets {
			if t.Addr().IsValid() {
				resolved++
			}
		}
		log.Info("hostnames resolved", "resolved", resolved, "total", len(hostTargets), "took", time.Since(start).Round(time.Millisecond))
	}

	sched := scheduler.New(scheduler.NewLimiter(cfg.Scheduler.MaxPPS, cfg.Scheduler.Burst, nil), uint64(h.Now().UnixNano()))
	for _, t := range hostTargets {
		sched.Add(scheduler.Job{
			Name:     "resolve/" + t.ID,
			Interval: cfg.Catalog.ResolveInterval,
			Run:      func(ctx context.Context) { res.Refresh(ctx, t) },
		})
	}
	timeout := cfg.ICMP.Timeout
	for _, t := range targets {
		sched.Add(scheduler.Job{
			Name:        "icmp/" + t.ID,
			Interval:    t.Interval,
			Budgeted:    true,
			MaxInFlight: int(math.Ceil(float64(timeout)/float64(t.Interval))) + 1,
			Run: func(ctx context.Context) {
				dst, ok := t.Dst()
				if !ok {
					return
				}
				r := pinger.Ping(ctx, dst, t.TTL, timeout)
				if r.Status == "" {
					return
				}
				s := icmpSample(t, dst, r)
				if t.TTL > 0 && s.Status == sample.StatusOK {
					if prev, changed := t.ObserveHop(r.From); changed {
						log.Info("hop changed", "target", t.ID, "ttl", t.TTL, "from", prev, "to", r.From)
						rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
							Category: t.Category, Service: t.Service, DstIP: r.From.String(),
							Extra: map[string]any{"event": "hop_change", "ttl": t.TTL, "via": dst.String(), "prev": prev.String()}})
					}
				}
				rec.Emit(s)
			},
		})
	}
	sched.Add(scheduler.Job{
		Name:     "netwatch",
		Interval: cfg.NetWatch.Interval,
		NoJitter: false,
		Run: func(context.Context) {
			if _, err := nw.Refresh(); err != nil {
				log.Warn("network refresh failed", "err", err)
			}
		},
	})
	selfc := self.New(h.FS, h.Now, func() map[string]any {
		return map[string]any{
			"icmp":          pinger.Stats(),
			"sched":         sched.Totals(),
			"samples":       rec.Emitted(),
			"write_errors":  rec.WriteErrors(),
			"targets_total": len(targets),
		}
	})
	sched.Add(scheduler.Job{
		Name:     "self",
		Interval: cfg.SelfMetrics.Interval,
		NoJitter: true,
		Run:      func(context.Context) { rec.Emit(selfc.Collect()) },
	})

	rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Extra: map[string]any{
		"event":        "start",
		"version":      version,
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
		"icmp_mode":    string(pinger.Mode()),
		"targets":      len(targets),
		"host_targets": len(hostTargets),
		"regions":      cfg.Catalog.Regions,
		"probe_rate":   cfg.ProbeRate(),
		"wan_iface":    wan.Iface,
		"gateway":      addrString(wan.Gateway),
		"wan_ipv4":     addrStrings(wan.WANIPv4),
	}})
	log.Info("probe started", "device", device, "version", version, "icmp_mode", pinger.Mode(),
		"targets", len(targets), "probe_rate", cfg.ProbeRate(), "wan_iface", wan.Iface, "gateway", wan.Gateway)

	sched.Run(ctx)

	rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Extra: map[string]any{
		"event":    "stop",
		"uptime_s": int64(h.Now().Sub(started).Seconds()),
		"icmp":     pinger.Stats(),
		"sched":    sched.Stats(),
	}})
	log.Info("probe stopped", "samples", rec.Emitted())
	return nil
}

func icmpSample(t *target.Target, dst netip.Addr, r icmp.Result) sample.Sample {
	s := sample.Sample{
		TS:       r.Sent.UnixMilli(),
		Kind:     sample.KindICMP,
		Category: t.Category,
		Service:  t.Service,
		TargetID: t.ID,
		DstIP:    dst.String(),
		Status:   r.Status,
	}
	if t.TTL > 0 {
		return hopSample(s, t, dst, r)
	}
	x := map[string]any{}
	switch r.Status {
	case sample.StatusOK:
		s.RTTms = sample.RTT(r.RTT)
		if r.TTL >= 0 {
			x["ttl"] = r.TTL
		}
	case sample.StatusUnreachable, sample.StatusTimeExceeded:
		x["from"] = r.From.String()
		x["icmp_type"] = r.ICMPType
		x["icmp_code"] = r.ICMPCode
		x["after_ms"] = sample.Millis(r.RTT)
	case sample.StatusError:
		if r.Err != nil {
			x["error"] = r.Err.Error()
		}
	}
	if len(x) > 0 {
		s.Extra = x
	}
	return s
}

// hopSample describes a TTL-limited probe. The measured router is the one
// that sent time exceeded, so it becomes dst_ip and the address the probe
// was sent towards is kept as "via". An echo reply means the destination
// is closer than the TTL, which is reported as an error.
func hopSample(s sample.Sample, t *target.Target, via netip.Addr, r icmp.Result) sample.Sample {
	x := map[string]any{"ttl_limit": t.TTL, "via": via.String()}
	s.Extra = x
	switch r.Status {
	case sample.StatusTimeExceeded:
		s.Status = sample.StatusOK
		s.DstIP = r.From.String()
		s.RTTms = sample.RTT(r.RTT)
		if r.TTL >= 0 {
			x["ttl"] = r.TTL
		}
	case sample.StatusOK:
		s.Status = sample.StatusError
		x["error"] = "destination reached before the TTL expired"
	case sample.StatusUnreachable:
		x["from"] = r.From.String()
		x["icmp_type"] = r.ICMPType
		x["icmp_code"] = r.ICMPCode
	case sample.StatusError:
		if r.Err != nil {
			x["error"] = r.Err.Error()
		}
	}
	if s.Status != sample.StatusOK {
		s.DstIP = ""
	}
	return s
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func addrStrings(as []netip.Addr) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.String()
	}
	return out
}
