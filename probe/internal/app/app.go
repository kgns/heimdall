// Package app wires configuration, probers, collectors and sinks into a
// running probe.
package app

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
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
	"github.com/kgns/heimdall/probe/internal/uploader"
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
	// UploadClient replaces the uploader's HTTP client, for tests.
	UploadClient *http.Client
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
	var upBuf *uploader.Buffer
	var token string
	if cfg.Upload.Enabled {
		t, err := readToken(cfg.Upload.TokenFile, log)
		if err != nil {
			return err
		}
		token = t
		upBuf = uploader.NewBuffer(int(cfg.Upload.Buffer))
		sinks = append(sinks, upBuf)
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
	// protocols[i] is the configuration of targets[i].
	protocols := make([]config.Target, 0, len(cfg.Targets))
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
		t.Port = cfg.TargetPort(tc)
		t.Path = tc.Path
		if t.TTL > 0 && pinger.Mode() != icmp.ModeRaw {
			// Datagram ICMP sockets do not deliver time exceeded errors.
			log.Warn("TTL-limited target needs a raw ICMP socket; skipping", "target", t.ID, "icmp_mode", pinger.Mode())
			rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, TargetID: t.ID,
				Category: t.Category, Service: t.Service,
				Extra: map[string]any{"event": "target_unsupported", "reason": "ttl needs raw icmp", "icmp_mode": string(pinger.Mode())}})
			continue
		}
		targets = append(targets, t)
		protocols = append(protocols, tc)
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
	ua := cfg.HTTP.UserAgent
	if ua == "" {
		ua = "heimdall-probe/" + version + " (latency measurement)"
	}
	e := &env{cfg: cfg, rec: rec, pinger: pinger, log: log, userAgent: ua}
	dnsProbes := newDNSProbes(e, h.FS, nw.Allowed)
	defer dnsProbes.close()
	// Learn the resolver identity before the first resolution, so that the
	// initial dst_change events already carry it.
	for _, l := range dnsProbes.identity {
		dnsProbes.probeIdentity(ctx, l)
	}

	res := resolve.New(h.Lookup, nw.Allowed, rec.Emit, log, cfg.Catalog.ResolveTimeout)
	res.ResolverID = dnsProbes.ResolverID
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
	if len(hostTargets) > 0 {
		// Targets that never resolved are retried well before their next
		// regular refresh, so a failed first lookup does not leave them
		// unmeasured for a whole resolve interval.
		sched.Add(scheduler.Job{
			Name:     "resolve/retry",
			Interval: resolveRetryInterval,
			Run: func(ctx context.Context) {
				var pending []*target.Target
				for _, t := range hostTargets {
					if !t.Addr().IsValid() {
						pending = append(pending, t)
					}
				}
				res.RefreshAll(ctx, pending, 2)
			},
		})
	}
	jobCounts := map[string]int{}
	stampers := &stampSenders{}
	defer stampers.close()
	for i, t := range targets {
		tc := protocols[i]
		if tc.Wants(config.ProtoICMP) {
			sched.Add(e.icmpJob(t))
			jobCounts[config.ProtoICMP]++
		}
		if tc.Wants(config.ProtoTCP) {
			sched.Add(e.tcpJob(t))
			jobCounts[config.ProtoTCP]++
		}
		if tc.Wants(config.ProtoHTTP) {
			sched.Add(e.httpJob(t))
			jobCounts[config.ProtoHTTP]++
		}
		if tc.Wants(config.ProtoSTAMP) {
			sched.Add(e.stampJob(t, stampers))
			jobCounts[config.ProtoSTAMP]++
		}
	}
	for _, j := range dnsProbes.jobs() {
		sched.Add(j)
	}
	jobCounts["dns"] = len(dnsProbes.layers) + len(dnsProbes.identity)

	leaseFile := ""
	if cfg.Collectors.LAN.UseLeases {
		if dm, err := sysinfo.DiscoverDnsmasq(h.FS); err == nil && dm != nil {
			leaseFile = dm.LeaseFile
		}
	}
	coll := newCollectors(e, h.FS, nw, h.Lookup, leaseFile)
	if cfg.Collectors.LAN.Enabled {
		coll.discoverLAN()
	}
	for _, j := range coll.jobs() {
		sched.Add(j)
		jobCounts["collectors"]++
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
	var up *uploader.Uploader
	if upBuf != nil {
		up, err = uploader.New(upBuf, uploader.Options{
			URL: cfg.Upload.URL, Token: token, Device: device, ProbeVersion: version,
			Interval: cfg.Upload.Interval, Timeout: cfg.Upload.Timeout,
			MaxBatch: cfg.Upload.MaxBatch, MaxBatchBytes: int(cfg.Upload.MaxBatchBytes),
			MinBackoff: 5 * time.Second, MaxBackoff: 5 * time.Minute,
			ClockOffset: coll.MeasuredClockOffset, Allowed: nw.Allowed, Lookup: h.Lookup,
			HTTPClient: h.UploadClient, Log: log, DrainAfterStop: cfg.Upload.DrainOnStop,
		})
		if err != nil {
			return fmt.Errorf("upload: %w", err)
		}
		sched.Add(scheduler.Job{
			Name: "heartbeat", Interval: cfg.Upload.Heartbeat, NoJitter: true,
			Run: func(context.Context) {
				rec.Emit(sample.Sample{Kind: sample.KindHeartbeat, Status: sample.StatusOK, Extra: map[string]any{
					"version":     version,
					"run_id":      up.RunID(),
					"uptime_s":    int64(h.Now().Sub(started).Seconds()),
					"upload":      up.Status(),
					"buffer":      upBuf.Stats(),
					"resolver_id": dnsProbes.ResolverID(),
					"lan_clients": coll.LANClients(),
				}})
			},
		})
	}
	runID := ""
	if up != nil {
		runID = up.RunID()
	}

	selfc := self.New(h.FS, h.Now, func() map[string]any {
		x := map[string]any{
			"icmp":            pinger.Stats(),
			"sched":           sched.Totals(),
			"samples":         rec.Emitted(),
			"write_errors":    rec.WriteErrors(),
			"targets_total":   len(targets),
			"lan_clients":     coll.LANClients(),
			"clock_offset_ms": sample.Millis(coll.ClockOffset()),
			"resolver_id":     dnsProbes.ResolverID(),
		}
		if up != nil {
			x["upload"], x["buffer"] = up.Status(), upBuf.Stats()
		}
		return x
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
		"jobs":         jobCounts,
		"dns_layers":   dnsLayerIDs(dnsProbes.layers),
		"lan_clients":  coll.LANClients(),
		"resolver_id":  dnsProbes.ResolverID(),
		"regions":      cfg.Catalog.Regions,
		"probe_rate":   cfg.ProbeRate(),
		"wan_iface":    wan.Iface,
		"gateway":      addrString(wan.Gateway),
		"wan_ipv4":     addrStrings(wan.WANIPv4),
		"run_id":       runID,
		"upload":       cfg.Upload.Enabled,
	}})
	log.Info("probe started", "device", device, "version", version, "icmp_mode", pinger.Mode(),
		"targets", len(targets), "jobs", jobCounts, "probe_rate", cfg.ProbeRate(),
		"wan_iface", wan.Iface, "gateway", wan.Gateway, "resolver", dnsProbes.ResolverID(),
		"upload", cfg.Upload.Enabled, "run_id", runID)

	// The uploader outlives the scheduler so that the stop event is sent.
	upCtx, stopUpload := context.WithCancel(context.Background())
	defer stopUpload()
	upDone := make(chan struct{})
	if up != nil {
		go func() {
			defer close(upDone)
			up.Run(upCtx)
		}()
	} else {
		close(upDone)
	}

	sched.Run(ctx)

	rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Extra: map[string]any{
		"event":    "stop",
		"uptime_s": int64(h.Now().Sub(started).Seconds()),
		"icmp":     pinger.Stats(),
		"sched":    sched.Stats(),
	}})
	stopUpload()
	<-upDone
	if up != nil {
		log.Info("probe stopped", "samples", rec.Emitted(), "upload", up.Status(), "unsent", upBuf.Stats().Samples)
	} else {
		log.Info("probe stopped", "samples", rec.Emitted())
	}
	return nil
}

// readToken reads the upload token and warns when the file is readable by
// other users.
func readToken(path string, log *slog.Logger) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("upload token: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		log.Warn("upload token file is readable by other users", "path", path, "mode", st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("upload token: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", fmt.Errorf("upload token file %s is empty", path)
	}
	return t, nil
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

const resolveRetryInterval = 30 * time.Second

func dnsLayerIDs(ls []dnsLayer) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.id
	}
	return out
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
