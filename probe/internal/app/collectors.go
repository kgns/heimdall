package app

import (
	"context"
	"io/fs"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kgns/heimdall/probe/internal/collectors/clock"
	"github.com/kgns/heimdall/probe/internal/collectors/hoststat"
	"github.com/kgns/heimdall/probe/internal/collectors/lan"
	"github.com/kgns/heimdall/probe/internal/collectors/procwatch"
	"github.com/kgns/heimdall/probe/internal/collectors/wifi"
	"github.com/kgns/heimdall/probe/internal/netwatch"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/resolve"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/scheduler"
)

// collectors produces the context samples recorded next to the
// measurements.
type collectors struct {
	*env
	fs     fs.FS
	nw     *netwatch.Watcher
	lookup resolve.LookupFunc

	// clockOffset is the last measured offset of the local clock in
	// nanoseconds; hasOffset is set once one was measured.
	clockOffset atomic.Int64
	hasOffset   atomic.Bool
	ntpPort     uint16

	lanMu      sync.Mutex
	lanClients map[string]*lanClient
	leaseFile  string
	hasher     lan.Hasher

	// wifi adds where a client is attached on Wi-Fi; nil when the Wi-Fi
	// collector is off.
	wifi     clientContexter
	wifiColl *wifi.Collector
}

type clientContexter interface {
	ClientContext(id string) map[string]any
}

type lanClient struct {
	lan.Client
	misses int
}

func newCollectors(e *env, fsys fs.FS, nw *netwatch.Watcher, lookup resolve.LookupFunc, leaseFile string) *collectors {
	c := &collectors{env: e, fs: fsys, nw: nw, lookup: lookup, lanClients: map[string]*lanClient{}, leaseFile: leaseFile, ntpPort: 123}
	co := e.cfg.Collectors
	if co.LAN.Enabled || co.Flows.Enabled || co.WiFi.Interval > 0 {
		salt, err := lan.LoadOrCreateSalt(e.cfg.Collectors.LAN.SaltFile)
		if err != nil {
			e.log.Warn("LAN client IDs", "err", err)
		}
		c.hasher = lan.NewHasher(salt)
	}
	if w := co.WiFi; w.Interval > 0 {
		c.wifiColl = wifi.New(wifi.Options{
			Run: wifi.ExecRunner(w.Command, w.Timeout), FS: fsys, MeshFile: w.MeshFile,
			ID: c.hasher.ID, Emit: e.rec.Emit,
		})
		c.wifi = c.wifiColl
	}
	return c
}

// ClockOffset returns the last measured local clock offset.
func (c *collectors) ClockOffset() time.Duration { return time.Duration(c.clockOffset.Load()) }

// MeasuredClockOffset returns the last offset and whether one was measured.
func (c *collectors) MeasuredClockOffset() (time.Duration, bool) {
	return c.ClockOffset(), c.hasOffset.Load()
}

// LANClients returns the number of LAN clients currently tracked.
func (c *collectors) LANClients() int {
	c.lanMu.Lock()
	defer c.lanMu.Unlock()
	return len(c.lanClients)
}

func (c *collectors) jobs() []scheduler.Job {
	co := c.cfg.Collectors
	var out []scheduler.Job
	if co.WAN.Interval > 0 {
		out = append(out, c.wanJob())
	}
	if co.CPU.Interval > 0 {
		out = append(out, c.cpuJob())
	}
	if co.LAN.Enabled {
		out = append(out,
			scheduler.Job{Name: "lan/discover", Interval: co.LAN.DiscoverInterval, NoJitter: true, Run: func(context.Context) { c.discoverLAN() }},
			scheduler.Job{Name: "lan/ping", Interval: co.LAN.Interval, Budgeted: true, Run: c.pingLAN},
		)
	}
	if c.wifiColl != nil {
		out = append(out, scheduler.Job{Name: "wifi", Interval: co.WiFi.Interval, NoJitter: true, Run: c.wifiColl.Poll})
	}
	if co.Processes.Interval > 0 && len(co.Processes.Names) > 0 {
		out = append(out, c.processJob())
	}
	if co.Clock.Interval > 0 {
		out = append(out, scheduler.Job{Name: "clock", Interval: co.Clock.Interval, Budgeted: true, Run: c.checkClock})
	}
	return out
}

func (c *collectors) wanJob() scheduler.Job {
	var (
		prevIface string
		prev      hoststat.IfCounters
		prevAt    time.Time
	)
	return scheduler.Job{
		Name: "wan", Interval: c.cfg.Collectors.WAN.Interval, NoJitter: true,
		Run: func(context.Context) {
			iface := c.nw.Current().Iface
			if iface == "" {
				prevIface = ""
				return
			}
			all, err := hoststat.ReadNetDev(c.fs)
			now := time.Now()
			if err != nil {
				return
			}
			cur, ok := all[iface]
			if !ok {
				prevIface = ""
				return
			}
			if iface != prevIface {
				prevIface, prev, prevAt = iface, cur, now
				return
			}
			secs := now.Sub(prevAt).Seconds()
			if secs <= 0 {
				return
			}
			rate := func(a, b uint64) float64 { return float64(hoststat.Delta(a, b)) / secs }
			s := sample.Sample{
				TS: now.UnixMilli(), Kind: sample.KindWAN, Category: "infra", Service: "wan",
				TargetID: "wan/" + iface, Status: sample.StatusOK,
				Extra: map[string]any{
					"rx_bps":      rate(prev.RxBytes, cur.RxBytes) * 8,
					"tx_bps":      rate(prev.TxBytes, cur.TxBytes) * 8,
					"rx_pps":      rate(prev.RxPackets, cur.RxPackets),
					"tx_pps":      rate(prev.TxPackets, cur.TxPackets),
					"rx_drop":     hoststat.Delta(prev.RxDrop, cur.RxDrop),
					"tx_drop":     hoststat.Delta(prev.TxDrop, cur.TxDrop),
					"rx_errs":     hoststat.Delta(prev.RxErrs, cur.RxErrs),
					"tx_errs":     hoststat.Delta(prev.TxErrs, cur.TxErrs),
					"interval_ms": sample.Millis(now.Sub(prevAt)),
				},
			}
			prev, prevAt = cur, now
			c.rec.Emit(s)
		},
	}
}

// snmpCounters are the protocol counters reported with each CPU sample.
// Udp.NoPorts counts datagrams to closed ports, such as DNS answers that
// arrive after the asking socket gave up.
var snmpCounters = map[string]string{
	"Udp.NoPorts":          "udp_noports",
	"Udp.InErrors":         "udp_in_errors",
	"Udp.RcvbufErrors":     "udp_rcvbuf_errors",
	"Tcp.RetransSegs":      "tcp_retrans",
	"Icmp.OutDestUnreachs": "icmp_out_unreach",
}

func (c *collectors) cpuJob() scheduler.Job {
	var (
		prev     hoststat.CPUTimes
		prevSNMP hoststat.SNMP
		have     bool
	)
	return scheduler.Job{
		Name: "cpu", Interval: c.cfg.Collectors.CPU.Interval, NoJitter: true,
		Run: func(context.Context) {
			cur, cpus, err := hoststat.ReadCPU(c.fs)
			if err != nil {
				return
			}
			snmp, _ := hoststat.ReadSNMP(c.fs)
			if !have {
				prev, prevSNMP, have = cur, snmp, true
				return
			}
			u, ok := hoststat.Usage(prev, cur)
			if !ok {
				return
			}
			x := map[string]any{
				"busy_pct": u.Busy, "user_pct": u.User, "system_pct": u.System,
				"softirq_pct": u.SoftIRQ, "irq_pct": u.IRQ, "iowait_pct": u.IOWait, "cpus": cpus,
			}
			if l, err := hoststat.ReadLoadAvg(c.fs); err == nil {
				x["load1"] = l
			}
			for k, name := range snmpCounters {
				if v, ok := snmp[k]; ok {
					if p, ok := prevSNMP[k]; ok {
						x[name] = hoststat.Delta(p, v)
					}
				}
			}
			prev, prevSNMP = cur, snmp
			c.rec.Emit(sample.Sample{Kind: sample.KindCPU, Category: "infra", Service: "cpe", TargetID: "cpu", Status: sample.StatusOK, Extra: x})
		},
	}
}

// inLAN reports the interface of a directly connected, non-default route
// for a, which is where LAN clients live.
func (c *collectors) inLAN(a netip.Addr) (string, bool) {
	rt, ok := c.nw.Route(a)
	if !ok || rt.HasGateway() || rt.Dest.Bits() == 0 || rt.Iface == c.nw.Current().Iface {
		return "", false
	}
	return rt.Iface, true
}

func (c *collectors) discoverLAN() {
	l := c.cfg.Collectors.LAN
	found, err := lan.Discover(c.fs, c.leaseFile, l.Interfaces, l.MaxClients, c.hasher, c.inLAN)
	if err != nil {
		c.log.Warn("LAN discovery failed", "err", err)
		return
	}
	seen := map[string]bool{}
	// Events are emitted after the lock is released: the detector reads
	// client context under its own lock, which takes this one.
	var events []sample.Sample
	defer func() {
		for _, ev := range events {
			c.rec.Emit(ev)
		}
	}()
	c.lanMu.Lock()
	defer c.lanMu.Unlock()
	for _, f := range found {
		seen[f.ID] = true
		cur, known := c.lanClients[f.ID]
		if !known {
			c.lanClients[f.ID] = &lanClient{Client: f}
			events = append(events, sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Category: "home", Service: "lan",
				TargetID: "lan/" + f.ID, DstIP: f.IP.String(),
				Extra: map[string]any{"event": "lan_client_seen", "iface": f.Iface, "port": f.Port, "medium": f.Medium}})
			continue
		}
		if cur.Medium != f.Medium && f.Medium != "" {
			events = append(events, sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Category: "home", Service: "lan",
				TargetID: "lan/" + f.ID, DstIP: f.IP.String(),
				Extra: map[string]any{"event": "lan_client_moved", "port": f.Port, "medium": f.Medium, "prev_port": cur.Port, "prev_medium": cur.Medium}})
		}
		cur.Client, cur.misses = f, 0
	}
	for id, cl := range c.lanClients {
		if seen[id] {
			continue
		}
		cl.misses++
		if cl.misses >= l.DisappearAfter {
			delete(c.lanClients, id)
			events = append(events, sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Category: "home", Service: "lan",
				TargetID: "lan/" + id, Extra: map[string]any{"event": "lan_client_gone"}})
		}
	}
}

func (c *collectors) pingLAN(ctx context.Context) {
	c.lanMu.Lock()
	clients := make([]lan.Client, 0, len(c.lanClients))
	for _, cl := range c.lanClients {
		clients = append(clients, cl.Client)
	}
	c.lanMu.Unlock()

	timeout := min(c.cfg.ICMP.Timeout, c.cfg.Collectors.LAN.Interval)
	var wg sync.WaitGroup
	for _, cl := range clients {
		if iface, ok := c.inLAN(cl.IP); !ok || iface != cl.Iface {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := c.pinger.Ping(ctx, cl.IP, 0, timeout)
			if r.Status == "" {
				return
			}
			var burst []any
			if n := c.cfg.Collectors.LAN.Burst; n > 1 {
				// The first answer may have waited for the client to wake;
				// the sample's RTT is the best of the rest.
				first := r
				burst = []any{lanBurstRTT(first)}
				var best icmp.Result
				for i := 1; i < n && ctx.Err() == nil; i++ {
					ri := c.pinger.Ping(ctx, cl.IP, 0, timeout)
					burst = append(burst, lanBurstRTT(ri))
					if ri.Status == sample.StatusOK && (best.Status != sample.StatusOK || ri.RTT < best.RTT) {
						best = ri
					}
				}
				if best.Status == sample.StatusOK {
					best.Sent = first.Sent
					r = best
				}
			}
			s := sample.Sample{
				TS: r.Sent.UnixMilli(), Kind: sample.KindLAN, Category: "home", Service: "lan",
				TargetID: "lan/" + cl.ID, DstIP: cl.IP.String(), Status: r.Status,
				Extra: map[string]any{"iface": cl.Iface},
			}
			if cl.Port != "" {
				s.Extra["port"], s.Extra["medium"] = cl.Port, cl.Medium
			}
			if r.Status == sample.StatusOK {
				s.RTTms = sample.RTT(r.RTT)
			}
			if burst != nil {
				s.Extra["burst_ms"] = burst
			}
			for k, v := range c.wifiContext(cl.ID) {
				s.Extra[k] = v
			}
			c.rec.Emit(s)
		}()
	}
	wg.Wait()
}

// lanBurstRTT is one burst answer in milliseconds, or nil when lost.
func lanBurstRTT(r icmp.Result) any {
	if r.Status != sample.StatusOK {
		return nil
	}
	return sample.Millis(r.RTT)
}

// wifiContext is the Wi-Fi part of a client's context.
func (c *collectors) wifiContext(id string) map[string]any {
	if c.wifi == nil {
		return nil
	}
	return c.wifi.ClientContext(id)
}

func (c *collectors) processJob() scheduler.Job {
	type last struct {
		pid int
		oom uint64
	}
	state := map[string]last{}
	return scheduler.Job{
		Name: "processes", Interval: c.cfg.Collectors.Processes.Interval, NoJitter: true,
		Run: func(context.Context) {
			for _, name := range c.cfg.Collectors.Processes.Names {
				st, err := procwatch.Observe(c.fs, name)
				if err != nil {
					continue
				}
				prev, known := state[name]
				s := sample.Sample{Kind: sample.KindDNSHealth, Category: "infra", Service: "dns", TargetID: "proc/" + name, Status: sample.StatusOK}
				x := map[string]any{"process": name}
				if st.PID == 0 {
					s.Status = sample.StatusError
					x["reason"] = "missing"
					if known && prev.pid != 0 {
						c.log.Warn("process disappeared", "process", name, "pid", prev.pid)
						c.rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Category: "infra", Service: "dns",
							TargetID: s.TargetID, Extra: map[string]any{"event": "process_missing", "process": name, "prev_pid": prev.pid}})
					}
				} else {
					x["pid"], x["rss_kb"] = st.PID, st.RSSkB
					if st.Cgroup != "" {
						x["cgroup"] = st.Cgroup
					}
					if st.HasMem {
						x["mem_usage"], x["mem_peak"], x["oom_events"] = st.MemUsage, st.MemPeak, st.OOMEvents
						if st.MemLimit > 0 {
							x["mem_limit"] = st.MemLimit
						}
						if known && st.OOMEvents > prev.oom {
							x["oom_new"] = st.OOMEvents - prev.oom
						}
					}
					if known && prev.pid != 0 && prev.pid != st.PID {
						c.log.Warn("process restarted", "process", name, "pid", st.PID, "prev_pid", prev.pid)
						c.rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK, Category: "infra", Service: "dns",
							TargetID: s.TargetID, Extra: map[string]any{"event": "process_restart", "process": name, "pid": st.PID, "prev_pid": prev.pid}})
					}
				}
				s.Extra = x
				state[name] = last{pid: st.PID, oom: st.OOMEvents}
				c.rec.Emit(s)
			}
		},
	}
}

func (c *collectors) checkClock(ctx context.Context) {
	cl := c.cfg.Collectors.Clock
	var server netip.Addr
	if a, err := netip.ParseAddr(cl.Server); err == nil {
		server = a
	} else {
		lctx, cancel := context.WithTimeout(ctx, cl.Timeout)
		addrs, err := c.lookup(lctx, cl.Server)
		cancel()
		if err != nil {
			return
		}
		for _, a := range addrs {
			if c.nw.Allowed(a) {
				server = a
				break
			}
		}
	}
	if !server.IsValid() || !c.nw.Allowed(server) {
		return
	}
	r, err := clock.Query(ctx, netip.AddrPortFrom(server, c.ntpPort), cl.Timeout)
	if ctx.Err() != nil {
		return
	}
	s := sample.Sample{
		TS: time.Now().UnixMilli(), Kind: sample.KindClock, Category: "infra", Service: "ntp",
		TargetID: "clock/" + cl.Server, DstIP: server.String(), DstPort: int(c.ntpPort), Status: sample.StatusOK,
	}
	if err != nil {
		s.Status = sample.StatusError
		s.Extra = map[string]any{"error": err.Error()}
		c.rec.Emit(s)
		return
	}
	s.TS = r.Sent.UnixMilli()
	s.RTTms = sample.RTT(r.Delay)
	s.Extra = map[string]any{"offset_ms": sample.Millis(r.Offset), "stratum": r.Stratum, "ref": r.RefID}
	c.clockOffset.Store(int64(r.Offset))
	c.hasOffset.Store(true)
	c.rec.Emit(s)
}
