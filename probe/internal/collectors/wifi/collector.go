package wifi

import (
	"context"
	"io/fs"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// Runner runs the wl utility with args and returns its standard output.
type Runner func(ctx context.Context, args ...string) ([]byte, error)

// ExecRunner runs command with a timeout per call.
func ExecRunner(command string, timeout time.Duration) Runner {
	return func(ctx context.Context, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return exec.CommandContext(ctx, command, args...).Output()
	}
}

// Execer runs the named command with args and returns its standard
// output.
type Execer func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecCommands runs commands with a timeout per call.
func ExecCommands(timeout time.Duration) Execer {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).Output()
	}
}

// Drivers.
const (
	DriverWL  = "wl"
	DriverMTK = "mtk"
)

// Options configure a Collector.
type Options struct {
	// Driver is DriverWL (the default) or DriverMTK.
	Driver string
	// Run runs wl, for DriverWL.
	Run Runner
	// Exec runs iwpriv and iwconfig, for DriverMTK.
	Exec Execer
	// Node names this access point in client samples, for DriverMTK; the
	// wl driver runs on the CPE, which is always "cpe".
	Node string
	// PortOf returns the bridge member each MAC was learned on, for
	// DriverMTK, which tells which virtual interface a station is on.
	PortOf func() map[string]string
	// FS is the root file system, for sys/class/net and the mesh file.
	FS fs.FS
	// MeshFile is the topology file's path relative to FS, or empty.
	MeshFile string
	// ID turns a MAC into the client ID used in all samples.
	ID   func(net.HardwareAddr) string
	Emit func(sample.Sample)
	Now  func() time.Time
	// MaxStations bounds the stations queried per poll.
	MaxStations int
}

// Collector polls radios and stations. Poll must not run concurrently with
// itself; ClientContext may be called from any goroutine.
type Collector struct {
	opt Options

	prevSta   map[string]StaInfo
	prevMTK   map[string]MTKCounts
	prevRadio map[string]map[string]uint64
	chanspec  map[string]string
	where     map[string]location
	// radioBusy is each radio's channel busy share from the last poll.
	radioBusy map[string]int64
	// lastRoam is when each client last moved between nodes or radios.
	lastRoam map[string]int64

	mu      sync.Mutex
	context map[string]map[string]any
}

// location is where a client was last seen.
type location struct {
	node, iface, band string
}

func (l location) String() string {
	if l.iface != "" {
		return l.node + "/" + l.iface
	}
	return l.node
}

// New returns a collector.
func New(opt Options) *Collector {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.MaxStations <= 0 {
		opt.MaxStations = 64
	}
	if opt.Node == "" {
		opt.Node = cpeNode
	}
	return &Collector{
		opt: opt, prevSta: map[string]StaInfo{}, prevMTK: map[string]MTKCounts{}, prevRadio: map[string]map[string]uint64{},
		chanspec: map[string]string{}, where: map[string]location{}, context: map[string]map[string]any{},
		radioBusy: map[string]int64{}, lastRoam: map[string]int64{},
	}
}

// ClientContext returns what is known about where client id is attached:
// the mesh node, the radio band and the last signal strength.
func (c *Collector) ClientContext(id string) map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	src := c.context[id]
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

var wlIface = regexp.MustCompile(`^wl\d+(\.\d+)?$`)

// Interfaces lists the wl interfaces in sys/class/net.
func Interfaces(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, "sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if wlIface.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// radioOf returns the radio a virtual interface belongs to: wl0.5 is on
// wl0.
func radioOf(iface string) string {
	r, _, _ := strings.Cut(iface, ".")
	return r
}

// cpeNode names the CPE itself in the client context.
const cpeNode = "cpe"

// radioCounters are the `wl counters` fields reported, as deltas.
var radioCounters = []string{"txframe", "txretrans", "txfail", "rxframe", "rxcrc", "d11_txnoack", "rxbadplcp", "txnoassoc"}

// chanimFields are the `wl chanim_stats` columns reported, under
// chanim_<name>.
var chanimFields = []string{"tx", "inbss", "obss", "nocat", "nopkt", "doze", "txop", "goodtx", "badtx", "glitch", "badplcp", "knoise", "idle", "busy"}

// Poll reads every radio and station once and emits their samples.
func (c *Collector) Poll(ctx context.Context) {
	if c.opt.Driver == DriverMTK {
		c.pollMTK(ctx)
		return
	}
	now := c.opt.Now()
	ts := now.UnixMilli()
	type ifInfo struct {
		status   Status
		stations []net.HardwareAddr
	}
	infos := map[string]ifInfo{}
	var ifaces []string
	for _, iface := range Interfaces(c.opt.FS) {
		out, err := c.opt.Run(ctx, "-i", iface, "bss")
		if err != nil || strings.TrimSpace(string(out)) != "up" {
			continue
		}
		var info ifInfo
		if out, err := c.opt.Run(ctx, "-i", iface, "status"); err == nil {
			info.status = ParseStatus(out)
		}
		if out, err := c.opt.Run(ctx, "-i", iface, "assoclist"); err == nil {
			info.stations = ParseAssoclist(out)
		}
		infos[iface] = info
		ifaces = append(ifaces, iface)
	}
	if ctx.Err() != nil {
		return
	}

	now2 := map[string]location{}
	ctxNew := map[string]map[string]any{}
	stationsPerRadio := map[string]int{}
	queried := 0
	for _, iface := range ifaces {
		info := infos[iface]
		radio := radioOf(iface)
		band := info.status.Band
		if band == "" {
			band = infos[radio].status.Band
		}
		for _, mac := range info.stations {
			stationsPerRadio[radio]++
			if queried >= c.opt.MaxStations {
				continue
			}
			queried++
			out, err := c.opt.Run(ctx, "-i", iface, "sta_info", mac.String())
			if err != nil {
				continue
			}
			st := ParseStaInfo(out)
			id := c.opt.ID(mac)
			key := iface + "/" + mac.String()
			x := map[string]any{"client": id, "node": cpeNode, "iface": iface, "band": band, "source": "wl"}
			if st.HasRSSI {
				x["rssi"] = st.RSSI
			}
			if n := maxInt(st.AntennaNoise); n < 0 {
				x["noise"] = n
				if st.HasRSSI {
					x["snr"] = st.RSSI - n
				}
			}
			if st.Chanspec != "" {
				x["chanspec"] = st.Chanspec
			}
			x["tx_rate_mbps"] = float64(st.TxRateKbps) / 1000
			x["rx_rate_mbps"] = float64(st.RxRateKbps) / 1000
			x["idle_s"], x["in_network_s"], x["ps"] = st.IdleS, st.InNetworkS, st.PowerSave
			if st.LinkBandwidthMHz > 0 {
				x["bw_mhz"] = st.LinkBandwidthMHz
			}
			if st.TxNrate != "" {
				x["tx_nrate"] = st.TxNrate
			}
			if prev, ok := c.prevSta[key]; ok && st.InNetworkS >= prev.InNetworkS {
				d := func(name string, cur, old uint64) {
					if cur >= old {
						x[name] = cur - old
					}
				}
				d("tx_pkts", st.TxUcastPkts, prev.TxUcastPkts)
				d("rx_pkts", st.RxUcastPkts, prev.RxUcastPkts)
				d("tx_bytes", st.TxUcastBytes, prev.TxUcastBytes)
				d("rx_bytes", st.RxUcastBytes, prev.RxUcastBytes)
				d("tx_sent", st.TxPktsSent, prev.TxPktsSent)
				d("tx_retries", st.TxRetries, prev.TxRetries)
				d("tx_retry_exhausted", st.TxRetryExhausted, prev.TxRetryExhausted)
				d("tx_failures", st.TxFailures, prev.TxFailures)
				d("rx_retried", st.RxRetried, prev.RxRetried)
				if st.TxPktsSent > prev.TxPktsSent && st.TxRetries >= prev.TxRetries {
					x["retry_pct"] = round1(100 * float64(st.TxRetries-prev.TxRetries) / float64(st.TxPktsSent-prev.TxPktsSent))
				}
			}
			c.prevSta[key] = st
			c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindWiFiSta, Category: "home", Service: "wifi",
				TargetID: "wifi/" + id, Status: sample.StatusOK, Extra: x})
			now2[id] = location{node: cpeNode, iface: iface, band: band}
			cx := map[string]any{"node": cpeNode, "medium": "wifi", "wifi_iface": iface, "band": band, "ps": st.PowerSave,
				"tx_rate_mbps": x["tx_rate_mbps"]}
			if st.HasRSSI {
				cx["rssi"] = st.RSSI
			}
			if v, ok := x["retry_pct"]; ok {
				cx["retry_pct"] = v
			}
			if v, ok := c.radioBusy[radio]; ok {
				cx["radio_busy"] = v
			}
			ctxNew[id] = cx
		}
	}
	for key := range c.prevSta {
		iface, macs, _ := strings.Cut(key, "/")
		mac, _ := net.ParseMAC(macs)
		if _, ok := now2[c.opt.ID(mac)]; !ok || now2[c.opt.ID(mac)].iface != iface {
			delete(c.prevSta, key)
		}
	}

	for _, iface := range ifaces {
		if radioOf(iface) != iface {
			continue
		}
		c.pollRadio(ctx, ts, iface, infos[iface].status, stationsPerRadio[iface])
	}

	meshOK := c.pollMesh(ts, now2, ctxNew)
	c.events(ts, now2, meshOK)
	c.publish(ts, ctxNew)
}

// publish adds the recent roams to the new client contexts and makes them
// current.
func (c *Collector) publish(ts int64, ctxNew map[string]map[string]any) {
	for id, t := range c.lastRoam {
		if ts-t > int64(time.Hour/time.Millisecond) {
			delete(c.lastRoam, id)
			continue
		}
		if cx := ctxNew[id]; cx != nil {
			cx["last_roam_ms"] = t
		}
	}
	c.mu.Lock()
	c.context = ctxNew
	c.mu.Unlock()
}

func (c *Collector) pollRadio(ctx context.Context, ts int64, iface string, st Status, stations int) {
	x := map[string]any{"iface": iface, "band": st.Band, "channel": st.Channel, "stations": stations}
	if st.WidthMHz > 0 {
		x["width_mhz"] = st.WidthMHz
	}
	if st.NoiseDBm < 0 {
		x["noise"] = st.NoiseDBm
	}
	if st.HasQBSSUtil {
		x["qbss_util_pct"] = st.QBSSUtilPct
	}
	if out, err := c.opt.Run(ctx, "-i", iface, "chanim_stats"); err == nil {
		if ch, ok := ParseChanim(out); ok {
			x["chanspec"] = ch.Chanspec
			for _, f := range chanimFields {
				if v, ok := ch.Values[f]; ok {
					x["chanim_"+f] = v
				}
			}
			if v, ok := ch.Values["busy"]; ok {
				c.radioBusy[iface] = v
			}
			if prev, ok := c.chanspec[iface]; ok && prev != ch.Chanspec {
				c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindEvent, Category: "home", Service: "wifi",
					TargetID: "wifi/radio/" + iface, Status: sample.StatusOK,
					Extra: map[string]any{"event": "wifi_channel_change", "iface": iface, "chanspec": ch.Chanspec, "prev_chanspec": prev}})
			}
			c.chanspec[iface] = ch.Chanspec
		}
	}
	if out, err := c.opt.Run(ctx, "-i", iface, "counters"); err == nil {
		cur := ParseCounters(out)
		if prev, ok := c.prevRadio[iface]; ok {
			for _, n := range radioCounters {
				if v, ok := cur[n]; ok && v >= prev[n] {
					x[n] = v - prev[n]
				}
			}
			if tf, ok := x["txframe"].(uint64); ok && tf > 0 {
				if rt, ok := x["txretrans"].(uint64); ok {
					x["retrans_pct"] = round1(100 * float64(rt) / float64(tf))
				}
			}
		}
		c.prevRadio[iface] = cur
	}
	c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindWiFiRadio, Category: "home", Service: "wifi",
		TargetID: "wifi/radio/" + iface, Status: sample.StatusOK, Extra: x})
}

// pollMesh adds the clients of the other mesh nodes. Clients of the CPE
// itself are already measured through wl. It reports whether the
// topology was read.
func (c *Collector) pollMesh(ts int64, where map[string]location, ctxNew map[string]map[string]any) bool {
	if c.opt.MeshFile == "" {
		return false
	}
	b, err := fs.ReadFile(c.opt.FS, strings.TrimPrefix(c.opt.MeshFile, "/"))
	if err != nil {
		return false
	}
	m, err := ParseMesh(b)
	if err != nil {
		return false
	}
	ids := make([]string, 0, len(m.Nodes))
	for id := range m.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := m.Nodes[id]
		name := n.Hostname
		if name == "" {
			name = n.ID
		}
		if n.Mode == "Router" {
			name = cpeNode
		}
		x := map[string]any{"node": name, "hostname": n.Hostname, "node_mode": n.Mode, "ip": n.IP}
		if n.Backhaul != "" {
			x["backhaul"] = n.Backhaul
		}
		if p, ok := m.Nodes[n.Parent]; ok {
			x["parent"] = p.Hostname
			if p.Mode == "Router" {
				x["parent"] = cpeNode
			}
		}
		c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindMeshNode, Category: "home", Service: "wifi",
			TargetID: "mesh/" + name, DstIP: n.IP, Status: sample.StatusOK, Extra: x})
	}
	for _, cl := range m.Clients {
		node, ok := m.Nodes[cl.Node]
		if !ok || node.Mode == "Router" {
			continue
		}
		id := c.opt.ID(cl.MAC)
		name := node.Hostname
		if name == "" {
			name = node.ID
		}
		// The CPE's bridge sees every client of a node on the node's
		// uplink port, so the medium comes from the node instead.
		cx := map[string]any{"node": name, "node_mode": node.Mode, "media": cl.Media, "medium": "wired"}
		if node.Backhaul != "" {
			cx["backhaul"] = node.Backhaul
		}
		if cl.WiFi {
			cx["medium"] = "wifi"
		}
		if !cl.WiFi {
			if _, dup := ctxNew[id]; !dup {
				ctxNew[id] = cx
			}
			continue
		}
		cx["band"] = cl.Band
		if cl.HasRadio {
			cx["rssi"], cx["tx_rate_mbps"] = cl.RSSI, cl.RateMbps
		}
		ctxNew[id] = cx
		where[id] = location{node: name, band: cl.Band}
		x := map[string]any{"client": id, "node": name, "node_mode": node.Mode, "band": cl.Band, "media": cl.Media, "source": "mesh"}
		if node.Backhaul != "" {
			x["backhaul"] = node.Backhaul
		}
		if cl.HasRadio {
			x["rssi"], x["snr"], x["tx_rate_mbps"] = cl.RSSI, cl.SNR, cl.RateMbps
		}
		c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindWiFiSta, Category: "home", Service: "wifi",
			TargetID: "wifi/" + id, Status: sample.StatusOK, Extra: x})
	}
	return true
}

// events reports clients that joined, left or moved between nodes or
// radios since the last poll. Without a topology, mesh clients keep their
// last known place.
func (c *Collector) events(ts int64, now map[string]location, meshOK bool) {
	emit := func(id, event string, x map[string]any) {
		x["event"], x["client"] = event, id
		c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindEvent, Category: "home", Service: "wifi",
			TargetID: "wifi/" + id, Status: sample.StatusOK, Extra: x})
	}
	for id, loc := range now {
		prev, known := c.where[id]
		switch {
		case !known:
			emit(id, "wifi_join", map[string]any{"node": loc.node, "iface": loc.iface, "band": loc.band})
		case prev != loc:
			emit(id, "wifi_roam", map[string]any{"node": loc.node, "iface": loc.iface, "band": loc.band,
				"from": prev.String(), "from_band": prev.band})
			c.lastRoam[id] = ts
		}
	}
	for id, prev := range c.where {
		if _, ok := now[id]; ok {
			continue
		}
		if prev.node != cpeNode && !meshOK {
			now[id] = prev
			continue
		}
		emit(id, "wifi_leave", map[string]any{"node": prev.node, "iface": prev.iface, "band": prev.band})
	}
	c.where = now
}

func maxInt(v []int) int {
	m := 0
	for i, x := range v {
		if i == 0 || x > m {
			m = x
		}
	}
	return m
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
