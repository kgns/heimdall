package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/catalog"
	"github.com/kgns/heimdall/probe/internal/collectors/flows"
	"github.com/kgns/heimdall/probe/internal/collectors/lan"
	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// flowSampler turns the flows of LAN clients into samples.
type flowSampler struct {
	coll       *collectors
	cfg        config.Flows
	classifier *flows.Classifier
	fc         *flows.Collector
	now        func() time.Time

	// node is set on a bridge (an extender): every client whose
	// connections pass it is attached to it, on the bridge port its
	// frames arrive on.
	node string

	mu          sync.Mutex
	windowStart time.Time
	inWindow    int
	emitted     uint64
	capped      uint64

	portMu  sync.Mutex
	ports   map[string]string
	portsAt time.Time
}

// portsTTL is how long the bridge's forwarding table is reused.
const portsTTL = 10 * time.Second

// gatewayMAC returns the default gateway's MAC address from the ARP
// table.
func (c *collectors) gatewayMAC() (net.HardwareAddr, error) {
	gw := c.nw.Current().Gateway
	if !gw.IsValid() {
		return nil, fmt.Errorf("no default gateway")
	}
	arp, err := lan.ReadARP(c.fs)
	if err != nil {
		return nil, err
	}
	for _, e := range arp {
		if e.IP == gw {
			return e.MAC, nil
		}
	}
	return nil, fmt.Errorf("gateway %s is not in the ARP table", gw)
}

// port returns the bridge member a client's frames arrive on, from the
// bridge's forwarding table, re-read at most every few seconds.
func (fs *flowSampler) port(mac net.HardwareAddr) string {
	fs.portMu.Lock()
	defer fs.portMu.Unlock()
	if now := fs.now(); fs.ports == nil || now.Sub(fs.portsAt) > portsTTL {
		fs.ports, fs.portsAt = lan.PortOf(fs.coll.fs, fs.cfg.Interface), now
	}
	return fs.ports[mac.String()]
}

// startFlows opens the capture and runs the flow collector until ctx is
// done. It returns nil when the collector is off.
func (c *collectors) startFlows(ctx context.Context) (*flowSampler, error) {
	fcfg := c.cfg.Collectors.Flows
	if !fcfg.Enabled {
		return nil, nil
	}
	ifi, err := net.InterfaceByName(fcfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("flows: %w", err)
	}
	// upstream is the address answers from servers come from: the CPE's
	// own bridge on the CPE, the gateway's on an extender.
	upstream := ifi.HardwareAddr
	bridge := fcfg.Position == config.PositionBridge
	if bridge {
		if upstream, err = c.gatewayMAC(); err != nil {
			return nil, fmt.Errorf("flows: %w", err)
		}
	}
	filter, err := flows.Filter(upstream)
	if err != nil {
		return nil, fmt.Errorf("flows: %w", err)
	}
	var capt flows.Capture
	if bridge {
		capt, err = flows.OpenBridgeCapture(fcfg.Interface, filter, int(fcfg.ReceiveBuffer))
	} else {
		capt, err = flows.OpenCapture(fcfg.Interface, filter, int(fcfg.ReceiveBuffer))
	}
	if err != nil {
		return nil, fmt.Errorf("flows: %w", err)
	}
	fs := &flowSampler{coll: c, cfg: fcfg, classifier: c.flowClassifier(), now: time.Now}
	if bridge {
		fs.node = c.cfg.Collectors.WiFi.Node
		c.lanMu.Lock()
		c.bridgeNode, c.bridgePorts = fs.node, map[string]string{}
		c.lanMu.Unlock()
	}
	opt := flows.DefaultTrackerOptions()
	opt.Local = newLocalAddrs(fcfg.Interface).contains
	fs.fc = flows.NewCollector(capt, upstream, opt, fs.emit)
	go func() {
		if err := fs.fc.Run(ctx); err != nil {
			c.log.Warn("flow capture stopped", "err", err)
		}
	}()
	return fs, nil
}

// flowClassifier builds service rules from the whole catalog, including
// services that are not measured, so that more connections get a name.
func (c *collectors) flowClassifier() *flows.Classifier {
	cat := c.cfg.Catalog
	if cat.Path == "" {
		return nil
	}
	services, err := catalog.Load(cat.Path, cat.Regions)
	if err != nil {
		c.log.Warn("flows: catalog not loaded; connections stay unnamed", "err", err)
		return nil
	}
	byID := map[string]catalog.Service{}
	for _, s := range services {
		byID[s.ID] = s
	}
	var rules []flows.Rule
	for id, domains := range catalog.Domains(services) {
		for _, d := range domains {
			rules = append(rules, flows.Rule{Domain: d, Service: id, Category: byID[id].Category})
		}
	}
	return flows.NewClassifier(rules)
}

// Stats returns the counters reported with the probe's self metrics.
func (fs *flowSampler) Stats() map[string]any {
	if fs == nil {
		return nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return map[string]any{"capture": fs.fc.Stats(), "emitted": fs.emitted, "capped": fs.capped}
}

func (fs *flowSampler) allow() bool {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	now := fs.now()
	if now.Sub(fs.windowStart) >= time.Minute {
		fs.windowStart, fs.inWindow = now, 0
	}
	if fs.inWindow >= fs.cfg.MaxPerMinute {
		fs.capped++
		return false
	}
	fs.inWindow++
	fs.emitted++
	return true
}

func (fs *flowSampler) emit(f flows.Flow) {
	if !fs.allow() {
		return
	}
	fs.coll.rec.Emit(fs.sample(f))
}

func (fs *flowSampler) sample(f flows.Flow) sample.Sample {
	id := fs.coll.hasher.ID(f.ClientMAC)
	s := sample.Sample{
		TS: f.Start.UnixMilli(), Kind: sample.KindFlow, TargetID: "flow/" + id,
		Category: "unclassified", Service: "other", Status: sample.Status(f.Status),
	}
	x := map[string]any{"proto": f.Proto, "client": id, "ipv": 4}
	if f.Client.Addr().Is6() && !f.Client.Addr().Is4In6() {
		x["ipv"] = 6
	}
	if f.Name != "" {
		x["name_src"] = f.NameSource
		if r, ok := fs.classifier.Classify(f.Name); ok {
			s.Category, s.Service = r.Category, r.Service
		}
	}
	if fs.cfg.Names == config.FlowNamesCategory {
		s.Service = ""
	}
	if fs.cfg.Names == config.FlowNamesRaw {
		s.DstIP, s.DstPort = f.Server.Addr().String(), int(f.Server.Port())
		x["client_ip"], x["client_port"] = f.Client.Addr().String(), int(f.Client.Port())
		if f.Name != "" {
			x["name"] = f.Name
		}
	}
	if f.HasWAN {
		x["wan_ms"] = sample.Millis(f.WAN)
	}
	if f.HasLAN {
		x["lan_ms"] = sample.Millis(f.LAN)
		if f.HasWAN {
			s.RTTms = sample.RTT(f.WAN + f.LAN)
		}
	}
	if f.Proto == "quic" && f.HasLAN {
		x["lan_min_ms"] = sample.Millis(f.LANMin)
	}
	if f.ClientRetx > 0 {
		x["client_retx"] = f.ClientRetx
	}
	if f.ServerRetx > 0 {
		x["server_retx"] = f.ServerRetx
	}
	if f.LANFromData {
		x["lan_from_data"] = true
	}
	if f.SNI != "" {
		x["sni"] = f.SNI
	}
	if fs.node != "" {
		if p := fs.port(f.ClientMAC); p != "" {
			fs.coll.notePort(id, p)
		}
	}
	for k, v := range fs.coll.clientContext(id) {
		x[k] = v
	}
	s.Extra = x
	return s
}

// maxBridgePorts bounds the clients whose bridge port is remembered.
const maxBridgePorts = 512

// notePort records the bridge member a client's connection arrived on, so
// that the detector's client context knows it too.
func (c *collectors) notePort(id, port string) {
	c.lanMu.Lock()
	defer c.lanMu.Unlock()
	if c.bridgePorts == nil {
		return
	}
	if _, ok := c.bridgePorts[id]; !ok && len(c.bridgePorts) >= maxBridgePorts {
		clear(c.bridgePorts)
	}
	c.bridgePorts[id] = port
}

// clientContext describes where a LAN client is attached, for the samples
// about it.
func (c *collectors) clientContext(id string) map[string]any {
	x := map[string]any{}
	c.lanMu.Lock()
	if cl, ok := c.lanClients[id]; ok && cl.Port != "" {
		x["port"], x["medium"] = cl.Port, cl.Medium
	}
	if n, ok := c.names[id]; ok {
		x["client_name"] = n
	}
	if c.bridgeNode != "" {
		x["node"] = c.bridgeNode
		if p := c.bridgePorts[id]; p != "" {
			x["port"] = p
			if _, ok := x["medium"]; !ok {
				x["medium"] = lan.Medium(p)
			}
		}
	}
	c.lanMu.Unlock()
	if c.wifi != nil {
		for k, v := range c.wifi.ClientContext(id) {
			x[k] = v
		}
	}
	return x
}

// localAddrs tells LAN and CPE addresses from internet servers. The
// interface addresses are re-read once a minute, since the WAN address
// and the delegated IPv6 prefix can change.
type localAddrs struct {
	iface string

	mu       sync.Mutex
	readAt   time.Time
	own      map[netip.Addr]bool
	prefixes []netip.Prefix
}

func newLocalAddrs(iface string) *localAddrs { return &localAddrs{iface: iface} }

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func (l *localAddrs) contains(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.Is4() && cgnatPrefix.Contains(a) {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.readAt) > time.Minute {
		l.refresh()
	}
	if l.own[a] {
		return true
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (l *localAddrs) refresh() {
	l.readAt = time.Now()
	l.own = map[netip.Addr]bool{}
	l.prefixes = nil
	ifs, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			a, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			l.own[a] = true
			if ifi.Name == l.iface {
				ones, _ := ipn.Mask.Size()
				l.prefixes = append(l.prefixes, netip.PrefixFrom(a, ones).Masked())
			}
		}
	}
}
