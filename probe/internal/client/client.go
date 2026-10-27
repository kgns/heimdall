// Package client measures from a LAN client, for comparison with what the
// CPE measures passively about the same client: the round trip to the CPE
// itself, TCP connection setup to internet services, and the client's own
// view of its Wi-Fi link. Every TCP connection the client opens passes the
// CPE, whose flow collector splits it into LAN and WAN parts; the client
// reports its local address and port so the two records can be matched.
package client

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/probes/neterr"
	"github.com/kgns/heimdall/probe/internal/sample"
)

// Target is an internet service the client connects to.
type Target struct {
	Service  string
	Category string
	Host     string
	Port     int
}

// DefaultTargets mirror services the CPE measures, so client and CPE
// numbers can be compared directly.
func DefaultTargets() []Target {
	return []Target{
		{Service: "aws-reflector", Category: "infra", Host: "reflector.lat.kgns.dev", Port: 443},
		{Service: "google", Category: "browsing", Host: "www.google.com", Port: 443},
		{Service: "cloudflare", Category: "browsing", Host: "www.cloudflare.com", Port: 443},
		{Service: "youtube", Category: "streaming", Host: "www.youtube.com", Port: 443},
		{Service: "netflix", Category: "streaming", Host: "www.netflix.com", Port: 443},
		{Service: "github", Category: "cloud_work", Host: "github.com", Port: 443},
		{Service: "discord", Category: "voice", Host: "gateway.discord.gg", Port: 443},
		{Service: "steam", Category: "gaming", Host: "store.steampowered.com", Port: 443},
		{Service: "hurriyet", Category: "browsing", Host: "www.hurriyet.com.tr", Port: 443},
		{Service: "aws-eu-central-1", Category: "cloud_work", Host: "dynamodb.eu-central-1.amazonaws.com", Port: 443},
	}
}

// WiFiInfo is the client's view of its Wi-Fi link.
type WiFiInfo struct {
	Iface      string
	Connected  bool
	RSSI       int
	Noise      int
	Channel    int
	Band       string
	WidthMHz   int
	PHYMode    string
	TxRateMbps float64
	MCS        int
	HasMCS     bool
}

// Options configure a Client.
type Options struct {
	Targets      []Target
	Interval     time.Duration // TCP connects to each target
	PingInterval time.Duration // ICMP and TCP to the CPE
	WiFiInterval time.Duration
	Timeout      time.Duration
	Emit         func(sample.Sample)
	Lookup       func(ctx context.Context, host string) ([]netip.Addr, error)
	Gateway      func() (netip.Addr, error)
	// Pinger may be nil when ICMP sockets are not available.
	Pinger *icmp.Pinger
	// WiFi may be nil on platforms without a Wi-Fi reader.
	WiFi func(ctx context.Context) (WiFiInfo, error)
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client runs the measurement loops.
type Client struct {
	opt Options

	mu    sync.Mutex
	addrs map[string][]netip.Addr
}

// New returns a client.
func New(opt Options) *Client {
	if opt.Dial == nil {
		var d net.Dialer
		opt.Dial = d.DialContext
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 3 * time.Second
	}
	return &Client{opt: opt, addrs: map[string][]netip.Addr{}}
}

// gatewayPorts are tried in turn for TCP to the CPE: dnsmasq answers DNS
// over TCP on most CPEs, and the web interface on the others.
var gatewayPorts = []int{53, 80, 443}

// Run measures until ctx is done.
func (c *Client) Run(ctx context.Context) {
	var wg sync.WaitGroup
	run := func(f func(context.Context)) {
		wg.Add(1)
		go func() { defer wg.Done(); f(ctx) }()
	}
	c.resolveAll(ctx)
	run(c.gatewayLoop)
	run(c.targetLoop)
	run(func(ctx context.Context) {
		every(ctx, 5*time.Minute, func() { c.resolveAll(ctx) })
	})
	if c.opt.WiFi != nil && c.opt.WiFiInterval > 0 {
		run(func(ctx context.Context) {
			c.wifi(ctx)
			every(ctx, c.opt.WiFiInterval, func() { c.wifi(ctx) })
		})
	}
	wg.Wait()
}

// stopping reports whether ctx is done or past its deadline. A dial can
// fail on the deadline a moment before the context itself is cancelled;
// such results are artefacts of stopping, not measurements.
func stopping(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	dl, ok := ctx.Deadline()
	return ok && !time.Now().Before(dl)
}

func every(ctx context.Context, d time.Duration, f func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

func (c *Client) resolveAll(ctx context.Context) {
	for _, t := range c.opt.Targets {
		lctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
		addrs, err := c.opt.Lookup(lctx, t.Host)
		cancel()
		if err != nil {
			continue
		}
		var v4 []netip.Addr
		for _, a := range addrs {
			if a.Is4() {
				v4 = append(v4, a)
			}
		}
		if len(v4) > 0 {
			c.mu.Lock()
			c.addrs[t.Host] = v4
			c.mu.Unlock()
		}
	}
}

func (c *Client) gatewayLoop(ctx context.Context) {
	port := 0
	step := func() {
		gw, err := c.opt.Gateway()
		if err != nil || !gw.IsValid() {
			return
		}
		if c.opt.Pinger != nil {
			r := c.opt.Pinger.Ping(ctx, gw, 0, c.opt.Timeout)
			if r.Status != "" && !stopping(ctx) {
				s := sample.Sample{TS: r.Sent.UnixMilli(), Kind: sample.KindICMP, Category: "home", Service: "cpe",
					TargetID: "client/gateway", DstIP: gw.String(), Status: r.Status, Extra: map[string]any{"via": "client"}}
				if r.Status == sample.StatusOK {
					s.RTTms = sample.RTT(r.RTT)
				}
				c.opt.Emit(s)
			}
		}
		if port == 0 {
			for _, p := range gatewayPorts {
				if res := c.connect(ctx, netip.AddrPortFrom(gw, uint16(p))); res.status == sample.StatusOK {
					port = p
					break
				}
			}
			if port == 0 {
				return
			}
		}
		res := c.connect(ctx, netip.AddrPortFrom(gw, uint16(port)))
		if stopping(ctx) {
			return
		}
		c.opt.Emit(res.sample("client/gateway-tcp", "home", "cpe", ""))
	}
	step()
	every(ctx, c.opt.PingInterval, step)
}

func (c *Client) targetLoop(ctx context.Context) {
	if len(c.opt.Targets) == 0 {
		return
	}
	// Spread the targets over the interval instead of bursting them.
	gap := c.opt.Interval / time.Duration(len(c.opt.Targets))
	i := rand.IntN(len(c.opt.Targets))
	every(ctx, gap, func() {
		t := c.opt.Targets[i%len(c.opt.Targets)]
		i++
		c.mu.Lock()
		addrs := c.addrs[t.Host]
		c.mu.Unlock()
		if len(addrs) == 0 {
			return
		}
		res := c.connect(ctx, netip.AddrPortFrom(addrs[0], uint16(t.Port)))
		if stopping(ctx) {
			return
		}
		c.opt.Emit(res.sample("client/"+t.Service+"/"+t.Host, t.Category, t.Service, t.Host))
	})
}

type connectResult struct {
	sent   time.Time
	rtt    time.Duration
	status sample.Status
	reason string
	dst    netip.AddrPort
	local  netip.AddrPort
}

// connect opens a TCP connection and resets it at once, like the CPE's own
// TCP probe, and keeps the local address for matching with the CPE's flow.
func (c *Client) connect(ctx context.Context, dst netip.AddrPort) connectResult {
	ctx, cancel := context.WithTimeout(ctx, c.opt.Timeout)
	defer cancel()
	r := connectResult{sent: time.Now(), dst: dst}
	conn, err := c.opt.Dial(ctx, "tcp4", dst.String())
	r.rtt = time.Since(r.sent)
	if err != nil {
		r.status, r.reason = neterr.Classify(err)
		return r
	}
	if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		r.local = la.AddrPort()
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	conn.Close()
	r.status = sample.StatusOK
	return r
}

func (r connectResult) sample(id, category, service, host string) sample.Sample {
	s := sample.Sample{TS: r.sent.UnixMilli(), Kind: sample.KindTCP, Category: category, Service: service,
		TargetID: id, DstIP: r.dst.Addr().String(), DstPort: int(r.dst.Port()), Status: r.status,
		Extra: map[string]any{"via": "client"}}
	if host != "" {
		s.Extra["host"] = host
	}
	if r.local.IsValid() {
		s.Extra["local_ip"], s.Extra["local_port"] = r.local.Addr().Unmap().String(), int(r.local.Port())
	}
	if r.status == sample.StatusOK || r.status == sample.StatusRefused {
		s.RTTms = sample.RTT(r.rtt)
	}
	if r.reason != "" {
		s.Extra["reason"] = r.reason
	}
	return s
}

func (c *Client) wifi(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	w, err := c.opt.WiFi(ctx)
	if err != nil {
		return
	}
	x := map[string]any{"source": "client", "iface": w.Iface, "connected": w.Connected}
	if w.Connected {
		x["rssi"], x["noise"], x["snr"] = w.RSSI, w.Noise, w.RSSI-w.Noise
		x["channel"], x["band"], x["width_mhz"] = w.Channel, w.Band, w.WidthMHz
		x["phy_mode"], x["tx_rate_mbps"] = w.PHYMode, w.TxRateMbps
		if w.HasMCS {
			x["mcs"] = w.MCS
		}
	}
	c.opt.Emit(sample.Sample{Kind: sample.KindWiFiSta, Category: "home", Service: "wifi", TargetID: "client/wifi",
		Status: sample.StatusOK, Extra: x})
}
