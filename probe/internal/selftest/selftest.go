// Package selftest gathers the host facts the probe depends on and reports
// problems that would stop it from measuring correctly.
package selftest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kgns/heimdall/probe/internal/sysinfo"
)

// Deps are the host access points used by Run. Tests replace them.
type Deps struct {
	FS          fs.FS
	Now         func() time.Time
	Uname       func() (sysinfo.UnameInfo, error)
	Interface   func(name string) (sysinfo.Interface, error)
	EgressAddr  func(dst netip.AddrPort) (netip.Addr, error)
	ICMP        func() sysinfo.ICMPCapability
	Resolve     func(ctx context.Context, server netip.AddrPort, name string) ([]netip.Addr, error)
	UID, GID    int
	SkipDNS     bool
	DNSName     string
	DNSTimeout  time.Duration
	EgressProbe netip.AddrPort
}

// HostDeps returns Deps wired to the live host.
func HostDeps() Deps {
	return Deps{
		FS:          os.DirFS("/"),
		Now:         time.Now,
		Uname:       sysinfo.Uname,
		Interface:   sysinfo.LookupInterface,
		EgressAddr:  sysinfo.EgressAddr,
		ICMP:        sysinfo.CheckICMPSockets,
		Resolve:     ResolveVia,
		UID:         os.Getuid(),
		GID:         os.Getgid(),
		DNSName:     "www.google.com.",
		DNSTimeout:  3 * time.Second,
		EgressProbe: netip.MustParseAddrPort("1.1.1.1:53"),
	}
}

// Report is the self-test result.
type Report struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	GOARM     string `json:"goarm,omitempty"`
	NumCPU    int    `json:"num_cpu"`
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	TimeUTC   string `json:"time_utc"`

	Kernel       *sysinfo.UnameInfo      `json:"kernel,omitempty"`
	Memory       *sysinfo.MemInfo        `json:"memory,omitempty"`
	DefaultRoute *RouteInfo              `json:"default_route,omitempty"`
	WAN          *sysinfo.Interface      `json:"wan,omitempty"`
	Egress       *EgressInfo             `json:"egress,omitempty"`
	SideRoutes   []RouteInfo             `json:"side_gateway_routes,omitempty"`
	IPv6         IPv6Info                `json:"ipv6"`
	DNS          DNSInfo                 `json:"dns"`
	DNSChecks    []DNSCheck              `json:"dns_checks,omitempty"`
	ICMP         sysinfo.ICMPCapability  `json:"icmp"`
	ICMPMode     string                  `json:"icmp_mode"`
	PingGroup    *sysinfo.PingGroupRange `json:"ping_group_range,omitempty"`
	PingGroupOK  bool                    `json:"ping_group_allows_gid"`
	Problems     []string                `json:"problems,omitempty"`
	Notes        []string                `json:"notes,omitempty"`
}

// RouteInfo is a printable route.
type RouteInfo struct {
	Iface   string `json:"iface"`
	Dest    string `json:"dest"`
	Gateway string `json:"gateway,omitempty"`
	Metric  int    `json:"metric"`
}

// EgressInfo is the source address chosen for outbound traffic.
type EgressInfo struct {
	Probe            string `json:"probe"`
	LocalAddr        string `json:"local_addr"`
	OnDefaultIface   bool   `json:"on_default_iface"`
	RouteIface       string `json:"route_iface,omitempty"`
	RouteIsDefault   bool   `json:"route_is_default"`
	ProbeRouteDetail string `json:"route,omitempty"`
}

// IPv6Info summarises IPv6 reachability.
type IPv6Info struct {
	GlobalAddress bool     `json:"global_address"`
	DefaultRoute  bool     `json:"default_route"`
	DefaultIfaces []string `json:"default_ifaces,omitempty"`
	Usable        bool     `json:"usable"`
}

// DNSInfo describes where the host's DNS queries go.
type DNSInfo struct {
	Source        string              `json:"source"`
	SystemServers []string            `json:"system_servers,omitempty"`
	Dnsmasq       *sysinfo.Dnsmasq    `json:"dnsmasq,omitempty"`
	Upstreams     []sysinfo.DNSServer `json:"upstreams,omitempty"`
}

// DNSCheck is one live lookup through a specific server.
type DNSCheck struct {
	Role    string  `json:"role"`
	Server  string  `json:"server"`
	Name    string  `json:"name"`
	OK      bool    `json:"ok"`
	RTTms   float64 `json:"rtt_ms"`
	Answers int     `json:"answers"`
	Error   string  `json:"error,omitempty"`
}

func routeInfo(r sysinfo.Route) RouteInfo {
	ri := RouteInfo{Iface: r.Iface, Dest: r.Dest.String(), Metric: r.Metric}
	if r.Gateway.IsValid() {
		ri.Gateway = r.Gateway.String()
	}
	return ri
}

// Run gathers the report. It never fails; problems are recorded in the
// report so that a partial result is still printed.
func Run(ctx context.Context, version string, d Deps) Report {
	r := Report{
		Version:   version,
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		GOARM:     buildSetting("GOARM"),
		NumCPU:    runtime.NumCPU(),
		UID:       d.UID,
		GID:       d.GID,
		TimeUTC:   d.Now().UTC().Format(time.RFC3339Nano),
	}
	problem := func(format string, a ...any) { r.Problems = append(r.Problems, fmt.Sprintf(format, a...)) }
	note := func(format string, a ...any) { r.Notes = append(r.Notes, fmt.Sprintf(format, a...)) }

	if u, err := d.Uname(); err == nil {
		r.Kernel = &u
	} else {
		problem("uname: %v", err)
	}

	if m, err := sysinfo.ReadMemInfo(d.FS); err == nil {
		r.Memory = &m
	} else {
		problem("meminfo: %v", err)
	}

	routes, err := sysinfo.ReadRoutes(d.FS)
	if err != nil {
		problem("routes: %v", err)
	}
	def, hasDef := sysinfo.DefaultRoute(routes)
	if hasDef {
		ri := routeInfo(def)
		r.DefaultRoute = &ri
		if !def.Gateway.IsValid() {
			note("default route on %s has no gateway; hop 1 will be discovered by traceroute", def.Iface)
		}
		for _, sr := range sysinfo.SideGatewayRoutes(routes, def) {
			r.SideRoutes = append(r.SideRoutes, routeInfo(sr))
		}
		if len(r.SideRoutes) > 0 {
			note("%d gateway route(s) leave through other interfaces; targets inside them are excluded from probing", len(r.SideRoutes))
		}
		if ifc, err := d.Interface(def.Iface); err == nil {
			r.WAN = &ifc
			for _, a := range ifc.IPv4 {
				if isCGNATOrPrivate(a) {
					note("WAN address %s is private or CGNAT; inbound measurements are not possible", a)
				}
			}
		} else {
			problem("interface %s: %v", def.Iface, err)
		}
	} else {
		problem("no usable IPv4 default route")
	}

	if d.EgressProbe.IsValid() {
		e := &EgressInfo{Probe: d.EgressProbe.Addr().String()}
		if la, err := d.EgressAddr(d.EgressProbe); err == nil {
			e.LocalAddr = la.String()
			if r.WAN != nil {
				for _, a := range r.WAN.IPv4 {
					if a == la {
						e.OnDefaultIface = true
					}
				}
			}
		} else {
			problem("egress address: %v", err)
		}
		if rt, ok := sysinfo.Lookup(routes, d.EgressProbe.Addr()); ok {
			e.RouteIface = rt.Iface
			e.RouteIsDefault = hasDef && rt.Iface == def.Iface && rt.Dest == def.Dest
			e.ProbeRouteDetail = rt.Dest.String() + " dev " + rt.Iface
		}
		if e.LocalAddr != "" && !e.OnDefaultIface {
			problem("egress source %s is not an address of the default interface", e.LocalAddr)
		}
		r.Egress = e
	}

	routes6, err := sysinfo.ReadRoutes6(d.FS)
	if err != nil {
		problem("ipv6 routes: %v", err)
	}
	for _, rt := range sysinfo.DefaultRoutes6(routes6) {
		r.IPv6.DefaultRoute = true
		r.IPv6.DefaultIfaces = append(r.IPv6.DefaultIfaces, rt.Iface)
	}
	r.IPv6.GlobalAddress = r.WAN != nil && len(r.WAN.IPv6Global) > 0
	r.IPv6.Usable = r.IPv6.GlobalAddress && r.IPv6.DefaultRoute
	if !r.IPv6.Usable {
		note("IPv6 not usable on the WAN; IPv6 probes stay disabled")
	}

	r.DNS = discoverDNS(d.FS, problem)

	r.ICMP = d.ICMP()
	r.ICMPMode = r.ICMP.Mode()
	if pg, err := sysinfo.ReadPingGroupRange(d.FS); err == nil {
		r.PingGroup = &pg
		r.PingGroupOK = pg.Allows(uint32(d.GID))
	}
	if r.ICMPMode == "none" {
		problem("no ICMP socket available (raw: %s; dgram: %s); ICMP probes fall back to TCP/UDP", r.ICMP.RawError, r.ICMP.DgramError)
	}

	if !d.SkipDNS {
		r.DNSChecks = runDNSChecks(ctx, d, r.DNS)
		for _, c := range r.DNSChecks {
			if !c.OK {
				problem("DNS lookup via %s (%s) failed: %s", c.Server, c.Role, c.Error)
			}
		}
	}
	return r
}

func discoverDNS(fsys fs.FS, problem func(string, ...any)) DNSInfo {
	var info DNSInfo
	if sys, err := sysinfo.ReadResolvConf(fsys, "/etc/resolv.conf"); err == nil {
		for _, a := range sys {
			info.SystemServers = append(info.SystemServers, a.String())
		}
	} else {
		problem("resolv.conf: %v", err)
	}

	dm, err := sysinfo.DiscoverDnsmasq(fsys)
	if err != nil {
		problem("dnsmasq: %v", err)
	}
	if dm != nil {
		info.Source = "dnsmasq"
		info.Dnsmasq = dm
		info.Upstreams = dm.Upstreams()
		if len(info.Upstreams) == 0 {
			problem("dnsmasq has no default upstream servers")
		}
		return info
	}
	info.Source = "resolv.conf"
	for _, s := range info.SystemServers {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		info.Upstreams = append(info.Upstreams, sysinfo.DNSServer{Addr: netip.AddrPortFrom(a, 53), Origin: "/etc/resolv.conf"})
	}
	return info
}

func runDNSChecks(ctx context.Context, d Deps, info DNSInfo) []DNSCheck {
	type target struct {
		role string
		addr netip.AddrPort
	}
	var targets []target
	seen := map[netip.AddrPort]bool{}
	add := func(role string, ap netip.AddrPort) {
		if !ap.IsValid() || seen[ap] {
			return
		}
		seen[ap] = true
		targets = append(targets, target{role, ap})
	}
	if info.Dnsmasq != nil && info.Dnsmasq.ListenPort > 0 {
		add("local dnsmasq", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(info.Dnsmasq.ListenPort)))
	}
	for _, s := range info.SystemServers {
		if a, err := netip.ParseAddr(s); err == nil {
			add("system resolver", netip.AddrPortFrom(a, 53))
		}
	}
	for _, u := range info.Upstreams {
		add("upstream", u.Addr)
	}

	var out []DNSCheck
	for _, t := range targets {
		c := DNSCheck{Role: t.role, Server: t.addr.String(), Name: d.DNSName}
		cctx, cancel := context.WithTimeout(ctx, d.DNSTimeout)
		start := time.Now()
		addrs, err := d.Resolve(cctx, t.addr, d.DNSName)
		c.RTTms = float64(time.Since(start).Microseconds()) / 1000
		cancel()
		if err != nil {
			c.Error = err.Error()
		} else {
			c.OK = len(addrs) > 0
			c.Answers = len(addrs)
			if !c.OK {
				c.Error = "no answers"
			}
		}
		out = append(out, c)
	}
	return out
}

// ResolveVia looks up IPv4 addresses of name through one specific server.
func ResolveVia(ctx context.Context, server netip.AddrPort, name string) ([]netip.Addr, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, network, server.String())
		},
	}
	return r.LookupNetIP(ctx, "ip4", name)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isCGNATOrPrivate(a netip.Addr) bool {
	return a.IsPrivate() || cgnat.Contains(a)
}

func buildSetting(key string) string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable report.
func (r Report) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	kv := func(k string, v any) { fmt.Fprintf(tw, "%s\t%v\n", k, v) }

	arch := r.GOARCH
	if r.GOARM != "" {
		arch += "/v" + r.GOARM
	}
	kv("heimdall-probe", r.Version+" ("+r.GoVersion+", "+r.GOOS+"/"+arch+")")
	kv("time (UTC)", r.TimeUTC)
	kv("uid/gid", fmt.Sprintf("%d/%d", r.UID, r.GID))
	kv("cpus", r.NumCPU)
	if r.Kernel != nil {
		kv("kernel", r.Kernel.Sysname+" "+r.Kernel.Release+" "+r.Kernel.Machine)
		kv("hostname", r.Kernel.Nodename)
	}
	if r.Memory != nil {
		kv("memory", fmt.Sprintf("total %d MiB, available %d MiB", r.Memory.TotalKB/1024, r.Memory.AvailableKB/1024))
	}
	if r.DefaultRoute != nil {
		gw := r.DefaultRoute.Gateway
		if gw == "" {
			gw = "(none)"
		}
		kv("default route", fmt.Sprintf("dev %s via %s metric %d", r.DefaultRoute.Iface, gw, r.DefaultRoute.Metric))
	}
	if r.WAN != nil {
		kv("wan interface", fmt.Sprintf("%s mtu %d p2p=%t", r.WAN.Name, r.WAN.MTU, r.WAN.PointToPoint))
		kv("wan ipv4", joinAddrs(r.WAN.IPv4))
		kv("wan ipv6 global", joinAddrs(r.WAN.IPv6Global))
	}
	if r.Egress != nil {
		kv("egress", fmt.Sprintf("to %s from %s (default iface: %t, route: %s)", r.Egress.Probe, r.Egress.LocalAddr, r.Egress.OnDefaultIface, r.Egress.ProbeRouteDetail))
	}
	for _, sr := range r.SideRoutes {
		kv("side route (excluded)", fmt.Sprintf("%s via %s dev %s", sr.Dest, sr.Gateway, sr.Iface))
	}
	kv("ipv6", fmt.Sprintf("global address %t, default route %t (%s), usable %t",
		r.IPv6.GlobalAddress, r.IPv6.DefaultRoute, strings.Join(r.IPv6.DefaultIfaces, ","), r.IPv6.Usable))
	kv("dns source", r.DNS.Source)
	kv("dns system servers", strings.Join(r.DNS.SystemServers, ", "))
	if dm := r.DNS.Dnsmasq; dm != nil {
		state := "not running (config only)"
		if dm.Running {
			state = fmt.Sprintf("pid %d: %s", dm.PID, strings.Join(dm.Args, " "))
		}
		kv("dnsmasq", state)
		kv("dnsmasq files", strings.Join(dm.Files, ", "))
		kv("dnsmasq listen port", dm.ListenPort)
		kv("dnsmasq no-resolv", dm.NoResolv)
		if len(dm.ResolvFiles) > 0 {
			kv("dnsmasq resolv-file", strings.Join(dm.ResolvFiles, ", "))
		}
		for _, wmsg := range dm.Warnings {
			kv("dnsmasq warning", wmsg)
		}
	}
	for _, u := range r.DNS.Upstreams {
		kv("dns upstream", fmt.Sprintf("%s  (%s)", u.Addr, u.Origin))
	}
	for _, c := range r.DNSChecks {
		res := fmt.Sprintf("ok %.1f ms, %d answers", c.RTTms, c.Answers)
		if !c.OK {
			res = "FAIL " + c.Error
		}
		kv("dns check "+c.Server, fmt.Sprintf("%s [%s] %s", c.Name, c.Role, res))
	}
	kv("icmp raw", boolOrErr(r.ICMP.Raw, r.ICMP.RawError))
	kv("icmp dgram", boolOrErr(r.ICMP.Dgram, r.ICMP.DgramError))
	if r.PingGroup != nil {
		kv("ping_group_range", fmt.Sprintf("%s (allows gid %d: %t)", r.PingGroup, r.GID, r.PingGroupOK))
	}
	kv("icmp mode", r.ICMPMode)
	for _, n := range r.Notes {
		kv("note", n)
	}
	for _, p := range r.Problems {
		kv("PROBLEM", p)
	}
	if len(r.Problems) == 0 {
		kv("result", "OK")
	} else {
		kv("result", fmt.Sprintf("%d problem(s)", len(r.Problems)))
	}
	return tw.Flush()
}

func joinAddrs(a []netip.Addr) string {
	if len(a) == 0 {
		return "(none)"
	}
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = x.String()
	}
	return strings.Join(s, ", ")
}

func boolOrErr(ok bool, err string) string {
	if ok {
		return "yes"
	}
	return "no (" + err + ")"
}
