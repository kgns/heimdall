package selftest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sysinfo"
)

func ex7501Deps(t *testing.T) (Deps, *[]netip.AddrPort) {
	t.Helper()
	var queried []netip.AddrPort
	d := Deps{
		FS:  os.DirFS("../../testdata/hosts/ex7501"),
		Now: func() time.Time { return time.Date(2026, 10, 25, 16, 12, 53, 0, time.UTC) },
		Uname: func() (sysinfo.UnameInfo, error) {
			return sysinfo.UnameInfo{Sysname: "Linux", Nodename: "EX7501-B0", Release: "4.19.183", Machine: "armv8l"}, nil
		},
		Interface: func(name string) (sysinfo.Interface, error) {
			if name != "ppp1.4" {
				return sysinfo.Interface{}, errors.New("no such interface")
			}
			return sysinfo.Interface{Name: name, MTU: 1492, PointToPoint: true, IPv4: []netip.Addr{netip.MustParseAddr("10.234.57.8")}}, nil
		},
		EgressAddr: func(netip.AddrPort) (netip.Addr, error) { return netip.MustParseAddr("10.234.57.8"), nil },
		ICMP: func() sysinfo.ICMPCapability {
			return sysinfo.ICMPCapability{Raw: true, Dgram: false, DgramError: "permission denied"}
		},
		Resolve: func(_ context.Context, server netip.AddrPort, _ string) ([]netip.Addr, error) {
			queried = append(queried, server)
			return []netip.Addr{netip.MustParseAddr("142.250.187.100")}, nil
		},
		UID:         0,
		GID:         0,
		DNSName:     "www.google.com.",
		DNSTimeout:  time.Second,
		EgressProbe: netip.MustParseAddrPort("1.1.1.1:53"),
	}
	return d, &queried
}

func TestRunEX7501(t *testing.T) {
	d, queried := ex7501Deps(t)
	r := Run(context.Background(), "test", d)

	if len(r.Problems) != 0 {
		t.Fatalf("problems: %q", r.Problems)
	}
	if r.DefaultRoute == nil || r.DefaultRoute.Iface != "ppp1.4" || r.DefaultRoute.Gateway != "10.234.0.1" {
		t.Fatalf("default route = %+v", r.DefaultRoute)
	}
	if len(r.SideRoutes) != 1 || r.SideRoutes[0].Dest != "62.58.244.16/29" || r.SideRoutes[0].Iface != "eth5.2" {
		t.Fatalf("side routes = %+v", r.SideRoutes)
	}
	if r.Egress == nil || !r.Egress.OnDefaultIface || !r.Egress.RouteIsDefault {
		t.Fatalf("egress = %+v", r.Egress)
	}
	if r.IPv6.Usable || r.IPv6.DefaultRoute {
		t.Fatalf("ipv6 = %+v", r.IPv6)
	}
	if r.DNS.Source != "dnsmasq" || len(r.DNS.Upstreams) != 1 || r.DNS.Upstreams[0].Addr.String() != "127.0.0.1:5300" {
		t.Fatalf("dns = %+v", r.DNS)
	}
	wantQueried := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:53"),
		netip.MustParseAddrPort("127.0.0.1:5300"),
	}
	if !slices.Equal(*queried, wantQueried) {
		t.Fatalf("queried %v, want %v", *queried, wantQueried)
	}
	if r.ICMPMode != "raw" || r.PingGroup == nil || r.PingGroupOK {
		t.Fatalf("icmp mode %q ping group %+v ok=%v", r.ICMPMode, r.PingGroup, r.PingGroupOK)
	}
	if !containsSubstr(r.Notes, "CGNAT") || !containsSubstr(r.Notes, "excluded from probing") {
		t.Fatalf("notes: %q", r.Notes)
	}

	var text bytes.Buffer
	if err := r.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dev ppp1.4 via 10.234.0.1", "127.0.0.1:5300", "62.58.244.16/29 via 100.90.232.1 dev eth5.2", "result", "OK"} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, text.String())
		}
	}

	var js bytes.Buffer
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(js.Bytes(), &back); err != nil {
		t.Fatalf("json output does not parse: %v", err)
	}
}

func TestRunReportsProblems(t *testing.T) {
	d, _ := ex7501Deps(t)
	d.ICMP = func() sysinfo.ICMPCapability {
		return sysinfo.ICMPCapability{RawError: "operation not permitted", DgramError: "permission denied"}
	}
	d.EgressAddr = func(netip.AddrPort) (netip.Addr, error) { return netip.MustParseAddr("100.90.232.122"), nil }
	d.Resolve = func(context.Context, netip.AddrPort, string) ([]netip.Addr, error) {
		return nil, errors.New("i/o timeout")
	}
	r := Run(context.Background(), "test", d)

	for _, want := range []string{"no ICMP socket", "egress source 100.90.232.122", "DNS lookup via 127.0.0.1:53", "DNS lookup via 127.0.0.1:5300"} {
		if !containsSubstr(r.Problems, want) {
			t.Errorf("problems lack %q: %q", want, r.Problems)
		}
	}
	if r.ICMPMode != "none" {
		t.Fatalf("icmp mode = %q", r.ICMPMode)
	}
}

func TestRunSkipDNS(t *testing.T) {
	d, queried := ex7501Deps(t)
	d.SkipDNS = true
	r := Run(context.Background(), "test", d)
	if len(*queried) != 0 || len(r.DNSChecks) != 0 {
		t.Fatalf("DNS checks ran with SkipDNS")
	}
}

func containsSubstr(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
