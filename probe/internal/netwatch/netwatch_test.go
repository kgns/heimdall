package netwatch

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
	"github.com/kgns/heimdall/probe/internal/target"
)

type events struct {
	mu sync.Mutex
	s  []sample.Sample
}

func (e *events) emit(s sample.Sample) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.s = append(e.s, s)
}

func (e *events) named(name string) []sample.Sample {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []sample.Sample
	for _, s := range e.s {
		if s.Extra["event"] == name {
			out = append(out, s)
		}
	}
	return out
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const routeHeader = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"

func TestRefreshEX7501(t *testing.T) {
	route, err := os.ReadFile("../../testdata/hosts/ex7501/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{"proc/net/route": {Data: route}}
	wanIP := netip.MustParseAddr("10.234.57.8")
	iface := func(string) (sysinfo.Interface, error) {
		return sysinfo.Interface{Name: "ppp1.4", IPv4: []netip.Addr{wanIP}}, nil
	}

	gw := &target.Target{ID: "gateway", Category: "infra", Service: "isp-gateway", Auto: config.AutoGateway}
	cf := target.New("cf", "infra", "cloudflare", netip.MustParseAddr("1.1.1.1"))
	mgmt := target.New("mgmt", "infra", "oops", netip.MustParseAddr("62.58.244.17"))
	ev := &events{}
	w := New(fsys, iface, []*target.Target{gw, cf, mgmt}, ev.emit, quiet())

	st, err := w.Refresh()
	if err != nil {
		t.Fatal(err)
	}
	if st.Iface != "ppp1.4" || st.Gateway != netip.MustParseAddr("10.234.0.1") {
		t.Fatalf("state %+v", st)
	}
	if d, ok := gw.Dst(); !ok || d != st.Gateway {
		t.Fatalf("gateway target %v %v", d, ok)
	}
	if !w.Allowed(netip.MustParseAddr("142.250.1.1")) || w.Allowed(netip.MustParseAddr("62.58.244.20")) {
		t.Fatal("Allowed does not follow the side route")
	}
	if _, ok := cf.Dst(); !ok {
		t.Fatal("public target blocked")
	}
	if _, ok := mgmt.Dst(); ok {
		t.Fatal("management network target not blocked")
	}
	if len(ev.named("target_blocked")) != 1 || len(ev.named("wan_change")) != 0 {
		t.Fatalf("events %+v", ev.s)
	}

	// PPP reconnect: new peer and WAN address.
	fsys["proc/net/route"] = &fstest.MapFile{Data: []byte(routeHeader +
		"ppp1.4\t00000000\t0500EA0A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"ppp1.4\t0500EA0A\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n" +
		"eth5.2\t10F43A3E\t01E85A64\t0003\t0\t0\t0\tF8FFFFFF\t0\t0\t0\n")}
	wanIP = netip.MustParseAddr("10.234.99.1")
	if _, err := w.Refresh(); err != nil {
		t.Fatal(err)
	}
	if d, _ := gw.Dst(); d != netip.MustParseAddr("10.234.0.5") {
		t.Fatalf("gateway not followed: %v", d)
	}
	changes := ev.named("wan_change")
	if len(changes) != 1 || changes[0].Extra["gateway"] != "10.234.0.5" || changes[0].Extra["prev_gateway"] != "10.234.0.1" {
		t.Fatalf("wan_change %+v", changes)
	}

	// Unchanged state emits nothing more.
	w.Refresh()
	if len(ev.named("wan_change")) != 1 {
		t.Fatal("duplicate wan_change")
	}

	// Losing the default route suspends everything.
	fsys["proc/net/route"] = &fstest.MapFile{Data: []byte(routeHeader)}
	w.Refresh()
	if _, ok := cf.Dst(); ok {
		t.Fatal("target probed without a default route")
	}
	if _, ok := gw.Dst(); ok {
		t.Fatal("gateway probed without a default route")
	}
	if len(ev.named("wan_change")) != 2 {
		t.Fatal("route loss not reported")
	}
}

func TestRefreshMissingRoutes(t *testing.T) {
	w := New(fstest.MapFS{}, nil, nil, func(sample.Sample) {}, quiet())
	if _, err := w.Refresh(); err == nil {
		t.Fatal("missing route table accepted")
	}
}
