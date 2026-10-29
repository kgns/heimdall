package app

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"testing/fstest"

	"github.com/kgns/heimdall/probe/internal/config"
)

func TestISPResolvers(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.0.0/16")
	all := func(a netip.Addr) bool { return !lan.Contains(a) }
	r := config.Resolver{
		Mode:       config.ResolverISP,
		ISPFiles:   []string{"/etc/ppp/resolv.conf", "/tmp/resolv.conf.ppp"},
		ISPServers: []string{"10.234.0.1"},
	}
	// The first file names only the CPE's LAN address, so the second one
	// wins.
	fsys := fstest.MapFS{
		"etc/ppp/resolv.conf": {Data: []byte("nameserver 192.168.1.1\n")},
		"tmp/resolv.conf.ppp": {Data: []byte("nameserver 203.0.113.53\nnameserver 198.51.100.53\n")},
	}
	got, src := ispResolvers(fsys, r, all, "ppp0")
	if src != "/tmp/resolv.conf.ppp" || len(got) != 2 || got[0] != netip.MustParseAddrPort("203.0.113.53:53") {
		t.Fatalf("got %v from %s", got, src)
	}
	// No usable file: the configured servers, minus those the route guard
	// blocks.
	got, src = ispResolvers(fstest.MapFS{}, r, all, "ppp0")
	if src != "config" || len(got) != 1 || got[0].Addr() != netip.MustParseAddr("10.234.0.1") {
		t.Fatalf("got %v from %s", got, src)
	}
	if got, _ := ispResolvers(fstest.MapFS{}, r, func(netip.Addr) bool { return false }, "ppp0"); len(got) != 0 {
		t.Fatalf("guarded servers kept: %v", got)
	}
}

func TestISPResolversFromPPPD(t *testing.T) {
	// Two sessions in the database; the record of the WAN interface wins.
	tdb := []byte("\x00\x00pppd1IFNAME=ppp0;IPLOCAL=10.0.0.2;DNS1=192.0.2.1;DNS2=192.0.2.2;USEPEERDNS=1\x00" +
		"\x00pppd2PPPD_PID=9;IFNAME=ppp1.4;IPLOCAL=10.234.57.8;IPREMOTE=10.234.0.1;DNS1=213.74.1.1;DNS2=213.74.0.1;USEPEERDNS=1\x00")
	fsys := fstest.MapFS{
		"var/run/pppd2.tdb":   {Data: tdb},
		"etc/ppp/resolv.conf": {Data: []byte("nameserver 198.51.100.9\n")},
	}
	r := config.Default().Resolver
	r.Mode = config.ResolverISP
	got, src := ispResolvers(fsys, r, func(netip.Addr) bool { return true }, "ppp1.4")
	if src != "/var/run/pppd*.tdb" || len(got) != 2 || got[0] != netip.MustParseAddrPort("213.74.1.1:53") ||
		got[1] != netip.MustParseAddrPort("213.74.0.1:53") {
		t.Fatalf("got %v from %s", got, src)
	}
}

func TestISPDNSLayers(t *testing.T) {
	cfg := config.Default()
	cfg.DNS.UncachedZone = "w.example.net"
	e := &env{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	isp := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.53:53"), netip.MustParseAddrPort("198.51.100.53:53")}
	d := newDNSProbes(e, fstest.MapFS{}, func(netip.Addr) bool { return true }, isp)
	var ids []string
	for _, l := range d.layers {
		if l.layer == layerISP || l.layer == layerISPUncached {
			ids = append(ids, l.id)
		}
	}
	want := []string{"dns/isp/203.0.113.53:53", "dns/isp/198.51.100.53:53", "dns/isp-uncached/w.example.net"}
	if len(ids) != len(want) {
		t.Fatalf("layers %v", ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("layers %v", ids)
		}
	}
}
