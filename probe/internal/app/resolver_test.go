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
	got, src := ispResolvers(fsys, r, all)
	if src != "/tmp/resolv.conf.ppp" || len(got) != 2 || got[0] != netip.MustParseAddrPort("203.0.113.53:53") {
		t.Fatalf("got %v from %s", got, src)
	}
	// No usable file: the configured servers, minus those the route guard
	// blocks.
	got, src = ispResolvers(fstest.MapFS{}, r, all)
	if src != "config" || len(got) != 1 || got[0].Addr() != netip.MustParseAddr("10.234.0.1") {
		t.Fatalf("got %v from %s", got, src)
	}
	if got, _ := ispResolvers(fstest.MapFS{}, r, func(netip.Addr) bool { return false }); len(got) != 0 {
		t.Fatalf("guarded servers kept: %v", got)
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
