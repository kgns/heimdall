package sysinfo

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

var ex7501 = os.DirFS("../../testdata/hosts/ex7501")

func TestReadRoutesEX7501(t *testing.T) {
	routes, err := ReadRoutes(ex7501)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 8 {
		t.Fatalf("got %d routes, want 8", len(routes))
	}
	def, ok := DefaultRoute(routes)
	if !ok {
		t.Fatal("no default route")
	}
	if def.Iface != "ppp1.4" || def.Gateway != netip.MustParseAddr("10.234.0.1") {
		t.Fatalf("default route = %+v", def)
	}

	side := SideGatewayRoutes(routes, def)
	if len(side) != 1 || side[0].Iface != "eth5.2" ||
		side[0].Dest != netip.MustParsePrefix("62.58.244.16/29") ||
		side[0].Gateway != netip.MustParseAddr("100.90.232.1") {
		t.Fatalf("side routes = %+v", side)
	}

	tests := []struct {
		ip    string
		iface string
		dest  string
	}{
		{"1.1.1.1", "ppp1.4", "0.0.0.0/0"},
		{"10.234.0.1", "ppp1.4", "10.234.0.1/32"},
		{"62.58.244.17", "eth5.2", "62.58.244.16/29"},
		{"62.58.244.24", "ppp1.4", "0.0.0.0/0"},
		{"100.90.233.5", "eth5.2", "100.90.232.0/22"},
		{"192.168.1.20", "br0", "192.168.1.0/24"},
		{"239.1.2.3", "br0", "239.0.0.0/8"},
	}
	for _, tc := range tests {
		rt, ok := Lookup(routes, netip.MustParseAddr(tc.ip))
		if !ok || rt.Iface != tc.iface || rt.Dest.String() != tc.dest {
			t.Errorf("Lookup(%s) = %s %s, want %s %s", tc.ip, rt.Iface, rt.Dest, tc.iface, tc.dest)
		}
	}
}

func TestParseRoutesMetricAndReject(t *testing.T) {
	in := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"wan1\t00000000\t0101A8C0\t0003\t0\t0\t20\t00000000\t0\t0\t0\n" +
		"wan0\t00000000\t0100000A\t0003\t0\t0\t10\t00000000\t0\t0\t0\n" +
		"lo\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n"
	routes, err := ParseRoutes(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	def, ok := DefaultRoute(routes)
	if !ok || def.Iface != "wan0" || def.Gateway != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("default = %+v", def)
	}
}

func TestParseRoutesErrors(t *testing.T) {
	bad := []string{
		"eth0\t00000000\n",
		"eth0\tZZ000000\t00000000\t0001\t0\t0\t0\t00000000\n",
		"eth0\t00000000\t00000000\t0001\t0\t0\t0\t00FF00FF\n",
	}
	for _, in := range bad {
		if _, err := ParseRoutes(strings.NewReader(in)); err == nil {
			t.Errorf("ParseRoutes(%q) succeeded, want error", in)
		}
	}
}

func TestReadRoutes6(t *testing.T) {
	routes, err := ReadRoutes6(ex7501)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 {
		t.Fatalf("got %d routes", len(routes))
	}
	if d := DefaultRoutes6(routes); len(d) != 0 {
		t.Fatalf("unexpected IPv6 default routes %+v", d)
	}

	withDefault := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003  ppp1.4\n"
	r6, err := ParseRoutes6(strings.NewReader(withDefault))
	if err != nil {
		t.Fatal(err)
	}
	d := DefaultRoutes6(r6)
	if len(d) != 1 || d[0].Iface != "ppp1.4" || d[0].NextHop != netip.MustParseAddr("fe80::1") {
		t.Fatalf("defaults = %+v", d)
	}

	missing, err := ReadRoutes6(fstest.MapFS{})
	if err != nil || missing != nil {
		t.Fatalf("missing file: %v %v", missing, err)
	}
}

func TestReadMemInfo(t *testing.T) {
	m, err := ReadMemInfo(ex7501)
	if err != nil {
		t.Fatal(err)
	}
	want := MemInfo{TotalKB: 1018820, FreeKB: 469048, AvailableKB: 538604, CachedKB: 82544}
	if m != want {
		t.Fatalf("got %+v, want %+v", m, want)
	}
	if _, err := ParseMemInfo(strings.NewReader("MemFree: 1 kB\n")); err == nil {
		t.Fatal("missing MemTotal accepted")
	}
}

func TestPingGroupRange(t *testing.T) {
	pg, err := ReadPingGroupRange(ex7501)
	if err != nil {
		t.Fatal(err)
	}
	if pg.Allows(0) || pg.Allows(1) {
		t.Fatalf("default range %v must allow nobody", pg)
	}
	open, err := ParsePingGroupRange("0\t2147483647\n")
	if err != nil || !open.Allows(0) || !open.Allows(1000) {
		t.Fatalf("open range: %v %v", open, err)
	}
	if _, err := ParsePingGroupRange("1"); err == nil {
		t.Fatal("single value accepted")
	}
}

func TestFindProcess(t *testing.T) {
	pid, args, err := FindProcess(ex7501, "dnsmasq")
	if err != nil {
		t.Fatal(err)
	}
	if pid != 4090 || !slices.Equal(args, []string{"/usr/sbin/dnsmasq", "-q", "--conf-file=/etc/dnsmasq.conf"}) {
		t.Fatalf("pid %d args %q", pid, args)
	}
	pid, _, err = FindProcess(ex7501, "nope")
	if err != nil || pid != 0 {
		t.Fatalf("missing process: %d %v", pid, err)
	}
}

func TestDiscoverDnsmasqEX7501(t *testing.T) {
	d, err := DiscoverDnsmasq(ex7501)
	if err != nil {
		t.Fatal(err)
	}
	if d == nil || !d.Running || d.PID != 4090 {
		t.Fatalf("dnsmasq = %+v", d)
	}
	wantFiles := []string{"/etc/dnsmasq.conf", "/var/dnsmasq/conf.d/00-anondns.conf", "/var/dnsmasq/conf.d/lan.conf"}
	if !slices.Equal(d.Files, wantFiles) {
		t.Fatalf("files = %q, want %q", d.Files, wantFiles)
	}
	if !d.NoResolv {
		t.Fatal("no-resolv not detected")
	}
	if len(d.ResolvServers) != 0 {
		t.Fatalf("resolv servers read despite no-resolv: %+v", d.ResolvServers)
	}
	up := d.Upstreams()
	if len(up) != 1 || up[0].Addr != netip.MustParseAddrPort("127.0.0.1:5300") {
		t.Fatalf("upstreams = %+v", up)
	}
	if up[0].Origin != "/var/dnsmasq/conf.d/00-anondns.conf:9" {
		t.Fatalf("origin = %q", up[0].Origin)
	}
	if len(d.Warnings) != 0 {
		t.Fatalf("warnings: %q", d.Warnings)
	}
}

func TestDiscoverDnsmasqVariants(t *testing.T) {
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	proc := func(args string) fstest.MapFS {
		return fstest.MapFS{
			"proc/77/comm":    file("dnsmasq\n"),
			"proc/77/cmdline": file(args),
		}
	}
	merge := func(ms ...fstest.MapFS) fstest.MapFS {
		out := fstest.MapFS{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	t.Run("resolv-file without conf-dir", func(t *testing.T) {
		fsys := merge(proc("/usr/sbin/dnsmasq\x00--conf-file=/etc/dnsmasq.conf\x00"), fstest.MapFS{
			"etc/dnsmasq.conf": file("resolv-file=/var/fyi/sys/dns\nmin-port=1024\n"),
			"var/fyi/sys/dns":  file("nameserver 1.1.1.1\nnameserver 1.0.0.1\n"),
		})
		d, err := DiscoverDnsmasq(fsys)
		if err != nil {
			t.Fatal(err)
		}
		got := addrs(d.Upstreams())
		if !slices.Equal(got, []string{"1.1.1.1:53", "1.0.0.1:53"}) {
			t.Fatalf("upstreams = %q", got)
		}
	})

	t.Run("cmdline options and default resolv.conf", func(t *testing.T) {
		fsys := merge(proc("dnsmasq\x00-C\x00/opt/dm.conf\x00-S\x009.9.9.9\x00--port\x005353\x00"), fstest.MapFS{
			"opt/dm.conf":     file("server=/corp.example/10.0.0.53\nserver=8.8.8.8 # trailing comment\n"),
			"etc/resolv.conf": file("nameserver 192.0.2.1\n"),
		})
		d, err := DiscoverDnsmasq(fsys)
		if err != nil {
			t.Fatal(err)
		}
		if d.ListenPort != 5353 {
			t.Fatalf("port = %d", d.ListenPort)
		}
		got := addrs(d.Upstreams())
		if !slices.Equal(got, []string{"9.9.9.9:53", "8.8.8.8:53", "192.0.2.1:53"}) {
			t.Fatalf("upstreams = %q", got)
		}
		if len(d.Servers) != 3 || d.Servers[1].Domains[0] != "corp.example" {
			t.Fatalf("servers = %+v", d.Servers)
		}
	})

	t.Run("conf-dir filters", func(t *testing.T) {
		fsys := merge(proc("dnsmasq\x00"), fstest.MapFS{
			"etc/dnsmasq.conf":  file("no-resolv\nconf-dir=/etc/d,*.conf\nconf-dir=/etc/e,.bak\n"),
			"etc/d/a.conf":      file("server=192.0.2.10\n"),
			"etc/d/b.txt":       file("server=192.0.2.11\n"),
			"etc/d/.hidden":     file("server=192.0.2.12\n"),
			"etc/e/x":           file("server=192.0.2.13#5353@eth0\n"),
			"etc/e/y.bak":       file("server=192.0.2.14\n"),
			"etc/e/#tmp#":       file("server=192.0.2.15\n"),
			"etc/e/sub/z.conf":  file("server=192.0.2.16\n"),
			"etc/e/local.conf":  file("local=/lan/\nserver=/x/#\n"),
			"etc/e/bad.conf":    file("server=not-an-ip\n"),
			"etc/e/loop.conf":   file("conf-file=/etc/dnsmasq.conf\n"),
			"etc/e/v6.conf":     file("server=2001:db8::53#853\n"),
			"etc/e/quoted.conf": file("server=\"192.0.2.17\"\n"),
		})
		d, err := DiscoverDnsmasq(fsys)
		if err != nil {
			t.Fatal(err)
		}
		got := addrs(d.Upstreams())
		want := []string{"192.0.2.10:53", "192.0.2.17:53", "[2001:db8::53]:853", "192.0.2.13:5353"}
		if !slices.Equal(got, want) {
			t.Fatalf("upstreams = %q, want %q", got, want)
		}
		if len(d.Warnings) != 1 || !strings.Contains(d.Warnings[0], "not-an-ip") {
			t.Fatalf("warnings = %q", d.Warnings)
		}
	})

	t.Run("config without visible process", func(t *testing.T) {
		d, err := DiscoverDnsmasq(fstest.MapFS{
			"etc/dnsmasq.conf": file("no-resolv\nserver=127.0.0.1#5300\n"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if d.Running || len(d.Upstreams()) != 1 {
			t.Fatalf("dnsmasq = %+v", d)
		}
	})

	t.Run("absent", func(t *testing.T) {
		d, err := DiscoverDnsmasq(fstest.MapFS{"etc/resolv.conf": file("nameserver 1.1.1.1\n")})
		if err != nil || d != nil {
			t.Fatalf("got %+v %v, want nil", d, err)
		}
	})

	t.Run("resolv-file disabled", func(t *testing.T) {
		fsys := merge(proc("dnsmasq\x00"), fstest.MapFS{
			"etc/dnsmasq.conf": file("resolv-file=\nserver=192.0.2.1\n"),
			"etc/resolv.conf":  file("nameserver 192.0.2.99\n"),
		})
		d, err := DiscoverDnsmasq(fsys)
		if err != nil {
			t.Fatal(err)
		}
		if got := addrs(d.Upstreams()); !slices.Equal(got, []string{"192.0.2.1:53"}) {
			t.Fatalf("upstreams = %q", got)
		}
	})
}

func TestParseDnsmasqServer(t *testing.T) {
	tests := []struct {
		in      string
		addr    string
		domains []string
		ok      bool
		err     bool
	}{
		{"127.0.0.1#5300", "127.0.0.1:5300", nil, true, false},
		{"8.8.8.8@ppp0", "8.8.8.8:53", nil, true, false},
		{"/home/", "", []string{"home"}, false, false},
		{"/a.example/b.example/192.0.2.1", "192.0.2.1:53", []string{"a.example", "b.example"}, true, false},
		{"//192.0.2.2", "192.0.2.2:53", []string{""}, true, false},
		{"#", "", nil, false, false},
		{"192.0.2.1#0", "", nil, false, true},
		{"/unterminated", "", nil, false, true},
	}
	for _, tc := range tests {
		s, ok, err := parseDnsmasqServer(tc.in)
		if (err != nil) != tc.err || ok != tc.ok {
			t.Errorf("%q: ok=%v err=%v", tc.in, ok, err)
			continue
		}
		if ok && s.Addr.String() != tc.addr {
			t.Errorf("%q: addr %s, want %s", tc.in, s.Addr, tc.addr)
		}
		if !slices.Equal(s.Domains, tc.domains) {
			t.Errorf("%q: domains %q, want %q", tc.in, s.Domains, tc.domains)
		}
	}
}

func TestStripDnsmasqComment(t *testing.T) {
	tests := map[string]string{
		"# full line":                 "",
		"server=1.2.3.4#53":           "server=1.2.3.4#53",
		"server=1.2.3.4 # comment":    "server=1.2.3.4 ",
		"\t# indented":                "\t",
		`dhcp-option=252,"a #b"`:      `dhcp-option=252,"a #b"`,
		`txt-record=x,"q" #tail`:      `txt-record=x,"q" `,
		"no-resolv":                   "no-resolv",
		"address=/#/127.0.0.1":        "address=/#/127.0.0.1",
		"server=/x/#":                 "server=/x/#",
		"conf-dir=/etc/d,*.conf #all": "conf-dir=/etc/d,*.conf ",
	}
	for in, want := range tests {
		if got := stripDnsmasqComment(in); got != want {
			t.Errorf("stripDnsmasqComment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseResolvConf(t *testing.T) {
	got, err := ParseResolvConf(strings.NewReader("# c\nsearch home\nnameserver 127.0.0.1\nnameserver fe80::1%br0\nnameserver bogus\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != netip.MustParseAddr("127.0.0.1") || got[1].Zone() != "br0" {
		t.Fatalf("got %v", got)
	}
}

func TestIsGlobalIPv6(t *testing.T) {
	tests := map[string]bool{
		"2001:db8::1":      true,
		"2a02:ff0::1":      true,
		"fe80::1":          false,
		"fd00::1":          false,
		"::1":              false,
		"::ffff:192.0.2.1": false,
		"192.0.2.1":        false,
	}
	for in, want := range tests {
		if got := IsGlobalIPv6(netip.MustParseAddr(in)); got != want {
			t.Errorf("IsGlobalIPv6(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestFSPath(t *testing.T) {
	tests := map[string]string{
		"/etc/dnsmasq.conf":    "etc/dnsmasq.conf",
		"/var/../etc/x":        "etc/x",
		"relative/file":        "relative/file",
		"/":                    ".",
		"/../../../etc/passwd": "etc/passwd",
	}
	for in, want := range tests {
		if got := fsPath(in); got != want {
			t.Errorf("fsPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func addrs(s []DNSServer) []string {
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = x.Addr.String()
	}
	return out
}
