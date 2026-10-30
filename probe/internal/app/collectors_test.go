package app

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kgns/heimdall/probe/internal/config"
	"github.com/kgns/heimdall/probe/internal/netwatch"
	"github.com/kgns/heimdall/probe/internal/probes/icmp"
	"github.com/kgns/heimdall/probe/internal/sample"
	"github.com/kgns/heimdall/probe/internal/sysinfo"
)

func collectorFixture(t *testing.T) fstest.MapFS {
	t.Helper()
	route, err := os.ReadFile("../../testdata/hosts/ex7501/proc/net/route")
	if err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{
		"proc/net/route": {Data: route},
		"proc/net/arp": {Data: []byte("IP address HW type Flags HW address Mask Device\n" +
			"192.168.1.2 0x1 0x2 f0:87:56:8c:f7:a7 * br0\n" +
			"192.168.1.3 0x1 0x2 78:c5:7d:2e:d6:2f * br0\n" +
			"10.234.0.1 0x1 0x2 00:11:22:33:44:55 * ppp1.4\n")},
		"sys/class/net/br0/brif/eth0.0/port_no": {Data: []byte("0x1\n")},
		"sys/class/net/br0/brif/wl0/port_no":    {Data: []byte("0x2\n")},
		"sys/class/net/br0/brforward":           {Data: fdb("f0:87:56:8c:f7:a7", 2)},
	}
}

func fdb(mac string, port int) []byte {
	b := make([]byte, 16)
	m, _ := net.ParseMAC(mac)
	copy(b, m)
	b[6] = byte(port)
	return b
}

func collectorEnv(t *testing.T, fsys fstest.MapFS, conn icmp.Conn) (*collectors, *sample.MemorySink) {
	t.Helper()
	cfg := config.Default()
	cfg.Collectors.LAN.SaltFile = t.TempDir() + "/lan.salt"
	cfg.Collectors.LAN.DisappearAfter = 2
	cfg.ICMP.Timeout = 200 * time.Millisecond
	e, mem := testEnv(t, cfg)
	if conn != nil {
		p, err := icmp.New(conn, icmp.Options{PayloadSize: 16})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		e.pinger = p
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	nw := netwatch.New(fsys, func(string) (sysinfo.Interface, error) {
		return sysinfo.Interface{Name: "ppp1.4", IPv4: []netip.Addr{netip.MustParseAddr("10.234.57.8")}}, nil
	}, nil, func(sample.Sample) {}, log)
	if _, err := nw.Refresh(); err != nil {
		t.Fatal(err)
	}
	lookup := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return newCollectors(e, fsys, nw, lookup, ""), mem
}

func byKind(s []sample.Sample, k sample.Kind) []sample.Sample {
	var out []sample.Sample
	for _, x := range s {
		if x.Kind == k {
			out = append(out, x)
		}
	}
	return out
}

func eventsNamed(s []sample.Sample, name string) []sample.Sample {
	var out []sample.Sample
	for _, x := range s {
		if x.Kind == sample.KindEvent && x.Extra["event"] == name {
			out = append(out, x)
		}
	}
	return out
}

func netDev(rx, tx uint64) []byte {
	return []byte(fmt.Sprintf("Inter-|\n face |\nppp1.4: %d 1000 0 0 0 0 0 0 %d 500 0 0 0 0 0 0\n    lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n", rx, tx))
}

func TestWANCollector(t *testing.T) {
	fsys := collectorFixture(t)
	fsys["proc/net/dev"] = &fstest.MapFile{Data: netDev(1_000_000, 100_000)}
	c, mem := collectorEnv(t, fsys, nil)
	job := c.wanJob()
	job.Run(context.Background())
	if len(mem.Samples()) != 0 {
		t.Fatal("first reading produced a sample")
	}
	time.Sleep(200 * time.Millisecond)
	fsys["proc/net/dev"] = &fstest.MapFile{Data: netDev(1_000_000+2_500_000, 100_000+250_000)}
	job.Run(context.Background())
	s := byKind(mem.Samples(), sample.KindWAN)
	if len(s) != 1 || s[0].TargetID != "wan/ppp1.4" {
		t.Fatalf("%+v", s)
	}
	rx := s[0].Extra["rx_bps"].(float64)
	tx := s[0].Extra["tx_bps"].(float64)
	// 20 Mbit over about 0.2 s and a tenth of that upstream.
	if rx < 50e6 || rx > 110e6 || tx < 5e6 || tx > 11e6 {
		t.Fatalf("rx %.0f tx %.0f", rx, tx)
	}
}

func TestCPUCollector(t *testing.T) {
	fsys := collectorFixture(t)
	fsys["proc/stat"] = &fstest.MapFile{Data: []byte("cpu  100 0 50 800 10 0 40 0\ncpu0 1\ncpu1 1\n")}
	fsys["proc/loadavg"] = &fstest.MapFile{Data: []byte("0.50 0.4 0.3 1/90 100\n")}
	fsys["proc/net/snmp"] = &fstest.MapFile{Data: []byte("Udp: InDatagrams NoPorts InErrors\nUdp: 10 100 0\n")}
	c, mem := collectorEnv(t, fsys, nil)
	job := c.cpuJob()
	job.Run(context.Background())
	fsys["proc/stat"] = &fstest.MapFile{Data: []byte("cpu  130 0 60 850 10 0 50 0\ncpu0 1\ncpu1 1\n")}
	fsys["proc/net/snmp"] = &fstest.MapFile{Data: []byte("Udp: InDatagrams NoPorts InErrors\nUdp: 20 126 0\n")}
	job.Run(context.Background())
	s := byKind(mem.Samples(), sample.KindCPU)
	if len(s) != 1 {
		t.Fatalf("%+v", s)
	}
	x := s[0].Extra
	if x["busy_pct"] != 50.0 || x["softirq_pct"] != 10.0 || x["cpus"] != 2 || x["load1"] != 0.5 || x["udp_noports"] != uint64(26) {
		t.Fatalf("%+v", x)
	}
}

// lanConn answers echo requests from 192.168.1.2 only.
type lanConn struct{ *echoConn }

func (l lanConn) WriteTo(b []byte, dst netip.Addr, ttl int) error {
	if dst != netip.MustParseAddr("192.168.1.2") {
		return nil
	}
	return l.echoConn.WriteTo(b, dst, ttl)
}

func TestLANCollector(t *testing.T) {
	fsys := collectorFixture(t)
	c, mem := collectorEnv(t, fsys, lanConn{newEchoConn(time.Millisecond)})
	c.discoverLAN()
	if c.LANClients() != 2 {
		t.Fatalf("%d clients", c.LANClients())
	}
	c.pingLAN(context.Background())

	lanSamples := byKind(mem.Samples(), sample.KindLAN)
	if len(lanSamples) != 2 {
		t.Fatalf("%+v", lanSamples)
	}
	for _, s := range lanSamples {
		if strings.Contains(s.TargetID, "f0:87") || len(s.TargetID) != len("lan/")+12 {
			t.Fatalf("client id leaks or is malformed: %q", s.TargetID)
		}
		switch s.DstIP {
		case "192.168.1.2":
			if s.Status != sample.StatusOK || s.Extra["medium"] != "wifi" || s.Extra["port"] != "wl0" {
				t.Fatalf("wifi client %+v", s)
			}
		case "192.168.1.3":
			if s.Status != sample.StatusTimeout || s.Extra["medium"] != nil {
				t.Fatalf("silent client %+v", s)
			}
		default:
			t.Fatalf("non-LAN address pinged: %+v", s)
		}
	}
	if n := len(eventsNamed(mem.Samples(), "lan_client_seen")); n != 2 {
		t.Fatalf("%d seen events", n)
	}

	// The wired client leaves the ARP table; after two missed discoveries
	// it is dropped.
	fsys["proc/net/arp"] = &fstest.MapFile{Data: []byte("IP address HW type Flags HW address Mask Device\n192.168.1.2 0x1 0x2 f0:87:56:8c:f7:a7 * br0\n")}
	c.discoverLAN()
	if c.LANClients() != 2 {
		t.Fatal("client dropped after one miss")
	}
	c.discoverLAN()
	if c.LANClients() != 1 || len(eventsNamed(mem.Samples(), "lan_client_gone")) != 1 {
		t.Fatalf("clients %d, gone events %d", c.LANClients(), len(eventsNamed(mem.Samples(), "lan_client_gone")))
	}

	// Moving the remaining client to the wired port is reported.
	fsys["sys/class/net/br0/brforward"] = &fstest.MapFile{Data: fdb("f0:87:56:8c:f7:a7", 1)}
	c.discoverLAN()
	moved := eventsNamed(mem.Samples(), "lan_client_moved")
	if len(moved) != 1 || moved[0].Extra["medium"] != "wired" || moved[0].Extra["prev_medium"] != "wifi" {
		t.Fatalf("%+v", moved)
	}

	// IDs are stable across restarts because the salt is persisted.
	c2, _ := collectorEnv(t, fsys, nil)
	c2.cfg.Collectors.LAN.SaltFile = c.cfg.Collectors.LAN.SaltFile
	c3 := newCollectors(c2.env, fsys, c2.nw, c2.lookup, "")
	c3.discoverLAN()
	for id := range c.lanClients {
		if _, ok := c3.lanClients[id]; !ok {
			t.Fatalf("client id %s changed after restart", id)
		}
	}
}

func TestProcessCollector(t *testing.T) {
	fsys := collectorFixture(t)
	add := func(pid int, name string) {
		p := fmt.Sprintf("proc/%d/", pid)
		fsys[p+"comm"] = &fstest.MapFile{Data: []byte(name + "\n")}
		fsys[p+"cmdline"] = &fstest.MapFile{Data: []byte(name + "\x00")}
		fsys[p+"status"] = &fstest.MapFile{Data: []byte("VmRSS:\t 2000 kB\n")}
		fsys[p+"cgroup"] = &fstest.MapFile{Data: []byte("3:memory:/lxc/anondns\n")}
	}
	add(2808, "dnscrypt-proxy")
	fsys["sys/fs/cgroup/memory/lxc/anondns/memory.usage_in_bytes"] = &fstest.MapFile{Data: []byte("30000000\n")}
	fsys["sys/fs/cgroup/memory/lxc/anondns/memory.limit_in_bytes"] = &fstest.MapFile{Data: []byte("62914560\n")}
	fsys["sys/fs/cgroup/memory/lxc/anondns/memory.failcnt"] = &fstest.MapFile{Data: []byte("0\n")}

	c, mem := collectorEnv(t, fsys, nil)
	c.cfg.Collectors.Processes.Names = []string{"dnscrypt-proxy", "dnsmasq"}
	job := c.processJob()
	job.Run(context.Background())

	delete(fsys, "proc/2808/comm")
	add(3100, "dnscrypt-proxy")
	fsys["sys/fs/cgroup/memory/lxc/anondns/memory.failcnt"] = &fstest.MapFile{Data: []byte("2\n")}
	job.Run(context.Background())

	health := byKind(mem.Samples(), sample.KindDNSHealth)
	if len(health) != 4 {
		t.Fatalf("%d health samples", len(health))
	}
	last := health[2]
	if last.TargetID != "proc/dnscrypt-proxy" || last.Extra["pid"] != 3100 || last.Extra["mem_limit"] != uint64(62914560) || last.Extra["oom_new"] != uint64(2) {
		t.Fatalf("%+v", last)
	}
	if health[1].Status != sample.StatusError || health[1].Extra["reason"] != "missing" {
		t.Fatalf("missing dnsmasq %+v", health[1])
	}
	if r := eventsNamed(mem.Samples(), "process_restart"); len(r) != 1 || r[0].Extra["prev_pid"] != 2808 {
		t.Fatalf("%+v", r)
	}
}

func TestClockCollector(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil || n < 48 {
				return
			}
			now := time.Now().Add(-2 * time.Second)
			ntp := uint64(now.Unix()+2208988800)<<32 | uint64(now.Nanosecond())<<32/1e9
			resp := make([]byte, 48)
			resp[0], resp[1] = 0x24, 2
			copy(resp[24:32], buf[40:48])
			binary.BigEndian.PutUint64(resp[32:], ntp)
			binary.BigEndian.PutUint64(resp[40:], ntp)
			pc.WriteTo(resp, addr)
		}
	}()
	c, mem := collectorEnv(t, collectorFixture(t), nil)
	c.ntpPort = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	c.checkClock(context.Background())
	s := byKind(mem.Samples(), sample.KindClock)
	if len(s) != 1 || s[0].Status != sample.StatusOK || s[0].RTTms == nil {
		t.Fatalf("%+v", s)
	}
	off := s[0].Extra["offset_ms"].(float64)
	if off > -1900 || off < -2100 || c.ClockOffset() > -1900*time.Millisecond {
		t.Fatalf("offset %v / %v", off, c.ClockOffset())
	}
}

// On an extender the detector learns where a client is attached from the
// bridge ports its connections arrive on.
func TestBridgeClientContext(t *testing.T) {
	c, _ := collectorEnv(t, collectorFixture(t), nil)
	if cx := c.clientContext("aaa"); cx["node"] != nil {
		t.Fatalf("CPE context names a node: %v", cx)
	}
	c.bridgeNode, c.bridgePorts = "WX5600-AP-1", map[string]string{}
	c.notePort("aaa", "eth1")
	c.notePort("bbb", "ra0")
	for id, want := range map[string][3]any{
		"aaa": {"WX5600-AP-1", "eth1", "wired"},
		"bbb": {"WX5600-AP-1", "ra0", "wifi"},
		"ccc": {"WX5600-AP-1", nil, nil},
	} {
		cx := c.clientContext(id)
		if cx["node"] != want[0] || cx["port"] != want[1] || cx["medium"] != want[2] {
			t.Errorf("%s: %v", id, cx)
		}
	}
}
