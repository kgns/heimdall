package hoststat

import (
	"strings"
	"testing"
	"testing/fstest"
)

const netDev = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
ppp1.4: 98765432101 70000000 1 5 0 0 0 0 1234567890 30000000 0 2 0 0 0 0
   br0:200 2    0    0    0     0          0         0 300 3 0 0 0 0 0 0
`

func TestParseNetDev(t *testing.T) {
	m, err := ParseNetDev(strings.NewReader(netDev))
	if err != nil {
		t.Fatal(err)
	}
	p := m["ppp1.4"]
	if p.RxBytes != 98765432101 || p.RxPackets != 70000000 || p.RxErrs != 1 || p.RxDrop != 5 ||
		p.TxBytes != 1234567890 || p.TxPackets != 30000000 || p.TxDrop != 2 {
		t.Fatalf("%+v", p)
	}
	if m["br0"].TxBytes != 300 || len(m) != 3 {
		t.Fatalf("%+v", m)
	}
	if _, err := ParseNetDev(strings.NewReader("eth0: 1 2 3\n")); err == nil {
		t.Fatal("short line accepted")
	}
}

func TestDelta(t *testing.T) {
	tests := []struct{ prev, cur, want uint64 }{
		{100, 150, 50},
		{1<<32 - 10, 5, 15},
		{1 << 40, 7, 7},
		{5, 5, 0},
	}
	for _, tc := range tests {
		if got := Delta(tc.prev, tc.cur); got != tc.want {
			t.Errorf("Delta(%d, %d) = %d, want %d", tc.prev, tc.cur, got, tc.want)
		}
	}
}

func TestCPU(t *testing.T) {
	a, n, err := ParseCPU(strings.NewReader("cpu  100 0 50 800 10 0 40 0 0 0\ncpu0 1 1 1 1\ncpu1 1 1 1 1\nintr 1\n"))
	if err != nil || n != 2 {
		t.Fatalf("%v %d", err, n)
	}
	b, _, _ := ParseCPU(strings.NewReader("cpu  130 0 60 850 10 0 50 0 0 0\n"))
	u, ok := Usage(a, b)
	if !ok {
		t.Fatal("no usage")
	}
	// 100 jiffies elapsed: 30 user, 10 system, 50 idle, 10 softirq.
	if u.Busy != 50 || u.User != 30 || u.System != 10 || u.SoftIRQ != 10 || u.IOWait != 0 {
		t.Fatalf("%+v", u)
	}
	if _, ok := Usage(b, b); ok {
		t.Fatal("usage over zero time")
	}
	if _, _, err := ParseCPU(strings.NewReader("intr 1\n")); err == nil {
		t.Fatal("missing cpu line accepted")
	}
}

func TestSNMP(t *testing.T) {
	in := `Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 12345
Icmp: InMsgs InErrors OutDestUnreachs
Icmp: 9961802 14956 9873254
Tcp: RtoAlgorithm MaxConn RetransSegs
Tcp: 1 -1 4321
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors
Udp: 500 26 3 400 1
`
	s, err := ParseSNMP(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if s["Udp.NoPorts"] != 26 || s["Icmp.OutDestUnreachs"] != 9873254 || s["Tcp.RetransSegs"] != 4321 || s["Udp.RcvbufErrors"] != 1 {
		t.Fatalf("%v", s)
	}
	if _, has := s["Tcp.MaxConn"]; has {
		t.Fatal("negative counter kept")
	}
}

func TestReadersFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"proc/net/dev":  {Data: []byte(netDev)},
		"proc/stat":     {Data: []byte("cpu  1 2 3 4 5 6 7 8\ncpu0 1\n")},
		"proc/loadavg":  {Data: []byte("0.42 0.30 0.20 1/120 999\n")},
		"proc/net/snmp": {Data: []byte("Udp: NoPorts\nUdp: 9\n")},
	}
	if m, err := ReadNetDev(fsys); err != nil || len(m) != 3 {
		t.Fatal(m, err)
	}
	if c, n, err := ReadCPU(fsys); err != nil || n != 1 || c.Steal != 8 {
		t.Fatal(c, n, err)
	}
	if l, err := ReadLoadAvg(fsys); err != nil || l != 0.42 {
		t.Fatal(l, err)
	}
	if s, err := ReadSNMP(fsys); err != nil || s["Udp.NoPorts"] != 9 {
		t.Fatal(s, err)
	}
}
