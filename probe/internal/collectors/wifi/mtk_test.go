package wifi

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func TestParseMTKStaInfo(t *testing.T) {
	st := ParseMTKStaInfo(fixture(t, "mtk_stainfo_5g.txt"))
	if len(st) != 2 {
		t.Fatalf("stations: %+v", st)
	}
	a := st[0]
	if a.MAC.String() != "02:00:00:00:00:eb" || a.BSS != 0 || !a.PowerSave || a.PhyMode != "HE_SU" ||
		a.BWMHz != 80 || a.MCS != "2S-M11" || a.TxRateMb != 1201 || a.RxRateMb != 24 {
		t.Errorf("station: %+v", a)
	}
	if r, ok := a.BestRSSI(); !ok || r != -44 || len(a.RSSI) != 4 {
		t.Errorf("rssi %v %d %v", a.RSSI, r, ok)
	}
	b := st[1]
	if b.BSS != 2 || b.PowerSave || len(b.RSSI) != 2 {
		t.Errorf("unused chains must be left out: %+v", b)
	}
	if r, _ := b.BestRSSI(); r != -69 {
		t.Errorf("best rssi %d", r)
	}
}

func TestParseMTKCountersAndStat(t *testing.T) {
	c := ParseMTKStaCount(fixture(t, "mtk_stacount_5g.txt"))
	if got := c["02:00:00:00:00:eb"]; got.TxPkts != 38794 || got.RxPkts != 30691 || got.TxBytes != 22087895 || got.RxBytes != 5447576 {
		t.Errorf("counts: %+v", got)
	}
	n, temp, ok := ParseMTKStat(fixture(t, "mtk_stat_5g.txt"))
	if !ok || temp != 64 {
		t.Errorf("temperature %d %v", temp, ok)
	}
	if n["tx_success"] != 46141107 || n["tx_fail"] != 4984439 || n["tx_retrans"] != 2080584 ||
		n["rx_success"] != 88203194 || n["rx_crc"] != 199470817 {
		t.Errorf("stat: %+v", n)
	}
	if _, ok := n["Rx drop due to out of resource"]; ok || len(n) != 5 {
		t.Errorf("unexpected counters: %+v", n)
	}
	if ch, ok := ParseIwconfigChannel([]byte("rax0  IEEE 802.11ax  ESSID:\"x\"\n  Mode:Master  Channel:112  Access Point: 02:00:00:00:00:A9")); !ok || ch != 112 {
		t.Errorf("channel %d %v", ch, ok)
	}
}

func TestMTKRadios(t *testing.T) {
	fsys := fstest.MapFS{
		"sys/class/net/ra0/flags":    {Data: []byte("0x1003\n")},
		"sys/class/net/ra1/flags":    {Data: []byte("0x1003\n")},
		"sys/class/net/rax0/flags":   {Data: []byte("0x1003\n")},
		"sys/class/net/rax2/flags":   {Data: []byte("0x1003\n")},
		"sys/class/net/apcli0/flags": {Data: []byte("0x1002\n")},
		"sys/class/net/ra3/flags":    {Data: []byte("0x1002\n")},
		"sys/class/net/eth0/flags":   {Data: []byte("0x1003\n")},
	}
	r := MTKRadios(fsys)
	if len(r) != 2 || r[0].prefix != "ra" || r[0].first != "ra0" || len(r[0].ifaces) != 2 ||
		r[1].prefix != "rax" || r[1].ifaces[2] != "rax2" {
		t.Errorf("radios: %+v", r)
	}
}

func TestPollMTK(t *testing.T) {
	fsys := fstest.MapFS{
		"sys/class/net/rax0/flags": {Data: []byte("0x1003\n")},
		"sys/class/net/rax2/flags": {Data: []byte("0x1003\n")},
	}
	stainfo := fixture(t, "mtk_stainfo_5g.txt")
	count := fixture(t, "mtk_stacount_5g.txt")
	stat := fixture(t, "mtk_stat_5g.txt")
	exec := func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name + " " + strings.Join(args, " ") {
		case "iwconfig rax0":
			return []byte("rax0  Mode:Master  Channel:112\n"), nil
		case "iwpriv rax0 show stainfo":
			return stainfo, nil
		case "iwpriv rax0 show stacountinfo":
			return count, nil
		case "iwpriv rax0 stat":
			return stat, nil
		}
		return nil, errors.New("unexpected " + name + " " + strings.Join(args, " "))
	}
	var got []sample.Sample
	ports := func() map[string]string { return map[string]string{"02:00:00:00:00:07": "rax2"} }
	c := New(Options{Driver: DriverMTK, Exec: exec, Node: "WX5600-AP-1", FS: fsys, PortOf: ports,
		ID:   func(m net.HardwareAddr) string { return "id-" + m.String()[15:] },
		Emit: func(s sample.Sample) { got = append(got, s) }, Now: func() time.Time { return time.UnixMilli(1000) }})
	c.Poll(context.Background())
	byKind := func(k sample.Kind) []sample.Sample {
		var out []sample.Sample
		for _, s := range got {
			if s.Kind == k {
				out = append(out, s)
			}
		}
		return out
	}
	sta := byKind(sample.KindWiFiSta)
	if len(sta) != 2 {
		t.Fatalf("stations: %+v", got)
	}
	x := sta[0].Extra
	if x["node"] != "WX5600-AP-1" || x["iface"] != "rax0" || x["band"] != "5GHz" || x["rssi"] != -44 ||
		x["ps"] != true || x["source"] != "mtk" || x["tx_rate_mbps"] != 1201.0 {
		t.Errorf("first station: %+v", x)
	}
	if _, ok := x["tx_pkts"]; ok {
		t.Error("first poll must not report deltas")
	}
	if sta[1].Extra["iface"] != "rax2" {
		t.Errorf("second station's interface comes from the bridge table: %+v", sta[1].Extra)
	}
	ev := byKind(sample.KindEvent)
	if len(ev) != 2 || ev[0].Extra["event"] != "wifi_join" {
		t.Errorf("join events: %+v", ev)
	}
	cx := c.ClientContext("id-eb")
	if cx["node"] != "WX5600-AP-1" || cx["medium"] != "wifi" || cx["band"] != "5GHz" {
		t.Errorf("context: %+v", cx)
	}

	// The second poll reports deltas and the radio's shares.
	count2 := strings.Replace(string(count), "38794       30691       22087895", "38894       30791       22097895", 1)
	stat2 := strings.NewReplacer("46141107", "46142107", "4984439", "4984539", "2080584", "2080634").Replace(string(stat))
	// Too few frames for the shares to mean anything.
	few := strings.NewReplacer("46141107", "46141117", "2080584", "2080589").Replace(string(stat))
	stat = []byte(few)
	got = nil
	c.Poll(context.Background())
	if r := byKind(sample.KindWiFiRadio); r[0].Extra["tx_success"] != uint64(10) || r[0].Extra["retrans_pct"] != nil {
		t.Errorf("shares of 10 frames: %+v", r[0].Extra)
	}
	count, stat = []byte(count2), []byte(stat2)
	got = nil
	c.Poll(context.Background())
	sta = byKind(sample.KindWiFiSta)
	if sta[0].Extra["tx_pkts"] != uint64(100) || sta[0].Extra["rx_pkts"] != uint64(100) || sta[0].Extra["tx_bytes"] != uint64(10000) {
		t.Errorf("deltas: %+v", sta[0].Extra)
	}
	radio := byKind(sample.KindWiFiRadio)
	if len(radio) != 1 || radio[0].Extra["tx_success"] != uint64(990) || radio[0].Extra["retrans_pct"] != 4.5 ||
		radio[0].Extra["tx_fail_pct"] != 9.2 || radio[0].Extra["temp_c"] != 64 {
		t.Errorf("radio: %+v", radio)
	}
	if cx := c.ClientContext("id-eb"); cx["radio_retrans_pct"] != 4.5 {
		t.Errorf("context radio share: %+v", cx)
	}

	// A station that is gone leaves.
	stainfo = []byte(strings.SplitN(string(stainfo), "\n", 2)[0] + "\nsta_cnt=0\n")
	got = nil
	c.Poll(context.Background())
	ev = byKind(sample.KindEvent)
	if len(ev) != 2 || ev[0].Extra["event"] != "wifi_leave" {
		t.Errorf("leave events: %+v", ev)
	}
}
