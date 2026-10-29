package wifi

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseStaInfo(t *testing.T) {
	s := ParseStaInfo(fixture(t, "sta_info.txt"))
	if s.Chanspec != "112/80" || s.IdleS != 0 || s.InNetworkS != 226 || s.PowerSave {
		t.Errorf("header fields: %+v", s)
	}
	if !s.HasRSSI || s.RSSI != -34 || len(s.AntennaNoise) != 4 || s.AntennaNoise[1] != -91 {
		t.Errorf("signal: %+v", s)
	}
	if s.TxRateKbps != 866667 || s.RxRateKbps != 780000 || s.TxRetries != 898 || s.TxPktsSent != 7378 ||
		s.TxRetryExhausted != 2 || s.TxFailures != 2 || s.RxUcastPkts != 9249 || s.RxRetried != 22 {
		t.Errorf("counters: %+v", s)
	}
	if s.LinkBandwidthMHz != 80 || !strings.HasPrefix(s.TxNrate, "vht mcs 9 Nss 2") {
		t.Errorf("rate: %+v", s)
	}
	ps := ParseStaInfo([]byte("\t flags 0x11e13b: BRCM WME PS N_CAP\n"))
	if !ps.PowerSave {
		t.Error("PS flag not read")
	}
}

func TestParseChanimCountersStatus(t *testing.T) {
	c, ok := ParseChanim(fixture(t, "chanim_5g.txt"))
	if !ok || c.Chanspec != "112/80" || c.Values["busy"] != 37 || c.Values["obss"] != 9 || c.Values["knoise"] != -88 {
		t.Errorf("chanim: %+v", c)
	}
	if _, ok := c.Values["timestamp"]; ok {
		t.Error("timestamp kept")
	}
	n := ParseCounters(fixture(t, "counters.txt"))
	if n["txframe"] != 145946446 || n["txretrans"] != 2662706 || n["txfail"] != 52778 || n["d11_txnoack"] != 242890 {
		t.Errorf("counters: txframe=%d txretrans=%d txfail=%d", n["txframe"], n["txretrans"], n["txfail"])
	}
	s := ParseStatus(fixture(t, "status_5g.txt"))
	if s.Band != "5GHz" || s.Channel != 112 || s.WidthMHz != 80 || s.NoiseDBm != -88 || s.QBSSUtilPct != 29 || s.BeaconMs != 100 {
		t.Errorf("status: %+v", s)
	}
	s2 := ParseStatus(fixture(t, "status_24g.txt"))
	if s2.Band != "2.4GHz" || s2.Channel != 6 || s2.WidthMHz != 20 {
		t.Errorf("status 2.4: %+v", s2)
	}
}

func TestParseMesh(t *testing.T) {
	m, err := ParseMesh(fixture(t, "mesh.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Nodes) != 2 {
		t.Fatalf("nodes: %+v", m.Nodes)
	}
	var ext MeshNode
	for _, n := range m.Nodes {
		if n.Mode == "AP" {
			ext = n
		}
	}
	if ext.Hostname != "WX5600-AP-17479" || ext.Backhaul != "IEEE 802.3u" || ext.Parent == "" {
		t.Errorf("extender: %+v", ext)
	}
	wifi := 0
	for _, c := range m.Clients {
		if c.Node == ext.ID && c.WiFi {
			wifi++
			if !c.HasRadio || c.RSSI >= 0 || c.Band == "" {
				t.Errorf("client %+v", c)
			}
		}
	}
	if wifi != 4 {
		t.Errorf("extender wifi clients: %d", wifi)
	}
}

func TestCollectorPoll(t *testing.T) {
	sta := "02:00:00:aa:bb:01"
	staInfo := fixture(t, "sta_info.txt")
	responses := map[string][]byte{
		"-i wl0 bss":             []byte("up\n"),
		"-i wl1 bss":             []byte("down\n"),
		"-i wl0 status":          fixture(t, "status_5g.txt"),
		"-i wl0 assoclist":       []byte("assoclist " + sta + "\n"),
		"-i wl0 sta_info " + sta: staInfo,
		"-i wl0 chanim_stats":    fixture(t, "chanim_5g.txt"),
		"-i wl0 counters":        fixture(t, "counters.txt"),
	}
	run := func(_ context.Context, args ...string) ([]byte, error) {
		if b, ok := responses[strings.Join(args, " ")]; ok {
			return b, nil
		}
		return nil, errors.New("unexpected " + strings.Join(args, " "))
	}
	fsys := fstest.MapFS{
		"sys/class/net/wl0/type": {Data: []byte("1\n")},
		"sys/class/net/wl1/type": {Data: []byte("1\n")},
		"sys/class/net/br0/type": {Data: []byte("1\n")},
		"tmp/zy1905.json":        {Data: fixture(t, "mesh.json")},
	}
	var got []sample.Sample
	c := New(Options{Run: run, FS: fsys, MeshFile: "/tmp/zy1905.json", Emit: func(s sample.Sample) { got = append(got, s) },
		ID: func(m net.HardwareAddr) string { return "id-" + m.String() }, Now: func() time.Time { return time.Unix(1000, 0) }})
	c.Poll(context.Background())

	kinds := map[sample.Kind]int{}
	events := map[string]int{}
	for _, s := range got {
		kinds[s.Kind]++
		if s.Kind == sample.KindEvent {
			events[s.Extra["event"].(string)]++
		}
	}
	// One local station, four extender Wi-Fi clients, one radio.
	if kinds[sample.KindWiFiSta] != 5 || kinds[sample.KindWiFiRadio] != 1 || events["wifi_join"] != 5 || kinds[sample.KindMeshNode] != 2 {
		t.Fatalf("kinds %v events %v", kinds, events)
	}
	for _, s := range got {
		if s.Kind == sample.KindMeshNode && s.Extra["node_mode"] == "AP" {
			if s.TargetID != "mesh/WX5600-AP-17479" || s.DstIP != "192.168.1.2" || s.Extra["parent"] != cpeNode || s.Extra["backhaul"] != "IEEE 802.3u" {
				t.Errorf("extender node %+v", s)
			}
		}
	}
	cx := c.ClientContext("id-" + sta)
	if cx["node"] != cpeNode || cx["band"] != "5GHz" || cx["rssi"] != -34 {
		t.Errorf("context %v", cx)
	}

	// Second poll: the station's counters moved, so deltas appear; no new
	// joins.
	second := strings.Replace(string(staInfo), "tx pkts retries: 898", "tx pkts retries: 908", 1)
	second = strings.Replace(second, "tx total pkts sent: 7378", "tx total pkts sent: 7478", 1)
	responses["-i wl0 sta_info "+sta] = []byte(second)
	got = nil
	c.Poll(context.Background())
	for _, s := range got {
		if s.Kind == sample.KindEvent {
			t.Errorf("unexpected event %v", s.Extra)
		}
		if s.Kind == sample.KindWiFiSta && s.Extra["source"] == "wl" {
			if s.Extra["tx_retries"] != uint64(10) {
				t.Errorf("retries delta %v", s.Extra["tx_retries"])
			}
		}
		if s.Kind == sample.KindWiFiRadio {
			if s.Extra["txframe"] != uint64(0) || s.Extra["chanim_busy"] != int64(37) {
				t.Errorf("radio %v", s.Extra)
			}
		}
	}
	// The radio's busy share from the first poll and the retry share of
	// the second reach the client context used by the detector.
	cx = c.ClientContext("id-" + sta)
	if cx["radio_busy"] != int64(37) || cx["retry_pct"] == nil {
		t.Errorf("context %v", cx)
	}
}
