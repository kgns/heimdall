package client

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

const profilerJSON = `{"SPAirPortDataType":[{"spairport_airport_interfaces":[
 {"_name":"en0","spairport_current_network_information":{"_name":"<redacted>",
  "spairport_network_channel":"112 (5GHz, 80MHz)","spairport_network_mcs":11,
  "spairport_network_phymode":"802.11ax","spairport_network_rate":1200,
  "spairport_signal_noise":"-48 dBm / -93 dBm"}},
 {"_name":"awdl0"}]}]}`

func TestParseSystemProfiler(t *testing.T) {
	w, err := ParseSystemProfiler([]byte(profilerJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := WiFiInfo{Iface: "en0", Connected: true, RSSI: -48, Noise: -93, Channel: 112, Band: "5GHz",
		WidthMHz: 80, PHYMode: "802.11ax", TxRateMbps: 1200, MCS: 11, HasMCS: true}
	if w != want {
		t.Errorf("got %+v", w)
	}
	if _, err := ParseSystemProfiler([]byte(`{"SPAirPortDataType":[{"spairport_airport_interfaces":[{"_name":"en0"}]}]}`)); err == nil {
		t.Error("disconnected interface parsed")
	}
}

func TestClientSamples(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	var mu sync.Mutex
	var got []sample.Sample
	c := New(Options{
		Targets:  []Target{{Service: "svc", Category: "browsing", Host: "svc.example", Port: port}},
		Interval: 50 * time.Millisecond, PingInterval: 50 * time.Millisecond, Timeout: time.Second,
		Emit: func(s sample.Sample) { mu.Lock(); got = append(got, s); mu.Unlock() },
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
		Gateway: func() (netip.Addr, error) { return netip.Addr{}, nil },
		WiFi: func(context.Context) (WiFiInfo, error) {
			return ParseSystemProfiler([]byte(profilerJSON))
		},
		WiFiInterval: time.Hour,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	c.Run(ctx)

	mu.Lock()
	defer mu.Unlock()
	var tcp, wifi int
	for _, s := range got {
		switch s.Kind {
		case sample.KindTCP:
			tcp++
			if s.Status != sample.StatusOK || s.RTTms == nil || s.Extra["local_ip"] != "127.0.0.1" || s.Extra["local_port"] == nil ||
				s.TargetID != "client/svc/svc.example" || s.DstPort != port {
				t.Errorf("tcp sample %+v", s)
			}
		case sample.KindWiFiSta:
			wifi++
			if s.Extra["rssi"] != -48 || s.Extra["snr"] != 45 || s.Extra["band"] != "5GHz" {
				t.Errorf("wifi sample %+v", s.Extra)
			}
		}
	}
	if tcp < 2 || wifi != 1 {
		t.Errorf("tcp=%d wifi=%d", tcp, wifi)
	}
}
