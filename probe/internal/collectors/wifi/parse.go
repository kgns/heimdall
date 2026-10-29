// Package wifi reads Wi-Fi statistics on Broadcom CPEs through the wl
// utility and on MediaTek access points through iwpriv, and the EasyMesh
// topology that Zyxel CPEs write as JSON, which lists the clients of every
// mesh node with their signal.
package wifi

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// StaInfo is the part of `wl sta_info` the collector reports.
type StaInfo struct {
	Chanspec   string
	IdleS      int64
	InNetworkS int64
	// PowerSave is set while the station is in power-save mode; frames
	// for it wait at the access point until it wakes.
	PowerSave bool
	// Counters since association.
	TxUcastPkts, RxUcastPkts    uint64
	TxUcastBytes, RxUcastBytes  uint64
	TxFailures                  uint64
	TxPktsSent, TxRetries       uint64
	TxRetryExhausted, RxRetried uint64
	RxDecryptFailures           uint64
	TxRateKbps, RxRateKbps      int64
	RSSI                        int
	HasRSSI                     bool
	AntennaRSSI, AntennaNoise   []int
	TxNrate, RxNrate            string
	LinkBandwidthMHz            int
}

var (
	reInt     = regexp.MustCompile(`-?\d+`)
	reNrateBW = regexp.MustCompile(`bw(\d+)`)
)

func firstInt(s string) (int64, bool) {
	m := reInt.FindString(s)
	if m == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(m, 10, 64)
	return v, err == nil
}

func ints(s string) []int {
	var out []int
	for _, m := range reInt.FindAllString(s, -1) {
		if v, err := strconv.Atoi(m); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// ParseStaInfo parses `wl -i <if> sta_info <mac>`.
func ParseStaInfo(b []byte) StaInfo {
	var s StaInfo
	sc := bufio.NewScanner(bytes.NewReader(b))
	nrate := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		key, val, hasColon := strings.Cut(line, ":")
		u := func() uint64 {
			v, _ := firstInt(val)
			return uint64(max(v, 0))
		}
		switch {
		case nrate != "":
			if nrate == "tx" {
				s.TxNrate = line
			} else {
				s.RxNrate = line
			}
			nrate = ""
			continue
		case line == "tx nrate":
			nrate = "tx"
			continue
		case line == "rx nrate":
			nrate = "rx"
			continue
		case strings.HasPrefix(line, "chanspec "):
			s.Chanspec = strings.Fields(line)[1]
		case strings.HasPrefix(line, "idle "):
			s.IdleS, _ = firstInt(line)
		case strings.HasPrefix(line, "in network "):
			s.InNetworkS, _ = firstInt(line)
		case strings.HasPrefix(line, "flags "):
			_, names, _ := strings.Cut(line, ":")
			for _, f := range strings.Fields(names) {
				if f == "PS" {
					s.PowerSave = true
				}
			}
		case strings.HasPrefix(line, "link bandwidth"):
			v, _ := firstInt(line)
			s.LinkBandwidthMHz = int(v)
		case !hasColon:
			continue
		}
		switch key {
		case "tx ucast pkts":
			s.TxUcastPkts = u()
		case "tx ucast bytes":
			s.TxUcastBytes = u()
		case "rx ucast pkts":
			s.RxUcastPkts = u()
		case "rx ucast bytes":
			s.RxUcastBytes = u()
		case "tx failures":
			s.TxFailures = u()
		case "tx total pkts sent":
			s.TxPktsSent = u()
		case "tx pkts retries":
			s.TxRetries = u()
		case "tx pkts retry exhausted":
			s.TxRetryExhausted = u()
		case "rx total pkts retried":
			s.RxRetried = u()
		case "rx decrypt failures":
			s.RxDecryptFailures = u()
		case "rate of last tx pkt":
			s.TxRateKbps, _ = firstInt(val)
		case "rate of last rx pkt":
			s.RxRateKbps, _ = firstInt(val)
		case "smoothed rssi":
			if v, ok := firstInt(val); ok && v < 0 {
				s.RSSI, s.HasRSSI = int(v), true
			}
		case "per antenna average rssi of rx data frames":
			s.AntennaRSSI = ints(val)
		case "per antenna noise floor":
			s.AntennaNoise = ints(val)
		}
	}
	if !s.HasRSSI {
		// Fall back to the strongest antenna.
		for _, v := range s.AntennaRSSI {
			if v < 0 && (!s.HasRSSI || v > s.RSSI) {
				s.RSSI, s.HasRSSI = v, true
			}
		}
	}
	if s.LinkBandwidthMHz == 0 {
		if m := reNrateBW.FindStringSubmatch(s.TxNrate); m != nil {
			s.LinkBandwidthMHz, _ = strconv.Atoi(m[1])
		}
	}
	return s
}

// Chanim is one `wl chanim_stats` row. The time shares are percentages of
// the last measurement period.
type Chanim struct {
	Chanspec string
	Values   map[string]int64
}

// ParseChanim parses `wl -i <if> chanim_stats`: a header row naming the
// columns and a row of values.
func ParseChanim(b []byte) (Chanim, bool) {
	var header []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if f[0] == "chanspec" {
			header = f
			continue
		}
		if header == nil || len(f) != len(header) {
			continue
		}
		c := Chanim{Chanspec: f[0], Values: map[string]int64{}}
		for i := 1; i < len(f); i++ {
			if header[i] == "timestamp" {
				continue
			}
			if v, err := strconv.ParseInt(f[i], 10, 64); err == nil {
				c.Values[header[i]] = v
			}
		}
		return c, true
	}
	return Chanim{}, false
}

// ParseCounters parses the "name value" pairs of `wl counters`.
func ParseCounters(b []byte) map[string]uint64 {
	out := map[string]uint64{}
	f := strings.Fields(string(b))
	for i := 0; i+1 < len(f); i++ {
		name := strings.TrimSuffix(f[i], ":")
		if name == "" || name[0] < 'a' || name[0] > 'z' {
			continue
		}
		v, err := strconv.ParseUint(f[i+1], 10, 64)
		if err != nil {
			continue
		}
		out[name] = v
		i++
	}
	return out
}

// Status is the part of `wl status` the collector reports.
type Status struct {
	Band          string // "2.4GHz", "5GHz" or "6GHz"
	Channel       int    // primary channel
	WidthMHz      int
	NoiseDBm      int
	BeaconMs      int
	QBSSUtilPct   int
	HasQBSSUtil   bool
	ChanspecLabel string
}

var (
	reChanspec = regexp.MustCompile(`Chanspec:\s*([\d.]+GHz) channel \d+ (\d+)MHz`)
	rePrimary  = regexp.MustCompile(`Primary channel:\s*(\d+)`)
	reNoise    = regexp.MustCompile(`noise:\s*(-?\d+) dBm`)
	reBeacon   = regexp.MustCompile(`Beacon Interval:\s*(\d+)`)
	reQBSS     = regexp.MustCompile(`QBSS Channel Utilization: 0x[0-9a-fA-F]+ \((\d+) %\)`)
	reChannel  = regexp.MustCompile(`Channel:\s*(\S+)`)
)

// ParseStatus parses `wl -i <if> status`.
func ParseStatus(b []byte) Status {
	var s Status
	t := string(b)
	if m := reChanspec.FindStringSubmatch(t); m != nil {
		s.Band = m[1]
		s.WidthMHz, _ = strconv.Atoi(m[2])
	}
	if m := rePrimary.FindStringSubmatch(t); m != nil {
		s.Channel, _ = strconv.Atoi(m[1])
	}
	if m := reNoise.FindStringSubmatch(t); m != nil {
		s.NoiseDBm, _ = strconv.Atoi(m[1])
	}
	if m := reBeacon.FindStringSubmatch(t); m != nil {
		s.BeaconMs, _ = strconv.Atoi(m[1])
	}
	if m := reQBSS.FindStringSubmatch(t); m != nil {
		s.QBSSUtilPct, _ = strconv.Atoi(m[1])
		s.HasQBSSUtil = true
	}
	if m := reChannel.FindStringSubmatch(t); m != nil {
		s.ChanspecLabel = m[1]
	}
	return s
}

// ParseAssoclist parses `wl -i <if> assoclist`.
func ParseAssoclist(b []byte) []net.HardwareAddr {
	var out []net.HardwareAddr
	for _, f := range strings.Fields(string(b)) {
		if m, err := net.ParseMAC(f); err == nil && len(m) == 6 {
			out = append(out, m)
		}
	}
	return out
}

// MeshNode is one EasyMesh device: the controller (the CPE) or an agent
// such as an extender.
type MeshNode struct {
	ID       string // IEEE 1905 AL MAC
	Hostname string
	IP       string
	Mode     string // "Router" or "AP"
	Parent   string
	// Backhaul is the media type of the node's link towards its parent.
	Backhaul string
}

// MeshClient is a non-mesh device attached to a node.
type MeshClient struct {
	MAC      net.HardwareAddr
	Node     string // MeshNode.ID
	Media    string
	WiFi     bool
	Band     string
	RateMbps int64
	RSSI     int
	SNR      int
	HasRadio bool
	Tx, Rx   uint64
}

// Mesh is the parsed topology.
type Mesh struct {
	Nodes   map[string]MeshNode
	Clients []MeshClient
}

// ParseMesh parses the Zyxel zy1905 topology file, a TR-181 style tree of
// Device.X_<OUI>_IEEE1905.AL.NetworkTopology.IEEE1905Device.<n> objects.
func ParseMesh(b []byte) (Mesh, error) {
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return Mesh{}, err
	}
	m := Mesh{Nodes: map[string]MeshNode{}}
	topo := findTopology(root)
	for k, v := range topo {
		dev, ok := v.(map[string]any)
		if !ok || !strings.HasPrefix(k, "IEEE1905Device.") {
			continue
		}
		node := MeshNode{
			ID: strings.ToLower(str(dev["IEEE1905Id"])), Hostname: str(dev["Hostname"]),
			IP: str(dev["DeviceIP"]), Mode: str(dev["DeviceMode"]), Parent: strings.ToLower(str(dev["Parent"])),
		}
		for k2, v2 := range dev {
			obj, ok := v2.(map[string]any)
			if !ok {
				continue
			}
			switch {
			case strings.HasPrefix(k2, "IEEE1905Neighbor."):
				if node.Parent != "" && strings.EqualFold(str(obj["NeighborDeviceId"]), node.Parent) {
					node.Backhaul = mediaName(str(obj["MediaType"]))
				}
			case strings.HasPrefix(k2, "NonIEEE1905Neighbor."):
				mac, err := net.ParseMAC(str(obj["NeighborInterfaceId"]))
				if err != nil {
					continue
				}
				c := MeshClient{MAC: mac, Node: node.ID, Media: mediaName(str(obj["MediaType"])), Band: str(obj["Band"])}
				c.WiFi = strings.HasPrefix(str(obj["MediaType"]), "IEEE 802.11")
				if rssi, ok := num(obj["RSSI"]); ok && c.WiFi {
					c.RSSI, c.HasRadio = int(rssi), true
					snr, _ := num(obj["SNR"])
					c.SNR = int(snr)
					c.RateMbps, _ = num(obj["RATE"])
				}
				tx, _ := num(obj["Tx"])
				rx, _ := num(obj["Rx"])
				c.Tx, c.Rx = uint64(max(tx, 0)), uint64(max(rx, 0))
				m.Clients = append(m.Clients, c)
			}
		}
		m.Nodes[node.ID] = node
	}
	return m, nil
}

func findTopology(v any) map[string]any {
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	if t, ok := obj["NetworkTopology"].(map[string]any); ok {
		return t
	}
	for _, c := range obj {
		if t := findTopology(c); t != nil {
			return t
		}
	}
	return nil
}

// mediaName shortens "IEEE 802.3u(IEEE 802.3u Fast Ethernet)" to its
// first part, "IEEE 802.3u".
func mediaName(s string) string {
	if i := strings.IndexByte(s, '('); i > 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}
