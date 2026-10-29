package wifi

import (
	"bufio"
	"bytes"
	"context"
	"io/fs"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// MediaTek access points name their virtual interfaces after the radio:
// ra0..raN on one band and rax0..raxN on the other on two-band chips
// (rai, rae and ray on others). The driver reports per band, so one
// interface of each radio is queried.

// MTKStation is one row of `iwpriv <if> show stainfo`.
type MTKStation struct {
	MAC net.HardwareAddr
	// BSS is the driver's index of the BSS the station is on.
	BSS int
	// PowerSave is set while the station is in power-save mode.
	PowerSave bool
	// RSSI holds the station's signal on each receive chain; chains that
	// are not in use are left out.
	RSSI    []int
	PhyMode string // transmit PHY mode, such as HE_SU or HT_MM
	BWMHz   int    // transmit bandwidth
	MCS     string // transmit MCS, such as 2S-M11 (two streams, MCS 11)
	// The Idle column is not kept: it reads about 60 for stations that
	// are in use as well, so it does not tell how long one has been idle.
	TxRateMb int64
	RxRateMb int64
}

// BestRSSI is the strongest chain, or false when none is known.
func (s MTKStation) BestRSSI() (int, bool) {
	best, ok := 0, false
	for _, v := range s.RSSI {
		if !ok || v > best {
			best, ok = v, true
		}
	}
	return best, ok
}

// ParseMTKStaInfo parses `iwpriv <if> show stainfo`: a header row, then a
// row per station followed by indented detail rows.
func ParseMTKStaInfo(b []byte) []MTKStation {
	var out []MTKStation
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 16 {
			continue
		}
		mac, err := net.ParseMAC(f[0])
		if err != nil || len(mac) != 6 || f[1] != "STA" {
			continue
		}
		s := MTKStation{MAC: mac, PhyMode: before(f[9], "/"), MCS: before(f[11], "/")}
		s.BSS, _ = strconv.Atoi(f[4])
		s.PowerSave = f[5] == "1"
		for _, r := range strings.Split(f[8], "/") {
			// Unused chains read 0 or a floor value such as -127.
			if v, err := strconv.Atoi(r); err == nil && v < 0 && v > -100 {
				s.RSSI = append(s.RSSI, v)
			}
		}
		if bw := strings.TrimSuffix(before(f[10], "/"), "M"); bw != "" {
			s.BWMHz, _ = strconv.Atoi(bw)
		}
		tx, rx, _ := strings.Cut(f[15], "/")
		s.TxRateMb, _ = strconv.ParseInt(tx, 10, 64)
		s.RxRateMb, _ = strconv.ParseInt(rx, 10, 64)
		out = append(out, s)
	}
	return out
}

// MTKCounts are a station's traffic counters since it associated, from
// `iwpriv <if> show stacountinfo`.
type MTKCounts struct {
	TxPkts, RxPkts, TxBytes, RxBytes uint64
}

// ParseMTKStaCount parses `iwpriv <if> show stacountinfo`, keyed by MAC.
func ParseMTKStaCount(b []byte) map[string]MTKCounts {
	out := map[string]MTKCounts{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		mac, err := net.ParseMAC(f[0])
		if err != nil || len(mac) != 6 {
			continue
		}
		var v [4]uint64
		ok := true
		for i := range v {
			n, err := strconv.ParseUint(f[2+i], 10, 64)
			if err != nil {
				ok = false
				break
			}
			v[i] = n
		}
		if ok {
			out[mac.String()] = MTKCounts{TxPkts: v[0], RxPkts: v[1], TxBytes: v[2], RxBytes: v[3]}
		}
	}
	return out
}

// mtkStat maps `iwpriv <if> stat` labels to the names reported. The
// counters run since the driver started; the failures and retransmissions
// are per transmitted frame of the whole radio.
var mtkStat = map[string]string{
	"Tx success":           "tx_success",
	"Tx fail count":        "tx_fail",
	"Total retransmission": "tx_retrans",
	"Rx success":           "rx_success",
	"Rx with CRC":          "rx_crc",
}

// ParseMTKStat parses `iwpriv <if> stat`: "label = value" lines, some
// with a trailing ", PER=..." part. The temperature is returned apart.
func ParseMTKStat(b []byte) (counters map[string]uint64, tempC int, hasTemp bool) {
	counters = map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		label, val, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		label = strings.TrimSpace(label)
		val = strings.TrimSpace(val)
		val, _, _ = strings.Cut(val, ",")
		if label == "CurrentTemperature" {
			if t, err := strconv.Atoi(val); err == nil {
				tempC, hasTemp = t, true
			}
			continue
		}
		if name, ok := mtkStat[label]; ok {
			if n, err := strconv.ParseUint(val, 10, 64); err == nil {
				counters[name] = n
			}
		}
	}
	return counters, tempC, hasTemp
}

var reIwChannel = regexp.MustCompile(`Channel[:=](\d+)`)

// ParseIwconfigChannel returns the channel `iwconfig <if>` reports.
func ParseIwconfigChannel(b []byte) (int, bool) {
	m := reIwChannel.FindSubmatch(b)
	if m == nil {
		return 0, false
	}
	ch, err := strconv.Atoi(string(m[1]))
	return ch, err == nil && ch > 0
}

// bandOf names the band of a Wi-Fi channel number. Channels 1-14 are
// 2.4 GHz; 6 GHz channels share numbers with 5 GHz and are not told apart
// here.
func bandOf(ch int) string {
	if ch <= 14 {
		return "2.4GHz"
	}
	return "5GHz"
}

var mtkIface = regexp.MustCompile(`^(ra|rax|rai|rae|ray)(\d+)$`)

// mtkRadio is one radio and the virtual interfaces up on it.
type mtkRadio struct {
	prefix string
	ifaces map[int]string // BSS index to interface
	first  string         // the interface queried for the whole radio
}

// ifaceOf returns the interface a station is on: the bridge port its MAC
// was learned on when that is one of this radio's interfaces, else the
// radio's first interface. The BSS column is not used: on the WX5600 it
// counts the BSSes of both radios (a station on rax0 shows BSS 4, after
// ra0 to ra3), which does not map to an interface without knowing the
// driver's numbering.
func (r mtkRadio) ifaceOf(st MTKStation, ports map[string]string) string {
	if p, ok := ports[st.MAC.String()]; ok {
		if m := mtkIface.FindStringSubmatch(p); m != nil && m[1] == r.prefix {
			return p
		}
	}
	return r.first
}

// MTKRadios lists the MediaTek radios with at least one interface up,
// from sys/class/net.
func MTKRadios(fsys fs.FS) []mtkRadio {
	entries, err := fs.ReadDir(fsys, "sys/class/net")
	if err != nil {
		return nil
	}
	byPrefix := map[string]*mtkRadio{}
	for _, e := range entries {
		m := mtkIface.FindStringSubmatch(e.Name())
		if m == nil || !ifaceUp(fsys, e.Name()) {
			continue
		}
		idx, _ := strconv.Atoi(m[2])
		r := byPrefix[m[1]]
		if r == nil {
			r = &mtkRadio{prefix: m[1], ifaces: map[int]string{}}
			byPrefix[m[1]] = r
		}
		r.ifaces[idx] = e.Name()
	}
	var out []mtkRadio
	for _, r := range byPrefix {
		lowest := -1
		for i := range r.ifaces {
			if lowest < 0 || i < lowest {
				lowest = i
			}
		}
		r.first = r.ifaces[lowest]
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].prefix < out[j].prefix })
	return out
}

// ifaceUp reads IFF_UP from sys/class/net/<if>/flags. MediaTek interfaces
// report operstate "unknown" while up, so operstate is not used.
func ifaceUp(fsys fs.FS, iface string) bool {
	b, err := fs.ReadFile(fsys, "sys/class/net/"+iface+"/flags")
	if err != nil {
		return false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x")), 16, 64)
	return err == nil && v&1 != 0
}

// pollMTK reads every MediaTek radio and station once and emits their
// samples.
func (c *Collector) pollMTK(ctx context.Context) {
	ts := c.opt.Now().UnixMilli()
	node := c.opt.Node
	now := map[string]location{}
	ctxNew := map[string]map[string]any{}
	queried := 0
	var ports map[string]string
	if c.opt.PortOf != nil {
		ports = c.opt.PortOf()
	}
	for _, r := range MTKRadios(c.opt.FS) {
		band := ""
		channel := 0
		if out, err := c.opt.Exec(ctx, "iwconfig", r.first); err == nil {
			if ch, ok := ParseIwconfigChannel(out); ok {
				channel, band = ch, bandOf(ch)
			}
		}
		out, err := c.opt.Exec(ctx, "iwpriv", r.first, "show", "stainfo")
		if err != nil {
			continue
		}
		stations := ParseMTKStaInfo(out)
		var counts map[string]MTKCounts
		if out, err := c.opt.Exec(ctx, "iwpriv", r.first, "show", "stacountinfo"); err == nil {
			counts = ParseMTKStaCount(out)
		}
		radioRetrans, hasRetrans := c.pollMTKRadio(ctx, ts, r, band, channel, len(stations))
		for _, st := range stations {
			if queried >= c.opt.MaxStations {
				break
			}
			queried++
			iface := r.ifaceOf(st, ports)
			id := c.opt.ID(st.MAC)
			x := map[string]any{"client": id, "node": node, "iface": iface, "band": band, "source": "mtk",
				"ps": st.PowerSave, "tx_rate_mbps": float64(st.TxRateMb), "rx_rate_mbps": float64(st.RxRateMb)}
			rssi, hasRSSI := st.BestRSSI()
			if hasRSSI {
				x["rssi"] = rssi
				chains := make([]any, len(st.RSSI))
				for i, v := range st.RSSI {
					chains[i] = v
				}
				x["rssi_chains"] = chains
			}
			if st.PhyMode != "" {
				x["phy_mode"] = st.PhyMode
			}
			if st.MCS != "" {
				x["mcs"] = st.MCS
			}
			if st.BWMHz > 0 {
				x["bw_mhz"] = st.BWMHz
			}
			key := iface + "/" + st.MAC.String()
			if cur, ok := counts[st.MAC.String()]; ok {
				if prev, ok := c.prevMTK[key]; ok && cur.TxPkts >= prev.TxPkts && cur.RxPkts >= prev.RxPkts {
					x["tx_pkts"], x["rx_pkts"] = cur.TxPkts-prev.TxPkts, cur.RxPkts-prev.RxPkts
					if cur.TxBytes >= prev.TxBytes && cur.RxBytes >= prev.RxBytes {
						x["tx_bytes"], x["rx_bytes"] = cur.TxBytes-prev.TxBytes, cur.RxBytes-prev.RxBytes
					}
				}
				c.prevMTK[key] = cur
			}
			c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindWiFiSta, Category: "home", Service: "wifi",
				TargetID: "wifi/" + id, Status: sample.StatusOK, Extra: x})
			now[id] = location{node: node, iface: iface, band: band}
			cx := map[string]any{"node": node, "medium": "wifi", "wifi_iface": iface, "band": band, "ps": st.PowerSave,
				"tx_rate_mbps": x["tx_rate_mbps"]}
			if hasRSSI {
				cx["rssi"] = rssi
			}
			if hasRetrans {
				cx["radio_retrans_pct"] = radioRetrans
			}
			ctxNew[id] = cx
		}
	}
	if ctx.Err() != nil {
		return
	}
	for key := range c.prevMTK {
		iface, macs, _ := strings.Cut(key, "/")
		mac, _ := net.ParseMAC(macs)
		if loc, ok := now[c.opt.ID(mac)]; !ok || loc.iface != iface {
			delete(c.prevMTK, key)
		}
	}
	c.events(ts, now, true)
	c.publish(ts, ctxNew)
}

// pollMTKRadio emits the radio's sample and returns its retransmission
// share since the last poll.
func (c *Collector) pollMTKRadio(ctx context.Context, ts int64, r mtkRadio, band string, channel, stations int) (float64, bool) {
	x := map[string]any{"iface": r.first, "band": band, "stations": stations, "source": "mtk"}
	if channel > 0 {
		x["channel"] = channel
	}
	retrans, hasRetrans := 0.0, false
	if out, err := c.opt.Exec(ctx, "iwpriv", r.first, "stat"); err == nil {
		cur, temp, hasTemp := ParseMTKStat(out)
		if hasTemp {
			x["temp_c"] = temp
		}
		if prev, ok := c.prevRadio[r.first]; ok {
			for name := range cur {
				if cur[name] >= prev[name] {
					x[name] = cur[name] - prev[name]
				}
			}
			// The driver counts only the frames its CPU path sends, a few
			// per second when the traffic is offloaded, so shares of a
			// handful of frames are left out as noise.
			if sent, ok := delta(cur, prev, "tx_success"); ok && sent >= mtkMinFrames {
				if f, ok := delta(cur, prev, "tx_fail"); ok {
					x["tx_fail_pct"] = round1(100 * float64(f) / float64(sent+f))
				}
				if rt, ok := delta(cur, prev, "tx_retrans"); ok {
					retrans, hasRetrans = round1(100*float64(rt)/float64(sent)), true
					x["retrans_pct"] = retrans
				}
			}
		}
		c.prevRadio[r.first] = cur
	}
	c.opt.Emit(sample.Sample{TS: ts, Kind: sample.KindWiFiRadio, Category: "home", Service: "wifi",
		TargetID: "wifi/radio/" + r.first, Status: sample.StatusOK, Extra: x})
	return retrans, hasRetrans
}

// mtkMinFrames is the fewest frames sent in a poll interval for which the
// radio's failure and retransmission shares are reported.
const mtkMinFrames = 50

// delta is how much counter name grew since prev, or false when either
// value is missing or the counter went back (a driver restart).
func delta(cur, prev map[string]uint64, name string) (uint64, bool) {
	c, ok1 := cur[name]
	p, ok2 := prev[name]
	if !ok1 || !ok2 || c < p {
		return 0, false
	}
	return c - p, true
}

func before(s, sep string) string {
	v, _, _ := strings.Cut(s, sep)
	return v
}
