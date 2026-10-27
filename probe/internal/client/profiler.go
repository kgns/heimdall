package client

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	reSignalNoise = regexp.MustCompile(`(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm`)
	reChannel     = regexp.MustCompile(`^(\d+)\s*\(([\d.]+GHz)(?:,\s*(\d+)MHz)?\)`)
)

// ParseSystemProfiler reads the connected interface from the JSON output
// of `system_profiler SPAirPortDataType -json` on macOS.
func ParseSystemProfiler(b []byte) (WiFiInfo, error) {
	var doc struct {
		Data []struct {
			Interfaces []map[string]any `json:"spairport_airport_interfaces"`
		} `json:"SPAirPortDataType"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return WiFiInfo{}, err
	}
	for _, d := range doc.Data {
		for _, ifc := range d.Interfaces {
			cur, ok := ifc["spairport_current_network_information"].(map[string]any)
			if !ok {
				continue
			}
			w := WiFiInfo{Connected: true}
			w.Iface, _ = ifc["_name"].(string)
			if m := reSignalNoise.FindStringSubmatch(str(cur["spairport_signal_noise"])); m != nil {
				w.RSSI, _ = strconv.Atoi(m[1])
				w.Noise, _ = strconv.Atoi(m[2])
			}
			if m := reChannel.FindStringSubmatch(str(cur["spairport_network_channel"])); m != nil {
				w.Channel, _ = strconv.Atoi(m[1])
				w.Band = m[2]
				w.WidthMHz, _ = strconv.Atoi(m[3])
			}
			w.PHYMode = str(cur["spairport_network_phymode"])
			w.TxRateMbps = number(cur["spairport_network_rate"])
			if v, ok := cur["spairport_network_mcs"]; ok {
				w.MCS, w.HasMCS = int(number(v)), true
			}
			return w, nil
		}
	}
	return WiFiInfo{}, errors.New("no connected Wi-Fi interface")
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func number(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	}
	return 0
}
