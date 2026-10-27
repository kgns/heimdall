//go:build darwin

package client

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"strings"
)

// Gateway returns the default IPv4 gateway from `route -n get default`.
func Gateway() (netip.Addr, error) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return netip.Addr{}, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && k == "gateway" {
			return netip.ParseAddr(strings.TrimSpace(v))
		}
	}
	return netip.Addr{}, errors.New("no default gateway")
}

// ReadWiFi asks system_profiler for the current Wi-Fi network. It takes a
// second or two.
func ReadWiFi(ctx context.Context) (WiFiInfo, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/system_profiler", "SPAirPortDataType", "-json").Output()
	if err != nil {
		return WiFiInfo{}, err
	}
	return ParseSystemProfiler(out)
}
