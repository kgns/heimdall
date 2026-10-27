//go:build linux

package client

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strings"
)

// Gateway returns the default IPv4 gateway from /proc/net/route.
func Gateway() (netip.Addr, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 || fl[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(fl[2])
		if err != nil || len(b) != 4 {
			continue
		}
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(b))
		return netip.AddrFrom4(a), nil
	}
	return netip.Addr{}, errors.New("no default gateway")
}

// ReadWiFi is not implemented on Linux.
var ReadWiFi func(ctx context.Context) (WiFiInfo, error)
