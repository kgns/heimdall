// Package lan finds the clients on the CPE's LAN bridges and identifies them
// only by a salted hash of their MAC address.
package lan

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Client is one LAN host.
type Client struct {
	ID    string // salted hash of the MAC
	MAC   net.HardwareAddr
	IP    netip.Addr
	Iface string // bridge, e.g. br0
	// Port is the bridge member the MAC was last seen on, e.g. wl0 or
	// eth0.0, and Medium classifies it as "wifi", "wired" or "".
	Port   string
	Medium string
}

const (
	arpFlagComplete = 0x2
)

// ARPEntry is one complete /proc/net/arp entry.
type ARPEntry struct {
	IP    netip.Addr
	MAC   net.HardwareAddr
	Iface string
}

// ReadARP parses proc/net/arp and returns complete entries.
func ReadARP(fsys fs.FS) ([]ARPEntry, error) {
	f, err := fsys.Open("proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseARP(f)
}

// ParseARP parses the /proc/net/arp format.
func ParseARP(r io.Reader) ([]ARPEntry, error) {
	var out []ARPEntry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[0] == "IP" {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&arpFlagComplete == 0 {
			continue
		}
		ip, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(f[3])
		if err != nil || isZeroMAC(mac) {
			continue
		}
		out = append(out, ARPEntry{IP: ip, MAC: mac, Iface: f[5]})
	}
	return out, sc.Err()
}

// Lease is one dnsmasq lease.
type Lease struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// ReadLeases parses a dnsmasq lease file at an absolute path. Hostnames and
// client IDs are not kept.
func ReadLeases(fsys fs.FS, abs string) ([]Lease, error) {
	f, err := fsys.Open(strings.TrimPrefix(path.Clean("/"+abs), "/"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Lease
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 {
			continue
		}
		mac, err := net.ParseMAC(fl[1])
		if err != nil {
			continue
		}
		ip, err := netip.ParseAddr(fl[2])
		if err != nil || !ip.Is4() {
			continue
		}
		out = append(out, Lease{IP: ip, MAC: mac})
	}
	return out, sc.Err()
}

// fdbEntrySize is sizeof(struct __fdb_entry) from <linux/if_bridge.h>:
// mac[6], port_no, is_local, ageing_timer_value (u32), port_hi, pad, u16.
const fdbEntrySize = 16

// FDBEntry maps a MAC to a bridge port number.
type FDBEntry struct {
	MAC   net.HardwareAddr
	Port  int
	Local bool
}

// ParseBrForward parses the binary sys/class/net/<br>/brforward table. The
// ageing field is in host byte order, which does not matter here because
// it is not used.
func ParseBrForward(b []byte) []FDBEntry {
	var out []FDBEntry
	for len(b) >= fdbEntrySize {
		e := b[:fdbEntrySize]
		b = b[fdbEntrySize:]
		out = append(out, FDBEntry{
			MAC:   append(net.HardwareAddr(nil), e[0:6]...),
			Port:  int(e[12])<<8 | int(e[6]),
			Local: e[7] != 0,
		})
	}
	return out
}

// BridgePorts returns port number to member interface name for a bridge,
// from sys/class/net/<br>/brif/<member>/port_no.
func BridgePorts(fsys fs.FS, bridge string) (map[int]string, error) {
	dir := path.Join("sys/class/net", bridge, "brif")
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for _, e := range entries {
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name(), "port_no"))
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 16)
		if err != nil {
			continue
		}
		out[int(n)] = e.Name()
	}
	return out, nil
}

// PortOf returns, for each MAC learned on bridge, the member interface.
func PortOf(fsys fs.FS, bridge string) map[string]string {
	ports, err := BridgePorts(fsys, bridge)
	if err != nil {
		return nil
	}
	raw, err := fs.ReadFile(fsys, path.Join("sys/class/net", bridge, "brforward"))
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range ParseBrForward(raw) {
		if e.Local {
			continue
		}
		if name, ok := ports[e.Port]; ok {
			out[e.MAC.String()] = name
		}
	}
	return out
}

// Medium classifies a bridge member by its name: Wi-Fi radios and their
// virtual interfaces on common CPE chipsets, or wired otherwise.
func Medium(port string) string {
	switch {
	case port == "":
		return ""
	case strings.HasPrefix(port, "wl"), strings.HasPrefix(port, "ra"), strings.HasPrefix(port, "ath"),
		strings.HasPrefix(port, "wlan"), strings.HasPrefix(port, "apcli"), strings.HasPrefix(port, "rai"):
		return "wifi"
	default:
		return "wired"
	}
}

// Hasher derives stable client IDs from MAC addresses without revealing
// them.
type Hasher struct{ key []byte }

// NewHasher uses key as the HMAC key.
func NewHasher(key []byte) Hasher { return Hasher{key: key} }

// ID returns a 12-hex-digit identifier for mac.
func (h Hasher) ID(mac net.HardwareAddr) string {
	m := hmac.New(sha256.New, h.key)
	m.Write([]byte(strings.ToLower(mac.String())))
	return hex.EncodeToString(m.Sum(nil)[:6])
}

// LoadOrCreateSalt reads a hex salt from file, creating it with a random
// value on first use. An empty path or an unwritable location returns a
// random salt that lasts for this process only, and a non-nil error that
// explains why.
func LoadOrCreateSalt(file string) ([]byte, error) {
	random := func() []byte {
		b := make([]byte, 16)
		rand.Read(b)
		return b
	}
	if file == "" {
		return random(), errors.New("no salt file configured; client IDs change on restart")
	}
	if b, err := os.ReadFile(file); err == nil {
		s, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err == nil && len(s) >= 16 {
			return s, nil
		}
		return random(), fmt.Errorf("salt file %s is malformed; using a temporary salt", file)
	}
	s := random()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return s, fmt.Errorf("salt file %s: %w; using a temporary salt", file, err)
	}
	if err := os.WriteFile(file, []byte(hex.EncodeToString(s)+"\n"), 0o600); err != nil {
		return s, fmt.Errorf("salt file %s: %w; using a temporary salt", file, err)
	}
	return s, nil
}

// Discover merges ARP entries and leases on interfaces matching patterns
// (path.Match syntax, e.g. "br*"), keeps at most max clients ordered by IP,
// and fills in the bridge port where the bridge table knows it. inLAN
// decides whether an address is directly reachable on the LAN.
func Discover(fsys fs.FS, leaseFile string, patterns []string, max int, h Hasher, inLAN func(netip.Addr) (string, bool)) ([]Client, error) {
	arp, err := ReadARP(fsys)
	if err != nil {
		return nil, err
	}
	byIP := map[netip.Addr]Client{}
	match := func(iface string) bool {
		for _, p := range patterns {
			if ok, _ := path.Match(p, iface); ok {
				return true
			}
		}
		return false
	}
	for _, e := range arp {
		if !match(e.Iface) {
			continue
		}
		byIP[e.IP] = Client{MAC: e.MAC, IP: e.IP, Iface: e.Iface}
	}
	if leaseFile != "" {
		if leases, err := ReadLeases(fsys, leaseFile); err == nil {
			for _, l := range leases {
				if _, seen := byIP[l.IP]; seen {
					continue
				}
				iface, ok := inLAN(l.IP)
				if !ok || !match(iface) {
					continue
				}
				byIP[l.IP] = Client{MAC: l.MAC, IP: l.IP, Iface: iface}
			}
		}
	}

	ports := map[string]map[string]string{}
	var out []Client
	for _, c := range byIP {
		if iface, ok := inLAN(c.IP); !ok || iface != c.Iface {
			continue
		}
		if _, ok := ports[c.Iface]; !ok {
			ports[c.Iface] = PortOf(fsys, c.Iface)
		}
		c.Port = ports[c.Iface][c.MAC.String()]
		c.Medium = Medium(c.Port)
		c.ID = h.ID(c.MAC)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out, nil
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}
