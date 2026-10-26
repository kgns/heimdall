package lan

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

const arpTable = `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.2      0x1         0x2         f0:87:56:8c:f7:a7     *        br0
192.168.1.3      0x1         0x2         78:c5:7d:2e:d6:2f     *        br0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        br0
192.168.3.20     0x1         0x2         aa:bb:cc:00:00:01     *        br2
10.234.0.1       0x1         0x2         00:11:22:33:44:55     *        ppp1.4
100.90.232.1     0x1         0x2         00:11:22:33:44:66     *        eth5.2
`

const leases = `1793000000 b4:2e:99:34:bf:f0 192.168.1.4 laptop 01:b4:2e:99:34:bf:f0
1793000000 f0:87:56:8c:f7:a7 192.168.1.2 phone *
1793000000 bc:c7:da:21:dc:d0 192.168.1.6 * *
1793000000 de:ad:be:ef:00:01 10.0.0.5 stray *
`

func fixture() fstest.MapFS {
	var fdb bytes.Buffer
	fdb.Write(putFDB("f0:87:56:8c:f7:a7", 3, false))
	fdb.Write(putFDB("78:c5:7d:2e:d6:2f", 1, false))
	fdb.Write(putFDB("b4:2e:99:34:bf:f0", 2, false))
	fdb.Write(putFDB("02:10:18:00:00:01", 1, true))
	return fstest.MapFS{
		"proc/net/arp":                          {Data: []byte(arpTable)},
		"var/dnsmasq/dnsmasq.leases":            {Data: []byte(leases)},
		"sys/class/net/br0/brif/eth0.0/port_no": {Data: []byte("0x1\n")},
		"sys/class/net/br0/brif/wl0/port_no":    {Data: []byte("0x2\n")},
		"sys/class/net/br0/brif/wl1.1/port_no":  {Data: []byte("0x3\n")},
		"sys/class/net/br0/brforward":           {Data: fdb.Bytes()},
	}
}

// putFDB encodes an entry the way the kernel does.
func putFDB(mac string, port int, local bool) []byte {
	b := make([]byte, fdbEntrySize)
	m, _ := net.ParseMAC(mac)
	copy(b, m)
	b[6] = byte(port)
	if local {
		b[7] = 1
	}
	binary.LittleEndian.PutUint32(b[8:], 1234)
	b[12] = byte(port >> 8)
	return b
}

func inLAN(a netip.Addr) (string, bool) {
	switch {
	case netip.MustParsePrefix("192.168.1.0/24").Contains(a):
		return "br0", true
	case netip.MustParsePrefix("192.168.3.0/24").Contains(a):
		return "br2", true
	}
	return "", false
}

func TestParseARP(t *testing.T) {
	e, err := ParseARP(strings.NewReader(arpTable))
	if err != nil {
		t.Fatal(err)
	}
	if len(e) != 5 || e[0].IP != netip.MustParseAddr("192.168.1.2") || e[0].Iface != "br0" {
		t.Fatalf("%+v", e)
	}
}

func TestBrForward(t *testing.T) {
	fsys := fixture()
	ports := PortOf(fsys, "br0")
	if ports["f0:87:56:8c:f7:a7"] != "wl1.1" || ports["78:c5:7d:2e:d6:2f"] != "eth0.0" || ports["b4:2e:99:34:bf:f0"] != "wl0" {
		t.Fatalf("%v", ports)
	}
	if _, local := ports["02:10:18:00:00:01"]; local {
		t.Fatal("local entry kept")
	}
	entries := ParseBrForward(putFDB("aa:bb:cc:dd:ee:ff", 0x102, false))
	if entries[0].Port != 0x102 {
		t.Fatalf("port_hi ignored: %+v", entries[0])
	}
	if PortOf(fsys, "br2") != nil {
		t.Fatal("bridge without brif returned ports")
	}
}

func TestMedium(t *testing.T) {
	tests := map[string]string{"wl0": "wifi", "wl1.1": "wifi", "ra0": "wifi", "wlan0": "wifi", "ath1": "wifi", "eth0.0": "wired", "lan1": "wired", "": ""}
	for in, want := range tests {
		if got := Medium(in); got != want {
			t.Errorf("Medium(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDiscover(t *testing.T) {
	h := NewHasher([]byte("0123456789abcdef"))
	got, err := Discover(fixture(), "/var/dnsmasq/dnsmasq.leases", []string{"br*"}, 10, h, inLAN)
	if err != nil {
		t.Fatal(err)
	}
	var ips []string
	for _, c := range got {
		ips = append(ips, c.IP.String()+"/"+c.Medium)
		if len(c.ID) != 12 || strings.Contains(c.ID, ":") {
			t.Fatalf("id %q", c.ID)
		}
	}
	want := "192.168.1.2/wifi 192.168.1.3/wired 192.168.1.4/wifi 192.168.1.6/ 192.168.3.20/"
	if strings.Join(ips, " ") != want {
		t.Fatalf("got %q, want %q", strings.Join(ips, " "), want)
	}
	if got[0].Port != "wl1.1" || got[3].Iface != "br0" {
		t.Fatalf("%+v", got)
	}

	limited, _ := Discover(fixture(), "", []string{"br0"}, 1, h, inLAN)
	if len(limited) != 1 || limited[0].IP != netip.MustParseAddr("192.168.1.2") {
		t.Fatalf("limited %+v", limited)
	}
}

func TestHasher(t *testing.T) {
	mac, _ := net.ParseMAC("F0:87:56:8C:F7:A7")
	a := NewHasher([]byte("salt-one-16bytes")).ID(mac)
	b := NewHasher([]byte("salt-one-16bytes")).ID(mac)
	c := NewHasher([]byte("salt-two-16bytes")).ID(mac)
	if a != b || a == c || strings.Contains(a, "f087") {
		t.Fatalf("%s %s %s", a, b, c)
	}
}

func TestSalt(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "lan.salt")
	s1, err := LoadOrCreateSalt(p)
	if err != nil || len(s1) != 16 {
		t.Fatalf("%x %v", s1, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	s2, err := LoadOrCreateSalt(p)
	if err != nil || !bytes.Equal(s1, s2) {
		t.Fatal("salt not persisted")
	}
	os.WriteFile(p, []byte("zz\n"), 0o600)
	if _, err := LoadOrCreateSalt(p); err == nil {
		t.Fatal("malformed salt accepted")
	}
	if s, err := LoadOrCreateSalt(""); err == nil || len(s) != 16 {
		t.Fatal("empty path")
	}
}
