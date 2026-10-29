package sysinfo

import (
	"bytes"
	"io/fs"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

// pppdRecord matches one pppd environment record in its tdb database:
// KEY=value pairs joined by ';', as pppd stores them for each session.
var pppdRecord = regexp.MustCompile(`(?:[A-Z_][A-Z0-9_]*=[^;\x00-\x1f]*;)+[A-Z_][A-Z0-9_]*=[^;\x00-\x1f]*`)

// ParsePPPDTDB returns the DNS servers pppd received from the peer (IPCP,
// with usepeerdns), from the session records in its tdb database. When
// iface is set, the record of that PPP interface is preferred. pppd
// rewrites a session's record as the link comes up, so the most complete
// record of the interface is the current one.
func ParsePPPDTDB(b []byte, iface string) []netip.Addr {
	var best map[string]string
	score := func(r map[string]string) int {
		s := len(r)
		if iface != "" && r["IFNAME"] == iface {
			s += 100
		}
		return s
	}
	for _, m := range pppdRecord.FindAll(b, -1) {
		rec := map[string]string{}
		for _, kv := range bytes.Split(m, []byte(";")) {
			k, v, ok := strings.Cut(string(kv), "=")
			if ok {
				rec[k] = v
			}
		}
		if rec["DNS1"] == "" && rec["DNS2"] == "" {
			continue
		}
		if best == nil || score(rec) >= score(best) {
			best = rec
		}
	}
	var out []netip.Addr
	for _, k := range []string{"DNS1", "DNS2"} {
		if a, err := netip.ParseAddr(best[k]); err == nil && a.Is4() {
			out = append(out, a)
		}
	}
	return out
}

// ReadPPPDNS reads the peer DNS servers from every pppd database matching
// pattern, such as /var/run/pppd*.tdb.
func ReadPPPDNS(fsys fs.FS, pattern, iface string) ([]netip.Addr, error) {
	matches, err := fs.Glob(fsys, fsPath(pattern))
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, m := range matches {
		b, err := fs.ReadFile(fsys, m)
		if err != nil {
			continue
		}
		out = append(out, ParsePPPDTDB(b, iface)...)
	}
	return out, nil
}

// IsPPPDTDB reports whether a configured path names pppd databases.
func IsPPPDTDB(p string) bool { return path.Ext(p) == ".tdb" }
