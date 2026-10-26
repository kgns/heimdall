package sysinfo

import (
	"bufio"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

// DefaultDnsmasqConf is the configuration file dnsmasq reads when it is not
// started with --conf-file.
const DefaultDnsmasqConf = "/etc/dnsmasq.conf"

// DNSServer is an upstream DNS server taken from dnsmasq or resolv.conf.
type DNSServer struct {
	Addr    netip.AddrPort `json:"addr"`
	Domains []string       `json:"domains,omitempty"`
	Origin  string         `json:"origin"`
}

// Dnsmasq is the effective DNS forwarding setup of a dnsmasq instance,
// reconstructed from its command line and configuration files.
type Dnsmasq struct {
	Running       bool        `json:"running"`
	PID           int         `json:"pid,omitempty"`
	Args          []string    `json:"args,omitempty"`
	Files         []string    `json:"files"`
	ListenPort    int         `json:"listen_port"`
	NoResolv      bool        `json:"no_resolv"`
	ResolvFiles   []string    `json:"resolv_files,omitempty"`
	LeaseFile     string      `json:"lease_file,omitempty"`
	Servers       []DNSServer `json:"servers,omitempty"`
	ResolvServers []DNSServer `json:"resolv_servers,omitempty"`
	Warnings      []string    `json:"warnings,omitempty"`
}

// Upstreams returns the servers dnsmasq forwards ordinary queries to:
// server= entries without a domain, plus resolv-file servers unless
// no-resolv is set.
func (d *Dnsmasq) Upstreams() []DNSServer {
	var out []DNSServer
	seen := map[netip.AddrPort]bool{}
	add := func(s DNSServer) {
		if len(s.Domains) > 0 || seen[s.Addr] {
			return
		}
		seen[s.Addr] = true
		out = append(out, s)
	}
	for _, s := range d.Servers {
		add(s)
	}
	if !d.NoResolv {
		for _, s := range d.ResolvServers {
			add(s)
		}
	}
	return out
}

// DiscoverDnsmasq locates a running dnsmasq through proc and reconstructs its
// configuration. When no process is visible (for example inside a container
// with its own PID namespace) it falls back to DefaultDnsmasqConf. It returns
// nil when neither exists.
func DiscoverDnsmasq(fsys fs.FS) (*Dnsmasq, error) {
	d := &Dnsmasq{ListenPort: 53}
	pid, args, err := FindProcess(fsys, "dnsmasq")
	if err != nil {
		return nil, err
	}
	if pid > 0 {
		d.Running, d.PID, d.Args = true, pid, args
	} else if _, err := fs.Stat(fsys, fsPath(DefaultDnsmasqConf)); err != nil {
		if isNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	p := &dnsmasqParser{fsys: fsys, d: d, visited: map[string]bool{}}
	directives := cmdlineDirectives(args)
	mainConf := DefaultDnsmasqConf
	for _, kv := range directives {
		if kv.key == "conf-file" {
			mainConf = kv.val
		}
	}
	for _, kv := range directives {
		if kv.key != "conf-file" {
			p.apply(kv.key, kv.val, "cmdline", 0)
		}
	}
	if mainConf != "" {
		p.parseFile(mainConf, 0)
	}

	if !d.NoResolv {
		files := d.ResolvFiles
		if len(files) == 0 && !p.resolvDisabled {
			files = []string{"/etc/resolv.conf"}
		}
		for _, rf := range files {
			addrs, err := ReadResolvConf(fsys, rf)
			if err != nil {
				d.Warnings = append(d.Warnings, fmt.Sprintf("resolv-file %s: %v", rf, err))
				continue
			}
			for _, a := range addrs {
				d.ResolvServers = append(d.ResolvServers, DNSServer{
					Addr:   netip.AddrPortFrom(a, 53),
					Origin: rf,
				})
			}
		}
	}
	return d, nil
}

type directive struct{ key, val string }

// Long option names that take an argument, for the subset this parser uses.
var dnsmasqArgOptions = map[string]bool{
	"conf-file": true, "conf-dir": true, "resolv-file": true, "server": true,
	"local": true, "port": true, "servers-file": true,
}

var dnsmasqShortOptions = map[string]string{
	"C": "conf-file", "7": "conf-dir", "r": "resolv-file", "S": "server", "p": "port", "R": "no-resolv",
}

func cmdlineDirectives(args []string) []directive {
	var out []directive
	if len(args) < 2 {
		return nil
	}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case strings.HasPrefix(a, "--"):
			key, val, hasVal := strings.Cut(a[2:], "=")
			if !hasVal && dnsmasqArgOptions[key] && i+1 < len(rest) && !strings.HasPrefix(rest[i+1], "-") {
				i++
				val = rest[i]
			}
			out = append(out, directive{key, val})
		case strings.HasPrefix(a, "-") && len(a) >= 2:
			key, ok := dnsmasqShortOptions[a[1:2]]
			if !ok {
				continue
			}
			val := a[2:]
			if val == "" && dnsmasqArgOptions[key] && i+1 < len(rest) {
				i++
				val = rest[i]
			}
			out = append(out, directive{key, val})
		}
	}
	return out
}

type dnsmasqParser struct {
	fsys           fs.FS
	d              *Dnsmasq
	visited        map[string]bool
	resolvDisabled bool
}

const maxIncludeDepth = 8

func (p *dnsmasqParser) warn(format string, a ...any) {
	p.d.Warnings = append(p.d.Warnings, fmt.Sprintf(format, a...))
}

func (p *dnsmasqParser) parseFile(abs string, depth int) {
	clean := path.Clean("/" + abs)
	if p.visited[clean] {
		return
	}
	if depth > maxIncludeDepth {
		p.warn("%s: include depth exceeded", clean)
		return
	}
	p.visited[clean] = true
	f, err := p.fsys.Open(fsPath(clean))
	if err != nil {
		p.warn("%s: %v", clean, err)
		return
	}
	defer f.Close()
	p.d.Files = append(p.d.Files, clean)

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(stripDnsmasqComment(sc.Text()))
		if line == "" {
			continue
		}
		key, val, _ := strings.Cut(line, "=")
		p.apply(strings.TrimSpace(key), unquote(strings.TrimSpace(val)), fmt.Sprintf("%s:%d", clean, lineNo), depth)
	}
	if err := sc.Err(); err != nil {
		p.warn("%s: %v", clean, err)
	}
}

func (p *dnsmasqParser) parseDir(val string, depth int) {
	parts := strings.Split(val, ",")
	dir := strings.TrimSpace(parts[0])
	var include, exclude []string
	for _, e := range parts[1:] {
		e = strings.TrimSpace(e)
		switch {
		case e == "":
		case strings.HasPrefix(e, "*"):
			include = append(include, e[1:])
		default:
			exclude = append(exclude, e)
		}
	}
	entries, err := fs.ReadDir(p.fsys, fsPath(dir))
	if err != nil {
		p.warn("conf-dir %s: %v", dir, err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, "~") || strings.HasPrefix(name, ".") ||
			(len(name) > 1 && strings.HasPrefix(name, "#") && strings.HasSuffix(name, "#")) {
			continue
		}
		if len(include) > 0 && !hasAnySuffix(name, include) {
			continue
		}
		if hasAnySuffix(name, exclude) {
			continue
		}
		p.parseFile(path.Join(dir, name), depth+1)
	}
}

func (p *dnsmasqParser) apply(key, val, origin string, depth int) {
	switch key {
	case "conf-file":
		if val != "" {
			p.parseFile(val, depth+1)
		}
	case "conf-dir":
		p.parseDir(val, depth)
	case "servers-file":
		p.parseFile(val, depth+1)
	case "no-resolv":
		p.d.NoResolv = true
	case "dhcp-leasefile", "dhcp-lease-file":
		p.d.LeaseFile = val
	case "resolv-file":
		if val == "" {
			p.resolvDisabled = true
		} else if !slices.Contains(p.d.ResolvFiles, val) {
			p.d.ResolvFiles = append(p.d.ResolvFiles, val)
		}
	case "server", "local":
		s, ok, err := parseDnsmasqServer(val)
		if err != nil {
			p.warn("%s: %s=%s: %v", origin, key, val, err)
			return
		}
		if ok {
			s.Origin = origin
			p.d.Servers = append(p.d.Servers, s)
		}
	case "port":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			p.warn("%s: invalid port %q", origin, val)
			return
		}
		p.d.ListenPort = n
	}
}

// parseDnsmasqServer parses the value of a server= or local= option:
// [/domain/[domain/]][addr[#port][@iface|@source[#port]]]. ok is false for
// entries without an upstream address (local-only domains, "#").
func parseDnsmasqServer(val string) (DNSServer, bool, error) {
	var s DNSServer
	rest := val
	if strings.HasPrefix(rest, "/") {
		end := strings.LastIndex(rest, "/")
		if end == 0 {
			return s, false, fmt.Errorf("unterminated domain list")
		}
		// An empty domain ("//") selects unqualified names; it still makes
		// the entry domain-scoped.
		s.Domains = strings.Split(rest[1:end], "/")
		rest = rest[end+1:]
	}
	if rest == "" || rest == "#" {
		return s, false, nil
	}
	host, _, _ := strings.Cut(rest, "@")
	port := 53
	if h, ps, ok := strings.Cut(host, "#"); ok {
		n, err := strconv.Atoi(ps)
		if err != nil || n <= 0 || n > 65535 {
			return s, false, fmt.Errorf("invalid port %q", ps)
		}
		host, port = h, n
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return s, false, fmt.Errorf("invalid address %q", host)
	}
	s.Addr = netip.AddrPortFrom(addr, uint16(port))
	return s, true, nil
}

// stripDnsmasqComment drops a comment, which in dnsmasq configuration starts
// with '#' at the beginning of a line or after whitespace, outside quotes.
// A '#' directly after other text is part of the value, as in addr#port.
func stripDnsmasqComment(line string) string {
	inQuote := false
	white := true
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == '#' && white && !inQuote:
			return line[:i]
		}
		white = c == ' ' || c == '\t'
	}
	return line
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func hasAnySuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}
