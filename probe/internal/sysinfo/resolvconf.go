package sysinfo

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"net/netip"
	"path"
	"strings"
)

// ParseResolvConf returns the nameserver addresses of a resolv.conf file.
func ParseResolvConf(r io.Reader) ([]netip.Addr, error) {
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

// ReadResolvConf parses a resolv.conf-format file at an absolute path.
func ReadResolvConf(fsys fs.FS, abs string) ([]netip.Addr, error) {
	f, err := fsys.Open(fsPath(abs))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseResolvConf(f)
}

// fsPath converts an absolute host path into an fs.FS path rooted at "/".
func fsPath(p string) string {
	c := strings.TrimPrefix(path.Clean("/"+p), "/")
	if c == "" {
		return "."
	}
	return c
}

func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
