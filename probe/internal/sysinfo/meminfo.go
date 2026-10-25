package sysinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
)

// MemInfo holds the /proc/meminfo fields the probe cares about, in kB.
type MemInfo struct {
	TotalKB     uint64 `json:"total_kb"`
	FreeKB      uint64 `json:"free_kb"`
	AvailableKB uint64 `json:"available_kb"`
	CachedKB    uint64 `json:"cached_kb"`
}

// ReadMemInfo parses proc/meminfo from fsys.
func ReadMemInfo(fsys fs.FS) (MemInfo, error) {
	f, err := fsys.Open("proc/meminfo")
	if err != nil {
		return MemInfo{}, err
	}
	defer f.Close()
	return ParseMemInfo(f)
}

// ParseMemInfo parses the /proc/meminfo format.
func ParseMemInfo(r io.Reader) (MemInfo, error) {
	var m MemInfo
	fields := map[string]*uint64{
		"MemTotal":     &m.TotalKB,
		"MemFree":      &m.FreeKB,
		"MemAvailable": &m.AvailableKB,
		"Cached":       &m.CachedKB,
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		dst, wanted := fields[strings.TrimSpace(key)]
		if !wanted {
			continue
		}
		val := strings.Fields(rest)
		if len(val) == 0 {
			return m, fmt.Errorf("meminfo %s: missing value", key)
		}
		n, err := strconv.ParseUint(val[0], 10, 64)
		if err != nil {
			return m, fmt.Errorf("meminfo %s: %w", key, err)
		}
		*dst = n
	}
	if err := sc.Err(); err != nil {
		return m, err
	}
	if m.TotalKB == 0 {
		return m, errors.New("meminfo: MemTotal not found")
	}
	return m, nil
}
