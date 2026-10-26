// Package hoststat reads interface, CPU and protocol counters from /proc and
// turns successive readings into rates.
package hoststat

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
)

// IfCounters are the /proc/net/dev counters of one interface.
type IfCounters struct {
	RxBytes, RxPackets, RxErrs, RxDrop uint64
	TxBytes, TxPackets, TxErrs, TxDrop uint64
}

// ReadNetDev parses proc/net/dev.
func ReadNetDev(fsys fs.FS) (map[string]IfCounters, error) {
	f, err := fsys.Open("proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseNetDev(f)
}

// ParseNetDev parses the /proc/net/dev format.
func ParseNetDev(r io.Reader) (map[string]IfCounters, error) {
	out := map[string]IfCounters{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.Contains(name, "|") {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			return nil, fmt.Errorf("net/dev %s: want 16 counters, got %d", strings.TrimSpace(name), len(f))
		}
		var v [16]uint64
		for i := range v {
			n, err := strconv.ParseUint(f[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("net/dev %s: %w", strings.TrimSpace(name), err)
			}
			v[i] = n
		}
		out[strings.TrimSpace(name)] = IfCounters{
			RxBytes: v[0], RxPackets: v[1], RxErrs: v[2], RxDrop: v[3],
			TxBytes: v[8], TxPackets: v[9], TxErrs: v[10], TxDrop: v[11],
		}
	}
	return out, sc.Err()
}

// Delta returns cur-prev for a monotonically increasing counter, allowing
// for a 32-bit wrap. A drop that cannot be a wrap (the counter was reset,
// for example when a PPP session restarts) yields cur.
func Delta(prev, cur uint64) uint64 {
	switch {
	case cur >= prev:
		return cur - prev
	case prev <= 1<<32-1:
		return cur + (1<<32 - prev)
	default:
		return cur
	}
}

// CPUTimes are the aggregate jiffies of the first "cpu" line of /proc/stat.
type CPUTimes struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64
}

// Total is the sum of all accounted time.
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// ReadCPU parses the aggregate line of proc/stat and the CPU count.
func ReadCPU(fsys fs.FS) (CPUTimes, int, error) {
	f, err := fsys.Open("proc/stat")
	if err != nil {
		return CPUTimes{}, 0, err
	}
	defer f.Close()
	return ParseCPU(f)
}

// ParseCPU parses the /proc/stat format.
func ParseCPU(r io.Reader) (CPUTimes, int, error) {
	var c CPUTimes
	found, cpus := false, 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		if f[0] != "cpu" {
			cpus++
			continue
		}
		if len(f) < 8 {
			return c, 0, fmt.Errorf("stat: short cpu line")
		}
		dst := []*uint64{&c.User, &c.Nice, &c.System, &c.Idle, &c.IOWait, &c.IRQ, &c.SoftIRQ, &c.Steal}
		for i, p := range dst {
			if i+1 >= len(f) {
				break
			}
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				return c, 0, fmt.Errorf("stat: %w", err)
			}
			*p = n
		}
		found = true
	}
	if !found {
		return c, 0, fmt.Errorf("stat: no aggregate cpu line")
	}
	return c, cpus, sc.Err()
}

// CPUUsage is the share of time spent in each state between two readings,
// in percent.
type CPUUsage struct {
	Busy, User, System, SoftIRQ, IRQ, IOWait float64
}

// Usage computes CPUUsage from two readings.
func Usage(prev, cur CPUTimes) (CPUUsage, bool) {
	total := float64(Delta(prev.Total(), cur.Total()))
	if total <= 0 {
		return CPUUsage{}, false
	}
	pct := func(a, b uint64) float64 { return float64(Delta(a, b)) / total * 100 }
	idle := pct(prev.Idle, cur.Idle) + pct(prev.IOWait, cur.IOWait)
	return CPUUsage{
		Busy:    100 - idle,
		User:    pct(prev.User, cur.User) + pct(prev.Nice, cur.Nice),
		System:  pct(prev.System, cur.System),
		SoftIRQ: pct(prev.SoftIRQ, cur.SoftIRQ),
		IRQ:     pct(prev.IRQ, cur.IRQ),
		IOWait:  pct(prev.IOWait, cur.IOWait),
	}, true
}

// ReadLoadAvg returns the one-minute load average.
func ReadLoadAvg(fsys fs.FS) (float64, error) {
	b, err := fs.ReadFile(fsys, "proc/loadavg")
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, fmt.Errorf("loadavg: empty")
	}
	return strconv.ParseFloat(f[0], 64)
}

// SNMP holds selected /proc/net/snmp counters, keyed "Proto.Name", for
// example "Udp.NoPorts".
type SNMP map[string]uint64

// ReadSNMP parses proc/net/snmp.
func ReadSNMP(fsys fs.FS) (SNMP, error) {
	f, err := fsys.Open("proc/net/snmp")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseSNMP(f)
}

// ParseSNMP parses the header/value line pairs of /proc/net/snmp.
func ParseSNMP(r io.Reader) (SNMP, error) {
	out := SNMP{}
	sc := bufio.NewScanner(r)
	var header []string
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		if header == nil || header[0] != f[0] {
			header = f
			continue
		}
		proto := strings.TrimSuffix(f[0], ":")
		for i := 1; i < len(f) && i < len(header); i++ {
			// Some fields (Tcp MaxConn) are signed; negative values carry
			// no rate information and are skipped.
			if n, err := strconv.ParseUint(f[i], 10, 64); err == nil {
				out[proto+"."+header[i]] = n
			}
		}
		header = nil
	}
	return out, sc.Err()
}
