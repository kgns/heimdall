// Package procwatch follows the daemons the measurements depend on, such as
// the DNS forwarder and resolver proxy, and reports their memory use,
// including the limits of any container they run in.
package procwatch

import (
	"bufio"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/kgns/heimdall/probe/internal/sysinfo"
)

// Status is one observation of a process.
type Status struct {
	Name   string
	PID    int
	RSSkB  uint64
	Cgroup string
	// Container memory, when the process runs in a non-root memory cgroup.
	MemUsage, MemLimit, MemPeak uint64
	// OOMEvents counts allocations that hit the limit: failcnt in cgroup
	// v1, the oom counter of memory.events in v2.
	OOMEvents uint64
	HasMem    bool
}

// Observe reads the current state of the process called name.
func Observe(fsys fs.FS, name string) (Status, error) {
	pid, _, err := sysinfo.FindProcess(fsys, name)
	if err != nil || pid == 0 {
		return Status{Name: name}, err
	}
	st := Status{Name: name, PID: pid}
	dir := path.Join("proc", strconv.Itoa(pid))
	if b, err := fs.ReadFile(fsys, path.Join(dir, "status")); err == nil {
		st.RSSkB = statusKB(string(b), "VmRSS")
	}
	if b, err := fs.ReadFile(fsys, path.Join(dir, "cgroup")); err == nil {
		readCgroup(fsys, string(b), &st)
	}
	return st, nil
}

func statusKB(s, key string) uint64 {
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok || k != key {
			continue
		}
		f := strings.Fields(v)
		if len(f) > 0 {
			n, _ := strconv.ParseUint(f[0], 10, 64)
			return n
		}
	}
	return 0
}

// readCgroup finds the memory cgroup in /proc/<pid>/cgroup and reads its
// accounting files, for both cgroup v1 ("N:memory:/path") and v2
// ("0::/path").
func readCgroup(fsys fs.FS, procCgroup string, st *Status) {
	var v1, v2 string
	sc := bufio.NewScanner(strings.NewReader(procCgroup))
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) != 3 {
			continue
		}
		switch {
		case parts[0] == "0" && parts[1] == "":
			v2 = parts[2]
		case containsController(parts[1], "memory"):
			v1 = parts[2]
		}
	}
	read := func(p string) (uint64, bool) {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return 0, false
		}
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0, true
		}
		n, err := strconv.ParseUint(s, 10, 64)
		return n, err == nil
	}
	switch {
	case v1 != "" && v1 != "/":
		st.Cgroup = v1
		dir := path.Join("sys/fs/cgroup/memory", v1)
		var ok bool
		if st.MemUsage, ok = read(path.Join(dir, "memory.usage_in_bytes")); !ok {
			return
		}
		st.HasMem = true
		st.MemLimit, _ = read(path.Join(dir, "memory.limit_in_bytes"))
		st.MemPeak, _ = read(path.Join(dir, "memory.max_usage_in_bytes"))
		st.OOMEvents, _ = read(path.Join(dir, "memory.failcnt"))
	case v2 != "" && v2 != "/":
		st.Cgroup = v2
		dir := path.Join("sys/fs/cgroup", v2)
		var ok bool
		if st.MemUsage, ok = read(path.Join(dir, "memory.current")); !ok {
			return
		}
		st.HasMem = true
		st.MemLimit, _ = read(path.Join(dir, "memory.max"))
		st.MemPeak, _ = read(path.Join(dir, "memory.peak"))
		if b, err := fs.ReadFile(fsys, path.Join(dir, "memory.events")); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if f := strings.Fields(line); len(f) == 2 && f[0] == "oom" {
					st.OOMEvents, _ = strconv.ParseUint(f[1], 10, 64)
				}
			}
		}
	}
}

func containsController(list, name string) bool {
	for _, c := range strings.Split(list, ",") {
		if c == name {
			return true
		}
	}
	return false
}
