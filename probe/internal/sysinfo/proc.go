package sysinfo

import (
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// FindProcess returns the lowest PID whose comm equals name, with its
// command-line arguments. It returns pid 0 when no such process is visible.
func FindProcess(fsys fs.FS, name string) (int, []string, error) {
	entries, err := fs.ReadDir(fsys, "proc")
	if err != nil {
		if isNotExist(err) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	best := 0
	var bestArgs []string
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		comm, err := fs.ReadFile(fsys, path.Join("proc", e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != name {
			continue
		}
		if best != 0 && pid > best {
			continue
		}
		raw, err := fs.ReadFile(fsys, path.Join("proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		best, bestArgs = pid, splitCmdline(raw)
	}
	return best, bestArgs, nil
}

func splitCmdline(raw []byte) []string {
	s := strings.TrimRight(string(raw), "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}
