//go:build linux

package app

import (
	"errors"
	"os"
	"strconv"
	"syscall"
)

// renice raises the nice value of every thread of the process to at least
// n. Linux keeps nice per thread, and new threads inherit it from the thread
// that creates them, so changing all current threads covers later ones too.
func renice(n int) error {
	entries, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		cur, err := syscall.Getpriority(syscall.PRIO_PROCESS, tid)
		if err != nil {
			continue
		}
		// The raw getpriority syscall returns 20 - nice.
		if 20-cur >= n {
			continue
		}
		if err := syscall.Setpriority(syscall.PRIO_PROCESS, tid, n); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
