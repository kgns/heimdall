//go:build unix

package self

import (
	"syscall"
	"time"
)

func cpuTimes() (user, sys time.Duration, ok bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0, false
	}
	return time.Duration(ru.Utime.Nano()), time.Duration(ru.Stime.Nano()), true
}
