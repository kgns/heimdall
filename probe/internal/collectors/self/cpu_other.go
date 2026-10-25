//go:build !unix

package self

import "time"

func cpuTimes() (user, sys time.Duration, ok bool) { return 0, 0, false }
