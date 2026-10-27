package flows

import (
	"errors"
	"time"
)

// Capture delivers frames from the LAN bridge.
type Capture interface {
	// Read returns the next frame and when the kernel received it, or
	// ErrTimeout when none arrived for a while.
	Read() ([]byte, time.Time, error)
	// Drops returns the frames dropped since the previous call.
	Drops() uint64
	Close() error
}

// ErrTimeout is returned by Capture.Read when no frame arrived in time.
var ErrTimeout = errors.New("capture: no packet")
