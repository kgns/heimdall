//go:build !linux

package flows

import (
	"errors"

	"golang.org/x/net/bpf"
)

// OpenCapture is only implemented on Linux.
func OpenCapture(iface string, filter []bpf.RawInstruction, rcvbuf int) (Capture, error) {
	return nil, errors.New("packet capture needs Linux")
}

// OpenBridgeCapture is only implemented on Linux.
func OpenBridgeCapture(bridge string, filter []bpf.RawInstruction, rcvbuf int) (Capture, error) {
	return nil, errors.New("packet capture needs Linux")
}
