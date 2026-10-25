//go:build !linux

package sysinfo

import "errors"

// Uname is only implemented on Linux.
func Uname() (UnameInfo, error) {
	return UnameInfo{}, errors.New("uname: unsupported platform")
}

// CheckICMPSockets is only implemented on Linux.
func CheckICMPSockets() ICMPCapability {
	return ICMPCapability{RawError: "unsupported platform", DgramError: "unsupported platform"}
}
