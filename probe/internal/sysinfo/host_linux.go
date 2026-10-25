//go:build linux

package sysinfo

import (
	"syscall"
)

// Uname returns the kernel identification as seen by this process. A 32-bit
// binary on a 64-bit ARM kernel reports a compat machine such as "armv8l".
func Uname() (UnameInfo, error) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return UnameInfo{}, err
	}
	return UnameInfo{
		Sysname:  utsString(u.Sysname[:]),
		Nodename: utsString(u.Nodename[:]),
		Release:  utsString(u.Release[:]),
		Version:  utsString(u.Version[:]),
		Machine:  utsString(u.Machine[:]),
	}, nil
}

func utsString[T ~int8 | ~uint8](b []T) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// CheckICMPSockets reports whether raw and unprivileged datagram ICMP
// sockets can be opened by this process.
func CheckICMPSockets() ICMPCapability {
	var c ICMPCapability
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP); err == nil {
		syscall.Close(fd)
		c.Raw = true
	} else {
		c.RawError = err.Error()
	}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP); err == nil {
		syscall.Close(fd)
		c.Dgram = true
	} else {
		c.DgramError = err.Error()
	}
	return c
}
