package sysinfo

import (
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

// PingGroupRange is net.ipv4.ping_group_range: the GIDs allowed to open
// unprivileged ICMP datagram sockets. The kernel default "1 0" allows nobody.
type PingGroupRange struct {
	Min uint32 `json:"min"`
	Max uint32 `json:"max"`
}

// Allows reports whether gid may open an ICMP datagram socket.
func (p PingGroupRange) Allows(gid uint32) bool {
	return p.Min <= gid && gid <= p.Max
}

func (p PingGroupRange) String() string {
	return fmt.Sprintf("%d %d", p.Min, p.Max)
}

// ReadPingGroupRange reads proc/sys/net/ipv4/ping_group_range from fsys.
func ReadPingGroupRange(fsys fs.FS) (PingGroupRange, error) {
	b, err := fs.ReadFile(fsys, "proc/sys/net/ipv4/ping_group_range")
	if err != nil {
		return PingGroupRange{}, err
	}
	return ParsePingGroupRange(string(b))
}

// ParsePingGroupRange parses the two whitespace-separated GIDs.
func ParsePingGroupRange(s string) (PingGroupRange, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return PingGroupRange{}, fmt.Errorf("ping_group_range %q: want two values", s)
	}
	lo, err := strconv.ParseUint(f[0], 10, 32)
	if err != nil {
		return PingGroupRange{}, fmt.Errorf("ping_group_range min: %w", err)
	}
	hi, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return PingGroupRange{}, fmt.Errorf("ping_group_range max: %w", err)
	}
	return PingGroupRange{Min: uint32(lo), Max: uint32(hi)}, nil
}
