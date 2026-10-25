package config

import (
	"fmt"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// ByteSize is a size in bytes that accepts suffixes B, KiB, MiB and GiB in
// YAML.
type ByteSize int64

const (
	KiB ByteSize = 1 << 10
	MiB ByteSize = 1 << 20
	GiB ByteSize = 1 << 30
)

// ParseByteSize parses "123", "64KiB", "16MiB" or "1GiB".
func ParseByteSize(s string) (ByteSize, error) {
	s = strings.TrimSpace(s)
	mult := ByteSize(1)
	for _, u := range []struct {
		suffix string
		mult   ByteSize
	}{{"GiB", GiB}, {"MiB", MiB}, {"KiB", KiB}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSpace(strings.TrimSuffix(s, u.suffix)), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q: use a whole number with B, KiB, MiB or GiB", s)
	}
	if n > int64(1<<62)/int64(mult) {
		return 0, fmt.Errorf("size %q overflows", s)
	}
	return ByteSize(n) * mult, nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = v
	return nil
}

func (b ByteSize) String() string {
	switch {
	case b != 0 && b%GiB == 0:
		return fmt.Sprintf("%dGiB", b/GiB)
	case b != 0 && b%MiB == 0:
		return fmt.Sprintf("%dMiB", b/MiB)
	case b != 0 && b%KiB == 0:
		return fmt.Sprintf("%dKiB", b/KiB)
	default:
		return fmt.Sprintf("%dB", int64(b))
	}
}
