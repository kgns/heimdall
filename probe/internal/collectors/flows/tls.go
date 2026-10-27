package flows

import (
	"encoding/binary"
	"strings"
)

// sniResult is what could be read from the start of a ClientHello.
type sniResult int

const (
	sniFound sniResult = iota
	// sniAbsent: the ClientHello is complete and has no server_name.
	sniAbsent
	// sniTruncated: the server_name extension, if any, lies beyond the
	// captured bytes, typically in the next segment after a large
	// post-quantum key share.
	sniTruncated
	sniInvalid
)

// ParseSNI reads the server_name of a TLS ClientHello from the start of the
// client's first TCP payload. b may hold only part of the record.
func ParseSNI(b []byte) (string, sniResult) {
	// Record header: type 22, version, length.
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return "", sniInvalid
	}
	b = b[5:]
	// Handshake header: type 1 (ClientHello), 24-bit length.
	if len(b) < 4 || b[0] != 0x01 {
		return "", sniInvalid
	}
	hsLen := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	b = b[4:]
	complete := len(b) >= hsLen
	if complete {
		b = b[:hsLen]
	}
	trunc := func() (string, sniResult) {
		if complete {
			return "", sniInvalid
		}
		return "", sniTruncated
	}
	// legacy_version(2) random(32)
	if len(b) < 34 {
		return trunc()
	}
	b = b[34:]
	// session id
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return trunc()
	}
	b = b[1+int(b[0]):]
	// cipher suites
	if len(b) < 2 {
		return trunc()
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return trunc()
	}
	b = b[2+n:]
	// compression methods
	if len(b) < 1 || len(b) < 1+int(b[0]) {
		return trunc()
	}
	b = b[1+int(b[0]):]
	if len(b) < 2 {
		if complete {
			return "", sniAbsent
		}
		return trunc()
	}
	b = b[2:]
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		if len(b) < 4+l {
			return trunc()
		}
		if typ == 0 {
			return parseServerName(b[4 : 4+l])
		}
		b = b[4+l:]
	}
	if complete {
		return "", sniAbsent
	}
	return "", sniTruncated
}

func parseServerName(b []byte) (string, sniResult) {
	if len(b) < 2 {
		return "", sniInvalid
	}
	b = b[2:]
	for len(b) >= 3 {
		typ := b[0]
		l := int(binary.BigEndian.Uint16(b[1:]))
		if len(b) < 3+l {
			return "", sniInvalid
		}
		if typ == 0 {
			name := strings.ToLower(strings.TrimSuffix(string(b[3:3+l]), "."))
			if !validName(name) {
				return "", sniInvalid
			}
			return name, sniFound
		}
		b = b[3+l:]
	}
	return "", sniAbsent
}

// validName accepts DNS names made of letters, digits, '-', '_' and '.'.
func validName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}
