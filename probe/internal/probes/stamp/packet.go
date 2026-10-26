// Package stamp implements the unauthenticated mode of the Simple
// Two-way Active Measurement Protocol (RFC 8762): a session-sender that
// measures round trip, one-way delays and the direction of packet loss
// against a stateful session-reflector, and the reflector itself.
package stamp

import (
	"encoding/binary"
	"errors"
	"time"
)

// Port is the IANA-assigned STAMP port.
const Port = 862

// PacketSize is the length of an unauthenticated test packet. Reflectors
// answer with a packet of the same length as the one they received.
const PacketSize = 44

// ntpEpochOffset is the number of seconds between 1900-01-01 and
// 1970-01-01.
const ntpEpochOffset = 2208988800

// ErrShort is returned for packets shorter than PacketSize.
var ErrShort = errors.New("stamp: packet too short")

// putNTP writes t as a 64-bit NTP timestamp.
func putNTP(b []byte, t time.Time) {
	sec := uint64(t.Unix()) + ntpEpochOffset
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	binary.BigEndian.PutUint32(b[0:4], uint32(sec))
	binary.BigEndian.PutUint32(b[4:8], uint32(frac))
}

// readNTP reads a 64-bit NTP timestamp.
func readNTP(b []byte) time.Time {
	sec := int64(binary.BigEndian.Uint32(b[0:4])) - ntpEpochOffset
	frac := uint64(binary.BigEndian.Uint32(b[4:8]))
	return time.Unix(sec, int64((frac*1e9)>>32))
}

// Error estimate (RFC 4656 section 4.1.2): S bit set when the clock is
// synchronised to UTC, Z bit clear for NTP timestamps, then a 6-bit scale
// and an 8-bit multiplier; the error is multiplier * 2^(scale-32) seconds.
const (
	errSynced = 0x8000
	// Scale 22, multiplier 1: about one millisecond.
	errMillisecond = 22<<8 | 1
	// Scale 32, multiplier 1: one second, for an unsynchronised clock.
	errSecond = 32<<8 | 1
)

// Synced reports whether an error estimate claims a synchronised clock.
func Synced(errEst uint16) bool { return errEst&errSynced != 0 }

// SenderPacket is the session-sender test packet.
type SenderPacket struct {
	Seq    uint32
	TS     time.Time
	ErrEst uint16
}

// Marshal writes p into b, which must be at least PacketSize long. The
// must-be-zero area is cleared.
func (p SenderPacket) Marshal(b []byte) {
	clear(b[:PacketSize])
	binary.BigEndian.PutUint32(b[0:4], p.Seq)
	putNTP(b[4:12], p.TS)
	binary.BigEndian.PutUint16(b[12:14], p.ErrEst)
}

// ParseSender decodes a session-sender test packet.
func ParseSender(b []byte) (SenderPacket, error) {
	if len(b) < PacketSize {
		return SenderPacket{}, ErrShort
	}
	return SenderPacket{
		Seq:    binary.BigEndian.Uint32(b[0:4]),
		TS:     readNTP(b[4:12]),
		ErrEst: binary.BigEndian.Uint16(b[12:14]),
	}, nil
}

// ReflectorPacket is the session-reflector test packet.
type ReflectorPacket struct {
	Seq          uint32
	TS           time.Time // transmit time at the reflector
	ErrEst       uint16
	RxTS         time.Time // receive time of the sender's packet
	SenderSeq    uint32
	SenderTS     time.Time
	SenderErrEst uint16
	// SenderTTL is the IP TTL of the sender's packet as it arrived.
	SenderTTL uint8
}

// Marshal writes p into b, which must be at least PacketSize long.
func (p ReflectorPacket) Marshal(b []byte) {
	clear(b[:PacketSize])
	binary.BigEndian.PutUint32(b[0:4], p.Seq)
	putNTP(b[4:12], p.TS)
	binary.BigEndian.PutUint16(b[12:14], p.ErrEst)
	putNTP(b[16:24], p.RxTS)
	binary.BigEndian.PutUint32(b[24:28], p.SenderSeq)
	putNTP(b[28:36], p.SenderTS)
	binary.BigEndian.PutUint16(b[36:38], p.SenderErrEst)
	b[40] = p.SenderTTL
}

// ParseReflector decodes a session-reflector test packet.
func ParseReflector(b []byte) (ReflectorPacket, error) {
	if len(b) < PacketSize {
		return ReflectorPacket{}, ErrShort
	}
	return ReflectorPacket{
		Seq:          binary.BigEndian.Uint32(b[0:4]),
		TS:           readNTP(b[4:12]),
		ErrEst:       binary.BigEndian.Uint16(b[12:14]),
		RxTS:         readNTP(b[16:24]),
		SenderSeq:    binary.BigEndian.Uint32(b[24:28]),
		SenderTS:     readNTP(b[28:36]),
		SenderErrEst: binary.BigEndian.Uint16(b[36:38]),
		SenderTTL:    b[40],
	}, nil
}
