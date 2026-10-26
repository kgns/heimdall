// Package sample defines the measurement record produced by every prober and
// collector, and the sinks that store or forward it.
package sample

import (
	"math"
	"time"
)

// Kind identifies what produced a sample.
type Kind string

const (
	KindICMP      Kind = "icmp"
	KindTCP       Kind = "tcp"
	KindHTTP      Kind = "http"
	KindDNS       Kind = "dns"
	KindUDPEcho   Kind = "udp_echo"
	KindSTUN      Kind = "stun"
	KindUDPBeacon Kind = "udp_beacon"
	KindTrace     Kind = "trace"
	KindWAN       Kind = "wan"
	KindCPU       Kind = "cpu"
	KindLAN       Kind = "lan"
	KindDNSHealth Kind = "dnshealth"
	KindClock     Kind = "clock"
	KindEvent     Kind = "event"
	KindHeartbeat Kind = "heartbeat"
	KindSelf      Kind = "self"
)

// Status is the outcome of a single measurement.
type Status string

const (
	StatusOK           Status = "ok"
	StatusTimeout      Status = "timeout"
	StatusUnreachable  Status = "unreachable"
	StatusTimeExceeded Status = "time_exceeded"
	// StatusRefused is a TCP reset in answer to a SYN. The round trip is
	// still a valid latency measurement.
	StatusRefused Status = "refused"
	StatusError   Status = "error"
)

// Sample is one measurement or observation. RTT is nil when no answer was
// received, so that loss serializes as an explicit null.
type Sample struct {
	TS         int64          `json:"ts_ms"`
	Device     string         `json:"device"`
	Seq        uint64         `json:"seq"`
	Kind       Kind           `json:"kind"`
	Category   string         `json:"category,omitempty"`
	Service    string         `json:"service,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	DstIP      string         `json:"dst_ip,omitempty"`
	DstPort    int            `json:"dst_port,omitempty"`
	RTTms      *float64       `json:"rtt_ms"`
	Status     Status         `json:"status"`
	ResolverID string         `json:"resolver_id,omitempty"`
	Extra      map[string]any `json:"extra,omitempty"`
}

// Millis converts a duration to milliseconds with microsecond precision.
func Millis(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000
}

// RTT returns a pointer suitable for Sample.RTTms.
func RTT(d time.Duration) *float64 {
	v := Millis(d)
	return &v
}
