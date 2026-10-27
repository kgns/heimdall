package flows

import (
	"fmt"
	"net"

	"golang.org/x/net/bpf"
)

// Capture lengths returned by the filter.
const (
	snapHeaders = 128
	snapHello   = 2048
	snapDNS     = 1514
)

// Filter returns the classic BPF program for the LAN bridge. routerMAC is
// the bridge's own address: frames from it were sent by the CPE towards a
// client, all others come from clients. The program keeps
//
//   - TCP segments with SYN set, in both directions;
//   - from clients, TCP segments that carry only an ACK, and the first
//     segment of a TLS ClientHello;
//   - QUIC long-header packets (UDP port 443, first bit set), both ways;
//   - DNS answers (UDP source port 53) sent by the CPE to clients.
//
// Pure ACKs of busy flows are the bulk of what passes; the flow
// accelerator takes established flows off the CPU after a few packets, so
// most of them never reach the filter.
func Filter(routerMAC net.HardwareAddr) ([]bpf.RawInstruction, error) {
	if len(routerMAC) != 6 {
		return nil, fmt.Errorf("router MAC %v is not an Ethernet address", routerMAC)
	}
	hi := uint32(routerMAC[0])<<24 | uint32(routerMAC[1])<<16 | uint32(routerMAC[2])<<8 | uint32(routerMAC[3])
	lo := uint32(routerMAC[4])<<8 | uint32(routerMAC[5])

	var a asm
	// fromRouter jumps to yes when the source MAC is the CPE's, else to no.
	fromRouter := func(yes, no string) {
		a.op(bpf.LoadAbsolute{Off: 6, Size: 4})
		a.jeq(hi, "", no)
		a.op(bpf.LoadAbsolute{Off: 10, Size: 2})
		a.jeq(lo, yes, no)
	}

	a.op(bpf.LoadAbsolute{Off: 12, Size: 2})
	a.jeq(etherIPv4, "v4", "")
	a.jeq(etherIPv6, "v6", "drop")

	a.label("v4")
	a.op(bpf.LoadAbsolute{Off: 23, Size: 1})
	a.jeq(protoTCP, "v4tcp", "")
	a.jeq(protoUDP, "v4udp", "drop")

	a.label("v4tcp")
	a.op(bpf.LoadAbsolute{Off: 20, Size: 2})
	a.jset(0x1fff, "drop", "")
	a.op(bpf.LoadMemShift{Off: 14})
	a.op(bpf.LoadIndirect{Off: 27, Size: 1})
	a.jset(flagSYN, "hdr", "")
	a.jset(flagFIN|flagRST, "drop", "")
	a.jset(flagACK, "", "drop")
	fromRouter("drop", "v4ack")
	a.label("v4ack")
	a.op(bpf.LoadAbsolute{Off: 16, Size: 2})
	a.op(bpf.StoreScratch{Src: bpf.RegA, N: 0})
	a.op(bpf.LoadIndirect{Off: 26, Size: 1})
	a.op(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0})
	a.op(bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2})
	a.op(bpf.ALUOpX{Op: bpf.ALUOpAdd})
	a.op(bpf.TAX{})
	a.op(bpf.LoadScratch{Dst: bpf.RegA, N: 0})
	a.op(bpf.ALUOpX{Op: bpf.ALUOpSub})
	a.jeq(0, "hdr", "")
	a.op(bpf.LoadIndirect{Off: 14, Size: 1})
	a.jeq(0x16, "", "drop")
	a.op(bpf.LoadIndirect{Off: 19, Size: 1})
	a.jeq(0x01, "hello", "drop")

	a.label("v4udp")
	a.op(bpf.LoadAbsolute{Off: 20, Size: 2})
	a.jset(0x1fff, "drop", "")
	a.op(bpf.LoadMemShift{Off: 14})
	a.op(bpf.LoadIndirect{Off: 14, Size: 2})
	a.jeq(443, "v4quic", "")
	a.jeq(53, "v4dns", "")
	a.op(bpf.LoadIndirect{Off: 16, Size: 2})
	a.jeq(443, "v4quic", "drop")
	a.label("v4quic")
	a.op(bpf.LoadIndirect{Off: 22, Size: 1})
	a.jset(0x80, "hdr", "drop")
	a.label("v4dns")
	fromRouter("dns", "drop")

	a.label("v6")
	a.op(bpf.LoadAbsolute{Off: 20, Size: 1})
	a.jeq(protoTCP, "v6tcp", "")
	a.jeq(protoUDP, "v6udp", "drop")

	a.label("v6tcp")
	a.op(bpf.LoadAbsolute{Off: 67, Size: 1})
	a.jset(flagSYN, "hdr", "")
	a.jset(flagFIN|flagRST, "drop", "")
	a.jset(flagACK, "", "drop")
	fromRouter("drop", "v6ack")
	a.label("v6ack")
	a.op(bpf.LoadAbsolute{Off: 66, Size: 1})
	a.op(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0})
	a.op(bpf.ALUOpConstant{Op: bpf.ALUOpShiftRight, Val: 2})
	a.op(bpf.TAX{})
	a.op(bpf.LoadAbsolute{Off: 18, Size: 2})
	a.op(bpf.ALUOpX{Op: bpf.ALUOpSub})
	a.jeq(0, "hdr", "")
	a.op(bpf.LoadIndirect{Off: 54, Size: 1})
	a.jeq(0x16, "", "drop")
	a.op(bpf.LoadIndirect{Off: 59, Size: 1})
	a.jeq(0x01, "hello", "drop")

	a.label("v6udp")
	a.op(bpf.LoadAbsolute{Off: 54, Size: 2})
	a.jeq(443, "v6quic", "")
	a.jeq(53, "v6dns", "")
	a.op(bpf.LoadAbsolute{Off: 56, Size: 2})
	a.jeq(443, "v6quic", "drop")
	a.label("v6quic")
	a.op(bpf.LoadAbsolute{Off: 62, Size: 1})
	a.jset(0x80, "hdr", "drop")
	a.label("v6dns")
	fromRouter("dns", "drop")

	a.label("hdr")
	a.op(bpf.RetConstant{Val: snapHeaders})
	a.label("hello")
	a.op(bpf.RetConstant{Val: snapHello})
	a.label("dns")
	a.op(bpf.RetConstant{Val: snapDNS})
	a.label("drop")
	a.op(bpf.RetConstant{Val: 0})

	prog, err := a.resolve()
	if err != nil {
		return nil, err
	}
	return bpf.Assemble(prog)
}

// asm builds a BPF program with symbolic jump targets. An empty target
// falls through to the next instruction.
type asm struct {
	ins    []bpf.Instruction
	jumps  map[int][2]string
	labels map[string]int
}

func (a *asm) op(i bpf.Instruction) { a.ins = append(a.ins, i) }

func (a *asm) label(name string) {
	if a.labels == nil {
		a.labels = map[string]int{}
	}
	a.labels[name] = len(a.ins)
}

func (a *asm) jump(cond bpf.JumpTest, val uint32, yes, no string) {
	if a.jumps == nil {
		a.jumps = map[int][2]string{}
	}
	a.jumps[len(a.ins)] = [2]string{yes, no}
	a.ins = append(a.ins, bpf.JumpIf{Cond: cond, Val: val})
}

func (a *asm) jeq(val uint32, yes, no string)  { a.jump(bpf.JumpEqual, val, yes, no) }
func (a *asm) jset(val uint32, yes, no string) { a.jump(bpf.JumpBitsSet, val, yes, no) }

func (a *asm) resolve() ([]bpf.Instruction, error) {
	out := append([]bpf.Instruction(nil), a.ins...)
	for at, t := range a.jumps {
		j := out[at].(bpf.JumpIf)
		skip := func(name string) (uint8, error) {
			if name == "" {
				return 0, nil
			}
			to, ok := a.labels[name]
			if !ok {
				return 0, fmt.Errorf("bpf: unknown label %q", name)
			}
			d := to - at - 1
			if d < 0 || d > 255 {
				return 0, fmt.Errorf("bpf: jump to %q out of range", name)
			}
			return uint8(d), nil
		}
		var err error
		if j.SkipTrue, err = skip(t[0]); err != nil {
			return nil, err
		}
		if j.SkipFalse, err = skip(t[1]); err != nil {
			return nil, err
		}
		out[at] = j
	}
	return out, nil
}
