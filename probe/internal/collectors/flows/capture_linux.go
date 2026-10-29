//go:build linux

package flows

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// socket is an AF_PACKET socket bound to one interface. Each frame comes
// with the kernel's receive timestamp, so the probe's own scheduling
// delays do not show up in the measured round trips.
type socket struct {
	fd  int
	buf []byte
	oob []byte
	// ports is set for a capture on all interfaces: only frames received
	// on an interface other than skipIndex are returned.
	ports     bool
	skipIndex int
}

// OpenCapture opens a packet socket on iface with filter attached. It
// needs CAP_NET_RAW.
func OpenCapture(iface string, filter []bpf.RawInstruction, rcvbuf int) (Capture, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	return open(ifi.Index, filter, rcvbuf)
}

// OpenBridgeCapture captures the frames a bridge forwards between its
// ports, which a socket on the bridge device itself does not see: frames
// passing through a bridge reach only the taps of the ports they arrive
// on and leave from. It listens on every interface and keeps the frames
// as they are received, so each frame is seen once, on its way in; frames
// delivered up to the bridge device are left out for the same reason.
func OpenBridgeCapture(bridge string, filter []bpf.RawInstruction, rcvbuf int) (Capture, error) {
	ifi, err := net.InterfaceByName(bridge)
	if err != nil {
		return nil, err
	}
	prog, err := IncomingOnly(filter, ifi.Index)
	if err != nil {
		return nil, err
	}
	c, err := open(0, prog, rcvbuf)
	if err != nil {
		return nil, err
	}
	s := c.(*socket)
	s.ports, s.skipIndex = true, ifi.Index
	return s, nil
}

func open(ifindex int, filter []bpf.RawInstruction, rcvbuf int) (Capture, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	// Attach the filter before binding, so no unfiltered frame is queued.
	prog := make([]unix.SockFilter, len(filter))
	for i, ins := range filter {
		prog[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog); err != nil {
		return nil, fmt.Errorf("attach filter: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		return nil, fmt.Errorf("timestamps: %w", err)
	}
	if rcvbuf > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf)
	}
	// A receive timeout lets Read return so the caller can stop.
	tv := unix.NsecToTimeval(int64(250 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, fmt.Errorf("receive timeout: %w", err)
	}
	sa := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, fmt.Errorf("bind interface %d: %w", ifindex, err)
	}
	ok = true
	return &socket{fd: fd, buf: make([]byte, snapHello+64), oob: make([]byte, 128)}, nil
}

// Read returns the next frame and its kernel timestamp. The frame is valid
// until the next call. It returns ErrTimeout when nothing arrived for a
// while.
func (s *socket) Read() ([]byte, time.Time, error) {
	for {
		n, oobn, _, from, err := unix.Recvmsg(s.fd, s.buf, s.oob, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return nil, time.Time{}, ErrTimeout
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, time.Time{}, err
		}
		if s.ports {
			// The filter already drops these; the check also holds where
			// the kernel ignores the filter's ancillary loads.
			if ll, ok := from.(*unix.SockaddrLinklayer); ok && (ll.Pkttype == unix.PACKET_OUTGOING || ll.Ifindex == s.skipIndex) {
				continue
			}
		}
		ts := time.Time{}
		if msgs, err := unix.ParseSocketControlMessage(s.oob[:oobn]); err == nil {
			for _, m := range msgs {
				if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SO_TIMESTAMPNS && len(m.Data) >= int(unsafe.Sizeof(unix.Timespec{})) {
					t := (*unix.Timespec)(unsafe.Pointer(&m.Data[0]))
					ts = time.Unix(int64(t.Sec), int64(t.Nsec))
				}
			}
		}
		if ts.IsZero() {
			ts = time.Now()
		}
		return s.buf[:n], ts, nil
	}
}

// Drops returns the frames the kernel dropped because the socket buffer
// was full, since the last call.
func (s *socket) Drops() uint64 {
	st, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0
	}
	return uint64(st.Drops)
}

func (s *socket) Close() error { return unix.Close(s.fd) }

func htons(v uint16) uint16 { return v<<8 | v>>8 }
