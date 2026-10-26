package neterr

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/kgns/heimdall/probe/internal/sample"
)

func TestClassify(t *testing.T) {
	op := func(err error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: err}}
	}
	tests := []struct {
		err    error
		status sample.Status
		reason string
	}{
		{nil, sample.StatusOK, ""},
		{context.DeadlineExceeded, sample.StatusTimeout, "timeout"},
		{fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), sample.StatusTimeout, "timeout"},
		{op(syscall.ECONNREFUSED), sample.StatusRefused, "refused"},
		{op(syscall.ECONNRESET), sample.StatusError, "reset"},
		{op(syscall.EHOSTUNREACH), sample.StatusUnreachable, "unreachable"},
		{op(syscall.ENETUNREACH), sample.StatusUnreachable, "unreachable"},
		{fmt.Errorf("tls: %w", x509.UnknownAuthorityError{}), sample.StatusError, "tls_verify"},
		{x509.HostnameError{Host: "x"}, sample.StatusError, "tls_verify"},
		{&net.DNSError{IsNotFound: true}, sample.StatusError, "nxdomain"},
		{&net.DNSError{IsTimeout: true}, sample.StatusTimeout, "timeout"},
		{errors.New("boom"), sample.StatusError, "error"},
	}
	for _, tc := range tests {
		st, reason := Classify(tc.err)
		if st != tc.status || reason != tc.reason {
			t.Errorf("Classify(%v) = %s %s, want %s %s", tc.err, st, reason, tc.status, tc.reason)
		}
	}
}
