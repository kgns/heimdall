// Package neterr maps network errors to sample statuses.
package neterr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// Classify returns the sample status for err and a short machine-readable
// reason. It returns StatusOK and "" for a nil error.
func Classify(err error) (sample.Status, string) {
	if err == nil {
		return sample.StatusOK, ""
	}
	var (
		unknownAuth x509.UnknownAuthorityError
		hostErr     x509.HostnameError
		certInvalid x509.CertificateInvalidError
		recordErr   tls.RecordHeaderError
		alertErr    tls.AlertError
		dnsErr      *net.DNSError
	)
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), isTimeout(err):
		return sample.StatusTimeout, "timeout"
	case errors.Is(err, syscall.ECONNREFUSED):
		return sample.StatusRefused, "refused"
	case errors.Is(err, syscall.ECONNRESET):
		return sample.StatusError, "reset"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return sample.StatusUnreachable, "unreachable"
	case errors.As(err, &unknownAuth), errors.As(err, &hostErr), errors.As(err, &certInvalid):
		return sample.StatusError, "tls_verify"
	case errors.As(err, &recordErr), errors.As(err, &alertErr):
		return sample.StatusError, "tls"
	case errors.As(err, &dnsErr):
		if dnsErr.IsNotFound {
			return sample.StatusError, "nxdomain"
		}
		return sample.StatusError, "dns"
	}
	return sample.StatusError, "error"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
