// Package tlsconf builds the TLS client configuration shared by the HTTPS
// and DoH probes.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
)

// BrowserCurves are the key exchange groups current Chrome and Firefox
// offer. Matching them keeps handshakes representative of what users get,
// and leaves out P-521: some servers prefer it, and without assembly
// support its key exchange costs hundreds of milliseconds on 32-bit ARM,
// which would show up as network latency.
var BrowserCurves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}

// Client returns a verifying TLS 1.2+ client configuration for serverName.
// A nil roots uses the system pool.
func Client(serverName string, roots *x509.CertPool) *tls.Config {
	return &tls.Config{
		ServerName:       serverName,
		RootCAs:          roots,
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: BrowserCurves,
	}
}
