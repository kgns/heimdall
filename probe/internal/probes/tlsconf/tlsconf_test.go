package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func handshake(t *testing.T, server []tls.CurveID) (tls.ConnectionState, error) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{CurvePreferences: server, MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := tls.Dial("tcp", srv.Listener.Addr().String(), Client("example.com", pool))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer c.Close()
	return c.ConnectionState(), nil
}

func TestClientNeverNegotiatesP521(t *testing.T) {
	if _, err := handshake(t, []tls.CurveID{tls.CurveP521}); err == nil {
		t.Fatal("handshake succeeded with a P-521-only server; P-521 is offered")
	}
	st, err := handshake(t, []tls.CurveID{tls.CurveP521, tls.CurveP384})
	if err != nil || st.CurveID != tls.CurveP384 {
		t.Fatalf("server preferring P-521 then P-384: curve %v err %v", st.CurveID, err)
	}
}

func TestClientDefaultsToPostQuantumHybrid(t *testing.T) {
	st, err := handshake(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.CurveID != tls.X25519MLKEM768 || st.Version != tls.VersionTLS13 {
		t.Fatalf("curve %v version %x", st.CurveID, st.Version)
	}
}
