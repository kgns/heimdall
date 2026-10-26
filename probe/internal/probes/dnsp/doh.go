package dnsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/kgns/heimdall/probe/internal/probes/tlsconf"
)

// DoH is an RFC 8484 client that connects to a fixed address, so that no
// lookup through the system resolver is needed to reach the DoH server.
// Connections are kept alive between queries, as browsers and stub
// resolvers do; the measured time is then one HTTPS round trip plus the
// resolver's own work.
type DoH struct {
	URL    string
	client *http.Client
}

// NewDoH returns a client for url (https://host/path) reached at addr.
func NewDoH(url string, addr netip.AddrPort, roots *x509.CertPool) (*DoH, error) {
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("DoH URL %q is not https", url)
	}
	var dialer net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr.String())
		},
		TLSClientConfig:     tlsconf.Client(req.URL.Hostname(), roots),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     5 * time.Minute,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &DoH{URL: url, client: &http.Client{Transport: tr}}, nil
}

// Exchange implements Exchanger. The message ID is set to 0 as RFC 8484
// recommends for cache friendliness.
func (d *DoH) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("DoH HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("DoH response: %w", err)
	}
	return out, nil
}

// Close drops idle connections.
func (d *DoH) Close() { d.client.CloseIdleConnections() }
