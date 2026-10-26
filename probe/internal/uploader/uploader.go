package uploader

import (
	"bytes"
	"compress/gzip"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/kgns/heimdall/probe/internal/probes/tlsconf"
)

// Options configure an Uploader.
type Options struct {
	URL            string
	Token          string
	Device         string
	ProbeVersion   string
	Interval       time.Duration
	Timeout        time.Duration
	MaxBatch       int
	MaxBatchBytes  int
	MinBackoff     time.Duration
	MaxBackoff     time.Duration
	ClockOffset    func() (time.Duration, bool)
	Allowed        func(netip.Addr) bool
	Lookup         func(ctx context.Context, host string) ([]netip.Addr, error)
	HTTPClient     *http.Client
	Log            *slog.Logger
	DrainAfterStop time.Duration
}

// Uploader sends the buffer's contents in batches.
type Uploader struct {
	opt    Options
	buf    *Buffer
	runID  string
	client *http.Client

	mu          sync.Mutex
	batchSeq    uint64
	lastDropped uint64
	st          Status
}

// Status describes upload health for heartbeats.
type Status struct {
	OK          uint64 `json:"ok"`
	Failed      uint64 `json:"failed"`
	Discarded   uint64 `json:"discarded_batches"`
	LastStatus  int    `json:"last_status"`
	LastError   string `json:"last_error,omitempty"`
	LastSuccess int64  `json:"last_success_ms,omitempty"`
	Backoff     string `json:"backoff,omitempty"`
}

// New returns an uploader draining buf.
func New(buf *Buffer, opt Options) (*Uploader, error) {
	u, err := url.Parse(opt.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("upload url %q must be https://host/path", opt.URL)
	}
	if opt.Token == "" {
		return nil, errors.New("upload token is empty")
	}
	var id [8]byte
	if _, err := cryptoRead(id[:]); err != nil {
		return nil, err
	}
	up := &Uploader{opt: opt, buf: buf, runID: hex.EncodeToString(id[:])}
	up.client = opt.HTTPClient
	if up.client == nil {
		up.client = up.defaultClient(u.Hostname())
	}
	return up, nil
}

var cryptoRead = crand.Read

// RunID identifies this probe process in every batch.
func (u *Uploader) RunID() string { return u.runID }

// Status returns a snapshot of upload counters.
func (u *Uploader) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.st
}

// defaultClient resolves the ingest host through the system resolver and
// connects only to addresses the route guard allows.
func (u *Uploader) defaultClient(host string) *http.Client {
	var dialer net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var addrs []netip.Addr
			if a, err := netip.ParseAddr(h); err == nil {
				addrs = []netip.Addr{a}
			} else if addrs, err = u.opt.Lookup(ctx, h); err != nil {
				return nil, err
			}
			var lastErr error = fmt.Errorf("no allowed address for %s", h)
			for _, a := range addrs {
				if !a.Is4() || (u.opt.Allowed != nil && !u.opt.Allowed(a)) {
					continue
				}
				c, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(a.String(), port))
				if err == nil {
					return c, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
		TLSClientConfig:     tlsconf.Client(host, nil),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        1,
		IdleConnTimeout:     2 * time.Minute,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: u.opt.Timeout}
}

// Run sends batches until ctx is done, then tries once more to flush what
// is buffered within DrainAfterStop.
func (u *Uploader) Run(ctx context.Context) {
	backoff := time.Duration(0)
	timer := time.NewTimer(u.opt.Interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			u.drain()
			return
		case <-timer.C:
		}
		next := u.opt.Interval
		// Stopping must not abort a request the server may already have
		// stored: the batch would stay buffered and drain would send it
		// twice. The request is still bounded by Options.Timeout.
		sent, err := u.sendOnce(context.WithoutCancel(ctx))
		switch {
		case err != nil:
			backoff, next = nextBackoff(backoff, u.opt.MinBackoff, u.opt.MaxBackoff)
			u.mu.Lock()
			u.st.Backoff = next.Round(time.Second).String()
			u.mu.Unlock()
		default:
			backoff = 0
			u.mu.Lock()
			u.st.Backoff = ""
			u.mu.Unlock()
			// A full batch means a backlog: keep sending without waiting
			// for the next interval.
			if sent >= u.opt.MaxBatch {
				next = 200 * time.Millisecond
			}
		}
		timer.Reset(next)
	}
}

func (u *Uploader) drain() {
	if u.opt.DrainAfterStop <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), u.opt.DrainAfterStop)
	defer cancel()
	for ctx.Err() == nil {
		n, err := u.sendOnce(ctx)
		if err != nil || n == 0 || n < u.opt.MaxBatch {
			return
		}
	}
}

// nextBackoff doubles base within [lo, hi] and returns the new base plus the
// wait to use. The wait is jittered and the base is not, so the jitter does
// not feed back into the next step.
func nextBackoff(base, lo, hi time.Duration) (time.Duration, time.Duration) {
	if base < lo {
		base = lo
	} else {
		base *= 2
	}
	if base > hi {
		base = hi
	}
	// Jitter in [base/2, base] keeps many probes from retrying in step.
	return base, base/2 + time.Duration(rand.Int64N(int64(base/2)+1))
}

// sendOnce uploads one batch and returns how many samples it carried.
func (u *Uploader) sendOnce(ctx context.Context) (int, error) {
	batch := u.buf.Peek(u.opt.MaxBatch, u.opt.MaxBatchBytes)
	if len(batch) == 0 {
		return 0, nil
	}
	u.mu.Lock()
	seq := u.batchSeq + 1
	dropped := u.buf.Stats().Dropped
	sinceLast := dropped - u.lastDropped
	u.mu.Unlock()

	body, err := u.encode(batch, seq, sinceLast)
	if err != nil {
		return 0, err
	}
	status, err := u.post(ctx, body)
	u.mu.Lock()
	defer u.mu.Unlock()
	u.st.LastStatus = status
	switch {
	case err == nil && status == http.StatusOK:
		u.buf.Commit(batch)
		u.batchSeq = seq
		u.lastDropped = dropped
		u.st.OK++
		u.st.LastError = ""
		u.st.LastSuccess = time.Now().UnixMilli()
		return len(batch), nil
	case err == nil && (status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge):
		// The server will reject this batch every time; keeping it would
		// block everything behind it.
		u.buf.Commit(batch)
		u.batchSeq = seq
		u.st.Discarded++
		u.st.LastError = "HTTP " + strconv.Itoa(status)
		u.opt.Log.Warn("upload batch discarded", "status", status, "samples", len(batch))
		return len(batch), nil
	case err == nil:
		err = fmt.Errorf("HTTP %d", status)
	}
	u.st.Failed++
	u.st.LastError = err.Error()
	if u.st.Failed == 1 || u.st.Failed%10 == 0 {
		u.opt.Log.Warn("upload failed", "err", err, "buffered", u.buf.Stats().Samples, "failures", u.st.Failed)
	}
	return 0, err
}

type envelope struct {
	Device        string          `json:"device"`
	ProbeVersion  string          `json:"probe_version"`
	RunID         string          `json:"run_id"`
	BatchSeq      uint64          `json:"batch_seq"`
	Dropped       uint64          `json:"dropped_since_last"`
	ClockOffsetMs *float64        `json:"clock_offset_ms"`
	Samples       json.RawMessage `json:"samples"`
}

func (u *Uploader) encode(batch [][]byte, seq, dropped uint64) ([]byte, error) {
	var samples bytes.Buffer
	samples.WriteByte('[')
	for i, s := range batch {
		if i > 0 {
			samples.WriteByte(',')
		}
		samples.Write(s)
	}
	samples.WriteByte(']')
	env := envelope{
		Device: u.opt.Device, ProbeVersion: u.opt.ProbeVersion, RunID: u.runID,
		BatchSeq: seq, Dropped: dropped, Samples: samples.Bytes(),
	}
	if u.opt.ClockOffset != nil {
		if off, ok := u.opt.ClockOffset(); ok {
			ms := float64(off.Microseconds()) / 1000
			env.ClockOffsetMs = &ms
		}
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	zw.Write(raw)
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func (u *Uploader) post(ctx context.Context, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, u.opt.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.opt.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+u.opt.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("User-Agent", "heimdall-probe/"+u.opt.ProbeVersion)
	resp, err := u.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, nil
}
