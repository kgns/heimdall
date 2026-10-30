package uploader

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// item returns a fixed-size encoded sample.
func item(i int) []byte {
	return []byte(fmt.Sprintf(`{"seq":%06d,"pad":"%s"}`, i, "xxxxxxxxxxxxxxxxxxxx"))
}

func TestBufferDropsOldest(t *testing.T) {
	b := NewBuffer(5 * len(item(0)))
	for i := range 8 {
		b.Push(item(i))
	}
	st := b.Stats()
	if st.Samples != 5 || st.Dropped != 3 || st.Bytes > st.MaxBytes {
		t.Fatalf("%+v", st)
	}
	got := b.Peek(100, 1<<20)
	if string(got[0]) != string(item(3)) || string(got[4]) != string(item(7)) {
		t.Fatalf("kept %s .. %s", got[0], got[4])
	}
	b.Push(make([]byte, st.MaxBytes+1))
	if b.Stats().Dropped != 4 || b.Stats().Samples != 5 {
		t.Fatal("oversized sample not dropped on its own")
	}
}

func TestBufferPeekLimits(t *testing.T) {
	b := NewBuffer(1 << 20)
	for i := range 10 {
		b.Push(item(i))
	}
	if n := len(b.Peek(4, 1<<20)); n != 4 {
		t.Fatalf("count limit: %d", n)
	}
	if n := len(b.Peek(100, 3*len(item(0)))); n != 3 {
		t.Fatalf("byte limit: %d", n)
	}
	if n := len(b.Peek(100, 1)); n != 1 {
		t.Fatalf("at least one sample must be returned: %d", n)
	}
}

func TestBufferCommitAfterDrops(t *testing.T) {
	b := NewBuffer(6 * len(item(0)))
	for i := range 6 {
		b.Push(item(i))
	}
	batch := b.Peek(4, 1<<20) // items 0..3
	// During the upload, two new samples push out items 0 and 1.
	b.Push(item(6))
	b.Push(item(7))
	b.Commit(batch)
	got := b.Peek(100, 1<<20)
	if len(got) != 4 || string(got[0]) != string(item(4)) {
		t.Fatalf("after commit: %d items, first %s", len(got), got[0])
	}

	// A batch that was dropped entirely leaves the buffer alone.
	old := b.Peek(1, 1<<20)
	for i := range 6 {
		b.Push(item(100 + i))
	}
	b.Commit(old)
	if b.Stats().Samples != 6 {
		t.Fatal("commit of a fully dropped batch removed samples")
	}
}

func TestBufferCompaction(t *testing.T) {
	b := NewBuffer(1 << 30)
	for i := range 5000 {
		b.Push(item(i))
		if i%2 == 1 {
			b.Commit(b.Peek(2, 1<<20))
		}
	}
	if b.Stats().Samples != 0 || len(b.items) > 2100 {
		t.Fatalf("samples %d, backing slice %d", b.Stats().Samples, len(b.items))
	}
}

// server records decoded envelopes and answers with the next status from
// statuses, then 200.
type server struct {
	mu        sync.Mutex
	statuses  []int
	envelopes []map[string]any
	samples   []map[string]any
	auth      []string
	reply     string
}

func (s *server) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	code := http.StatusOK
	if len(s.statuses) > 0 {
		code, s.statuses = s.statuses[0], s.statuses[1:]
	}
	if code != http.StatusOK {
		w.WriteHeader(code)
		return
	}
	if r.Header.Get("Content-Encoding") != "gzip" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	raw, _ := io.ReadAll(zr)
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, x := range env["samples"].([]any) {
		s.samples = append(s.samples, x.(map[string]any))
	}
	delete(env, "samples")
	s.envelopes = append(s.envelopes, env)
	if s.reply != "" {
		w.Write([]byte(s.reply))
		return
	}
	w.Write([]byte(`{"accepted":1}`))
}

func (s *server) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.samples)
}

func newUploader(t *testing.T, srv *httptest.Server, buf *Buffer, mut func(*Options)) *Uploader {
	t.Helper()
	opt := Options{
		URL: srv.URL + "/v1/batch", Token: "tkn", Device: "dev1", ProbeVersion: "test",
		Interval: 20 * time.Millisecond, Timeout: time.Second, MaxBatch: 50, MaxBatchBytes: 1 << 20,
		MinBackoff: 10 * time.Millisecond, MaxBackoff: 40 * time.Millisecond,
		ClockOffset:    func() (time.Duration, bool) { return 386 * time.Millisecond, true },
		HTTPClient:     srv.Client(),
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		DrainAfterStop: time.Second,
	}
	if mut != nil {
		mut(&opt)
	}
	u, err := New(buf, opt)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUploadEnvelopeAndOrder(t *testing.T) {
	s := &server{}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	buf := NewBuffer(1 << 20)
	rec := sample.NewRecorder("dev1", nil, buf)
	for range 120 {
		rec.Emit(sample.Sample{Kind: sample.KindICMP, Status: sample.StatusOK})
	}
	u := newUploader(t, srv, buf, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	waitFor(t, "all samples", func() bool { return s.count() == 120 })
	cancel()
	<-done

	s.mu.Lock()
	defer s.mu.Unlock()
	for i, smp := range s.samples {
		if int(smp["seq"].(float64)) != i+1 {
			t.Fatalf("sample %d has seq %v", i, smp["seq"])
		}
	}
	if len(s.envelopes) != 3 {
		t.Fatalf("%d batches for 120 samples at 50 per batch", len(s.envelopes))
	}
	e := s.envelopes[0]
	if e["device"] != "dev1" || e["probe_version"] != "test" || e["run_id"] != u.RunID() || e["batch_seq"] != 1.0 ||
		e["clock_offset_ms"] != 386.0 || e["dropped_since_last"] != 0.0 {
		t.Fatalf("envelope %+v", e)
	}
	if s.envelopes[2]["batch_seq"] != 3.0 || s.auth[0] != "Bearer tkn" {
		t.Fatalf("batch seq %v auth %q", s.envelopes[2]["batch_seq"], s.auth[0])
	}
	if st := u.Status(); st.OK != 3 || st.Failed != 0 || st.LastStatus != 200 {
		t.Fatalf("%+v", st)
	}
}

func TestUploadSurvivesOutage(t *testing.T) {
	s := &server{statuses: []int{503, 503, 502, 504, 503, 503}}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	buf := NewBuffer(1 << 20)
	rec := sample.NewRecorder("dev1", nil, buf)
	u := newUploader(t, srv, buf, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)

	var emitted atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				rec.Emit(sample.Sample{Kind: sample.KindICMP, Status: sample.StatusOK})
				emitted.Add(1)
				time.Sleep(time.Millisecond)
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	waitFor(t, "backlog", func() bool { return int64(s.count()) == emitted.Load() })
	if st := u.Status(); st.Failed != 6 || buf.Stats().Dropped != 0 {
		t.Fatalf("status %+v buffer %+v", st, buf.Stats())
	}
}

func TestUploadReportsDrops(t *testing.T) {
	s := &server{statuses: []int{503}}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	buf := NewBuffer(10 * 200)
	rec := sample.NewRecorder("dev1", nil, buf)
	for range 50 {
		rec.Emit(sample.Sample{Kind: sample.KindICMP, Status: sample.StatusOK, TargetID: "padding-padding-padding-padding"})
	}
	dropped := buf.Stats().Dropped
	if dropped == 0 {
		t.Fatal("test needs a full buffer")
	}
	u := newUploader(t, srv, buf, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	waitFor(t, "upload", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.envelopes) > 0 })
	s.mu.Lock()
	defer s.mu.Unlock()
	if got := uint64(s.envelopes[0]["dropped_since_last"].(float64)); got != dropped {
		t.Fatalf("dropped_since_last %d, want %d", got, dropped)
	}
}

func TestUploadDiscardsRejectedBatch(t *testing.T) {
	s := &server{statuses: []int{400}}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	buf := NewBuffer(1 << 20)
	rec := sample.NewRecorder("dev1", nil, buf)
	for range 10 {
		rec.Emit(sample.Sample{Kind: sample.KindICMP, Status: sample.StatusOK})
	}
	u := newUploader(t, srv, buf, func(o *Options) { o.MaxBatch = 5 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	waitFor(t, "second batch", func() bool { return s.count() == 5 })
	if st := u.Status(); st.Discarded != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestUploadDrainsOnStop(t *testing.T) {
	s := &server{}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	buf := NewBuffer(1 << 20)
	u := newUploader(t, srv, buf, func(o *Options) { o.Interval = time.Hour })
	rec := sample.NewRecorder("dev1", nil, buf)
	for range 130 {
		rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u.Run(ctx)
	if s.count() != 130 {
		t.Fatalf("drained %d of 130", s.count())
	}
}

func TestNewValidates(t *testing.T) {
	buf := NewBuffer(1024)
	if _, err := New(buf, Options{URL: "http://x/v1/batch", Token: "t"}); err == nil {
		t.Fatal("plain http accepted")
	}
	if _, err := New(buf, Options{URL: "https://x/v1/batch"}); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestBackoff(t *testing.T) {
	var base, wait time.Duration
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, time.Minute, time.Minute}
	for i, w := range want {
		base, wait = nextBackoff(base, time.Second, time.Minute)
		if base != w {
			t.Fatalf("step %d: base %v, want %v", i, base, w)
		}
		if wait < base/2 || wait > base {
			t.Fatalf("step %d: wait %v outside [%v, %v]", i, wait, base/2, base)
		}
	}
}

func TestKickAndReply(t *testing.T) {
	s := &server{reply: `{"accepted":1,"fast_until_ms":1793400000000}`}
	srv := httptest.NewTLSServer(http.HandlerFunc(s.handler))
	defer srv.Close()
	buf := NewBuffer(1 << 20)
	rec := sample.NewRecorder("dev1", nil, buf)
	var mu sync.Mutex
	var got Reply
	u := newUploader(t, srv, buf, func(o *Options) {
		o.Interval = time.Hour
		o.OnReply = func(r Reply) { mu.Lock(); got = r; mu.Unlock() }
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	rec.Emit(sample.Sample{Kind: sample.KindEvent, Status: sample.StatusOK})
	u.Kick()
	waitFor(t, "kicked upload", func() bool { return s.count() == 1 })
	mu.Lock()
	defer mu.Unlock()
	if got.FastUntilMs != 1793400000000 {
		t.Fatalf("reply %+v", got)
	}
}
