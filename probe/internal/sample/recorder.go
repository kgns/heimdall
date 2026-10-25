package sample

import (
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Sink receives samples. Write is called with the recorder's lock held, so
// implementations need no locking of their own but must not block for long.
type Sink interface {
	Write(s *Sample) error
	Close() error
}

// Recorder stamps samples with the device ID and a per-process sequence
// number and hands them to every sink.
type Recorder struct {
	device string
	now    func() time.Time
	seq    atomic.Uint64

	mu     sync.Mutex
	sinks  []Sink
	closed bool

	writeErrors atomic.Uint64
}

// NewRecorder returns a recorder that writes to sinks.
func NewRecorder(device string, now func() time.Time, sinks ...Sink) *Recorder {
	if now == nil {
		now = time.Now
	}
	return &Recorder{device: device, now: now, sinks: sinks}
}

// Emit records s. A zero TS is set to the current time.
func (r *Recorder) Emit(s Sample) {
	if s.TS == 0 {
		s.TS = r.now().UnixMilli()
	}
	s.Device = r.device
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	s.Seq = r.seq.Add(1)
	for _, sk := range r.sinks {
		if err := sk.Write(&s); err != nil {
			r.writeErrors.Add(1)
		}
	}
}

// Emitted returns the number of samples recorded so far.
func (r *Recorder) Emitted() uint64 { return r.seq.Load() }

// WriteErrors returns the number of failed sink writes.
func (r *Recorder) WriteErrors() uint64 { return r.writeErrors.Load() }

// Close closes all sinks. Later Emit calls are dropped.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	for _, sk := range r.sinks {
		errs = append(errs, sk.Close())
	}
	return errors.Join(errs...)
}

// StreamSink writes one JSON object per line to w.
type StreamSink struct {
	w   io.Writer
	enc *json.Encoder
}

// NewStreamSink returns a sink writing JSON lines to w.
func NewStreamSink(w io.Writer) *StreamSink {
	return &StreamSink{w: w, enc: json.NewEncoder(w)}
}

func (s *StreamSink) Write(smp *Sample) error { return s.enc.Encode(smp) }
func (s *StreamSink) Close() error            { return nil }

// MemorySink keeps samples in memory. It is meant for tests.
type MemorySink struct {
	mu      sync.Mutex
	samples []Sample
}

func (m *MemorySink) Write(s *Sample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.samples = append(m.samples, *s)
	return nil
}

func (m *MemorySink) Close() error { return nil }

// Samples returns a copy of the recorded samples.
func (m *MemorySink) Samples() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Sample(nil), m.samples...)
}
