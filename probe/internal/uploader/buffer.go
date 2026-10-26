// Package uploader buffers encoded samples in memory and sends them to the
// ingest API in gzip-compressed batches, holding them through outages up
// to a size limit.
package uploader

import (
	"encoding/json"
	"sync"

	"github.com/kgns/heimdall/probe/internal/sample"
)

// Buffer is a FIFO of JSON-encoded samples bounded by total size. When a new
// sample does not fit, the oldest ones are dropped: recent data is worth
// more than old data after a long outage.
type Buffer struct {
	mu       sync.Mutex
	items    [][]byte
	head     int
	bytes    int
	maxBytes int
	dropped  uint64
}

// NewBuffer returns a buffer holding at most maxBytes of encoded samples.
func NewBuffer(maxBytes int) *Buffer {
	return &Buffer{maxBytes: maxBytes}
}

// Write implements sample.Sink.
func (b *Buffer) Write(s *sample.Sample) error {
	enc, err := json.Marshal(s)
	if err != nil {
		return err
	}
	b.Push(enc)
	return nil
}

// Close implements sample.Sink.
func (b *Buffer) Close() error { return nil }

// Push appends one encoded sample.
func (b *Buffer) Push(enc []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(enc) > b.maxBytes {
		b.dropped++
		return
	}
	for b.bytes+len(enc) > b.maxBytes && b.len() > 0 {
		b.bytes -= len(b.items[b.head])
		b.items[b.head] = nil
		b.head++
		b.dropped++
	}
	b.items = append(b.items, enc)
	b.bytes += len(enc)
	b.compact()
}

func (b *Buffer) len() int { return len(b.items) - b.head }

// compact reclaims the consumed prefix once it dominates the slice.
func (b *Buffer) compact() {
	if b.head > 1024 && b.head > len(b.items)/2 {
		n := copy(b.items, b.items[b.head:])
		clear(b.items[n:])
		b.items = b.items[:n]
		b.head = 0
	}
}

// Peek returns up to max oldest samples whose total size stays within
// maxBytes (at least one sample is returned when any is buffered). The
// returned slices must not be modified.
func (b *Buffer) Peek(max, maxBytes int) [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out [][]byte
	size := 0
	for i := b.head; i < len(b.items) && len(out) < max; i++ {
		if len(out) > 0 && size+len(b.items[i]) > maxBytes {
			break
		}
		out = append(out, b.items[i])
		size += len(b.items[i])
	}
	return out
}

// Commit removes the n oldest samples after a successful upload. Samples
// dropped meanwhile to make room are accounted for, so a commit never
// removes samples that were not part of the batch.
func (b *Buffer) Commit(batch [][]byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Find where the batch still overlaps the buffer: when the oldest
	// samples were dropped during the upload, the head has already moved
	// past part of the batch.
	if len(batch) == 0 || b.len() == 0 {
		return
	}
	last := batch[len(batch)-1]
	for i := b.head; i < len(b.items) && i < b.head+len(batch); i++ {
		if sameSlice(b.items[i], last) {
			for j := b.head; j <= i; j++ {
				b.bytes -= len(b.items[j])
				b.items[j] = nil
			}
			b.head = i + 1
			b.compact()
			return
		}
	}
}

func sameSlice(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// Stats is a snapshot of the buffer.
type Stats struct {
	Samples  int    `json:"samples"`
	Bytes    int    `json:"bytes"`
	MaxBytes int    `json:"max_bytes"`
	Dropped  uint64 `json:"dropped"`
}

// Stats returns the current fill level and the total dropped count.
func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return Stats{Samples: b.len(), Bytes: b.bytes, MaxBytes: b.maxBytes, Dropped: b.dropped}
}
