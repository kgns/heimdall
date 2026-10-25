package sample

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RotatingFile writes JSON lines to dir/name and rotates it to name.1 …
// name.(maxFiles-1) when it would exceed maxBytes, so total disk use stays
// below maxBytes*maxFiles. Output is buffered and flushed at most every
// flushEvery, and always on Close.
type RotatingFile struct {
	path       string
	maxBytes   int64
	maxFiles   int
	flushEvery time.Duration
	now        func() time.Time

	f         *os.File
	w         *bufio.Writer
	size      int64
	lastFlush time.Time
}

// NewRotatingFile opens or creates dir/name for appending.
func NewRotatingFile(dir, name string, maxBytes int64, maxFiles int, now func() time.Time) (*RotatingFile, error) {
	if maxBytes <= 0 || maxFiles < 1 {
		return nil, fmt.Errorf("rotating file: invalid limits %d bytes x %d files", maxBytes, maxFiles)
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	r := &RotatingFile{
		path:       filepath.Join(dir, name),
		maxBytes:   maxBytes,
		maxFiles:   maxFiles,
		flushEvery: time.Second,
		now:        now,
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	r.w = bufio.NewWriterSize(f, 32<<10)
	r.lastFlush = r.now()
	return nil
}

func (r *RotatingFile) Write(s *Sample) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if r.size > 0 && r.size+int64(len(b)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return err
		}
	}
	n, err := r.w.Write(b)
	r.size += int64(n)
	if err != nil {
		return err
	}
	if now := r.now(); now.Sub(r.lastFlush) >= r.flushEvery {
		r.lastFlush = now
		return r.w.Flush()
	}
	return nil
}

func (r *RotatingFile) rotate() error {
	if err := r.w.Flush(); err != nil {
		return err
	}
	if err := r.f.Close(); err != nil {
		return err
	}
	if r.maxFiles == 1 {
		if err := os.Remove(r.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return r.open()
	}
	os.Remove(fmt.Sprintf("%s.%d", r.path, r.maxFiles-1))
	for i := r.maxFiles - 2; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil {
		return err
	}
	return r.open()
}

// Close flushes and closes the current file.
func (r *RotatingFile) Close() error {
	if r.f == nil {
		return nil
	}
	ferr := r.w.Flush()
	cerr := r.f.Close()
	r.f = nil
	if ferr != nil {
		return ferr
	}
	return cerr
}
