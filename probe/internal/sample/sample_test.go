package sample

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSampleJSON(t *testing.T) {
	lost := Sample{TS: 1, Kind: KindICMP, Status: StatusTimeout}
	b, _ := json.Marshal(lost)
	if !strings.Contains(string(b), `"rtt_ms":null`) {
		t.Fatalf("lost sample must carry rtt_ms null: %s", b)
	}
	if strings.Contains(string(b), "extra") || strings.Contains(string(b), "dst_port") {
		t.Fatalf("empty optional fields serialized: %s", b)
	}
	ok := Sample{RTTms: RTT(12345678 * time.Nanosecond)}
	b, _ = json.Marshal(ok)
	if !strings.Contains(string(b), `"rtt_ms":12.346`) {
		t.Fatalf("rtt not rounded to microseconds: %s", b)
	}
}

func TestRecorder(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	mem := &MemorySink{}
	r := NewRecorder("dev1", func() time.Time { return now }, mem)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Emit(Sample{Kind: KindICMP})
		}()
	}
	wg.Wait()
	r.Emit(Sample{TS: 42, Kind: KindEvent})

	got := mem.Samples()
	if len(got) != 51 || r.Emitted() != 51 {
		t.Fatalf("got %d samples, emitted %d", len(got), r.Emitted())
	}
	seen := map[uint64]bool{}
	for _, s := range got {
		if s.Device != "dev1" || seen[s.Seq] {
			t.Fatalf("bad sample %+v", s)
		}
		seen[s.Seq] = true
	}
	if got[50].TS != 42 || got[0].TS != now.UnixMilli() {
		t.Fatalf("timestamps %d %d", got[0].TS, got[50].TS)
	}

	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r.Emit(Sample{})
	if len(mem.Samples()) != 51 {
		t.Fatal("emit after close was recorded")
	}
}

type failSink struct{}

func (failSink) Write(*Sample) error { return fmt.Errorf("disk full") }
func (failSink) Close() error        { return nil }

func TestRecorderCountsSinkErrors(t *testing.T) {
	mem := &MemorySink{}
	r := NewRecorder("d", nil, failSink{}, mem)
	r.Emit(Sample{})
	if r.WriteErrors() != 1 || len(mem.Samples()) != 1 {
		t.Fatalf("errors %d samples %d", r.WriteErrors(), len(mem.Samples()))
	}
}

func TestStreamSink(t *testing.T) {
	var buf bytes.Buffer
	s := NewStreamSink(&buf)
	s.Write(&Sample{Kind: KindICMP})
	s.Write(&Sample{Kind: KindEvent})
	if n := strings.Count(buf.String(), "\n"); n != 2 {
		t.Fatalf("%d lines", n)
	}
}

func TestRotatingFile(t *testing.T) {
	dir := t.TempDir()
	clock := time.Unix(0, 0)
	rf, err := NewRotatingFile(dir, "samples.jsonl", 1000, 3, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		clock = clock.Add(100 * time.Millisecond)
		if err := rf.Write(&Sample{Seq: uint64(i), Kind: KindICMP, Status: StatusOK}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rf.Close(); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(dir)
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	if len(names) != 3 || !names["samples.jsonl"] || !names["samples.jsonl.1"] || !names["samples.jsonl.2"] {
		t.Fatalf("files = %v", names)
	}

	var last uint64
	for _, name := range []string{"samples.jsonl.2", "samples.jsonl.1", "samples.jsonl"} {
		p := filepath.Join(dir, name)
		st, _ := os.Stat(p)
		if st.Size() > 1000 {
			t.Fatalf("%s is %d bytes", name, st.Size())
		}
		f, _ := os.Open(p)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var s Sample
			if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if last != 0 && s.Seq != last+1 {
				t.Fatalf("%s: seq %d after %d", name, s.Seq, last)
			}
			last = s.Seq
		}
		f.Close()
	}
	if last != 199 {
		t.Fatalf("newest seq %d, want 199", last)
	}
}

func TestRotatingFileSingleFile(t *testing.T) {
	dir := t.TempDir()
	rf, err := NewRotatingFile(dir, "s.jsonl", 300, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		rf.Write(&Sample{Seq: uint64(i)})
	}
	rf.Close()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("%d files", len(entries))
	}
	if _, err := NewRotatingFile(dir, "x", 0, 1, nil); err == nil {
		t.Fatal("zero size accepted")
	}
}
