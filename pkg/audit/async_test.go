package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAsyncRecorderWritesPreparedSnapshot(t *testing.T) {
	var output bytes.Buffer
	recorder := NewAsyncRecorder(NewStdoutSink(&output), 4, nil)
	event := Event{Type: "operation.start", Fields: map[string]string{"command": "id"}}
	recorder.Record(context.Background(), event)
	event.Fields["command"] = "changed"

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := recorder.Close(ctx); err != nil {
		t.Fatalf("close recorder: %v", err)
	}
	var got Event
	if err := json.NewDecoder(&output).
		Decode(&got); err != nil {
		t.Fatalf("decode event: %v", err)
	}
	if got.SchemaVersion != SchemaVersion || got.ID == "" || got.Time.IsZero() {
		t.Fatalf("event envelope not prepared: %+v", got)
	}
	if got.Fields["command"] != "id" {
		t.Fatalf("event was not snapshotted: %+v", got.Fields)
	}
}

func TestAsyncRecorderDropsWhenQueueIsFull(t *testing.T) {
	sink := &blockingSink{started: make(chan struct{}), release: make(chan struct{})}
	var mu sync.Mutex
	results := map[string]int{}
	recorder := NewAsyncRecorder(sink, 1, func(result string) {
		mu.Lock()
		defer mu.Unlock()
		results[result]++
	})
	recorder.Record(context.Background(), Event{Type: "first"})
	<-sink.started
	recorder.Record(context.Background(), Event{Type: "queued"})
	recorder.Record(context.Background(), Event{Type: "dropped"})
	close(sink.release)
	if err := recorder.Close(context.Background()); err != nil {
		t.Fatalf("close recorder: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if results[ResultDropped] != 1 || results[ResultWritten] != 2 {
		t.Fatalf("results = %#v", results)
	}
}

func TestAsyncRecorderClosesSinkOnce(t *testing.T) {
	sink := &countingCloseSink{}
	recorder := NewAsyncRecorder(sink, 1, nil)

	const callers = 8
	errs := make(chan error, callers)
	for range callers {
		go func() {
			errs <- recorder.Close(context.Background())
		}()
	}
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if got := sink.closeCalls.Load(); got != 1 {
		t.Fatalf("sink Close() calls = %d, want 1", got)
	}
}

type blockingSink struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSink) Write(context.Context, Event) error {
	s.once.Do(func() { close(s.started) })
	<-s.release
	return nil
}
func (*blockingSink) Close(context.Context) error { return nil }

type countingCloseSink struct{ closeCalls atomic.Int32 }

func (*countingCloseSink) Write(context.Context, Event) error { return nil }
func (s *countingCloseSink) Close(context.Context) error {
	s.closeCalls.Add(1)
	return nil
}

func BenchmarkCloneEvent(b *testing.B) {
	event := benchmarkEvent()
	b.ReportAllocs()
	for b.Loop() {
		_ = cloneEvent(event)
	}
}

func BenchmarkAsyncRecorder(b *testing.B) {
	var dropped atomic.Int64
	recorder := NewAsyncRecorder(benchmarkSink{}, DefaultQueueSize, func(result string) {
		if result == ResultDropped {
			dropped.Add(1)
		}
	})
	event := benchmarkEvent()
	b.ReportAllocs()
	for b.Loop() {
		recorder.Record(context.Background(), event)
	}
	if err := recorder.Close(context.Background()); err != nil {
		b.Fatal(err)
	}
	b.ReportMetric(float64(dropped.Load())/float64(max(b.N, 1))*100, "dropped_%")
}

func benchmarkEvent() Event {
	exitCode := 0
	return Event{
		Type:          "operation.end",
		Correlation:   Correlation{ConnectionID: "connection", OperationID: "operation"},
		Connection:    &Connection{SSHUsername: "default.nginx", RemoteAddress: "127.0.0.1:12345"},
		Actor:         &Actor{ID: "42", Name: "alice", Groups: []string{"developers"}, AuthenticationMethod: "publickey"},
		Target:        &Target{Kind: "kube", Namespace: "default", Name: "nginx", Container: "app"},
		Operation:     &Operation{Name: "session", Capability: "exec", Command: "id"},
		Authorization: &Authorization{Decision: "allow"},
		Outcome:       &Outcome{Result: "success", ExitCode: &exitCode},
		Fields:        map[string]string{"command": "id"},
	}
}

type benchmarkSink struct{}

func (benchmarkSink) Write(context.Context, Event) error { return nil }

func (benchmarkSink) Close(context.Context) error { return nil }
