package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	if err := json.NewDecoder(&output).Decode(&got); err != nil {
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

func TestChainSinkContinuesAfterError(t *testing.T) {
	good := &collectSink{}
	chain := ChainSink{errorSink{}, good}
	if err := chain.Write(context.Background(), Event{Type: "test"}); err == nil {
		t.Fatal("expected joined sink error")
	}
	if len(good.events) != 1 {
		t.Fatalf("successful sink writes = %d", len(good.events))
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

type errorSink struct{}

func (errorSink) Write(context.Context, Event) error { return errors.New("failed") }
func (errorSink) Close(context.Context) error        { return nil }

type collectSink struct{ events []Event }

func (s *collectSink) Write(_ context.Context, event Event) error {
	s.events = append(s.events, event)
	return nil
}
func (*collectSink) Close(context.Context) error { return nil }

type countingCloseSink struct{ closeCalls atomic.Int32 }

func (*countingCloseSink) Write(context.Context, Event) error { return nil }
func (s *countingCloseSink) Close(context.Context) error {
	s.closeCalls.Add(1)
	return nil
}
