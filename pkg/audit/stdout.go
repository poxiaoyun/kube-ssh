package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
)

type Sink interface {
	Write(context.Context, Event) error
	Close(context.Context) error
}

type StdoutSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewStdoutSink(w io.Writer) *StdoutSink {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutSink{w: w}
}

func (r *StdoutSink) Write(_ context.Context, event Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.NewEncoder(r.w).Encode(event)
}

func (*StdoutSink) Close(context.Context) error { return nil }

// StdoutRecorder is the synchronous compatibility recorder used by embedders.
type StdoutRecorder struct{ sink *StdoutSink }

func NewStdoutRecorder() *StdoutRecorder { return &StdoutRecorder{sink: NewStdoutSink(nil)} }

func (r *StdoutRecorder) Record(ctx context.Context, event Event) {
	prepare(&event)
	_ = r.sink.Write(ctx, event)
}
