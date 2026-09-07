package audit

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
)

type Sink interface {
	// Write delivers one prepared audit event.
	Write(ctx context.Context, event Event) error
	// Close flushes and releases the sink.
	Close(ctx context.Context) error
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
