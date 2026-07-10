package audit

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type StdoutRecorder struct {
	mu sync.Mutex
}

func NewStdoutRecorder() *StdoutRecorder {
	return &StdoutRecorder{}
}

func (r *StdoutRecorder) Record(ctx context.Context, event Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	record := struct {
		Time string `json:"time"`
		Event
	}{
		Time:  time.Now().UTC().Format(time.RFC3339Nano),
		Event: event,
	}
	_ = json.NewEncoder(os.Stdout).Encode(record)
}
