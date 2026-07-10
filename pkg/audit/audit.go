package audit

import "context"

type Event struct {
	Type   string            `json:"type"`
	Fields map[string]string `json:"fields,omitempty"`
}

type Recorder interface {
	Record(ctx context.Context, event Event)
}
