package audit

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultQueueSize = 4096

type ResultObserver func(result string)

const (
	ResultWritten   = "written"
	ResultDropped   = "dropped"
	ResultSinkError = "sink_error"
)

// AsyncRecorder decouples SSH request handling from audit I/O. Queue overflow
// drops the event and reports it through the observer; it never denies access.
type AsyncRecorder struct {
	sink           Sink
	queue          chan Event
	observer       ResultObserver
	closed         atomic.Bool
	done           chan struct{}
	queueCloseOnce sync.Once
	sinkCloseOnce  sync.Once
	sinkCloseDone  chan struct{}
	sinkCloseErr   error
	mu             sync.RWMutex
}

func NewAsyncRecorder(sink Sink, queueSize int, observer ResultObserver) *AsyncRecorder {
	if queueSize <= 0 {
		queueSize = DefaultQueueSize
	}
	r := &AsyncRecorder{
		sink:          sink,
		queue:         make(chan Event, queueSize),
		observer:      observer,
		done:          make(chan struct{}),
		sinkCloseDone: make(chan struct{}),
	}
	go r.run()
	return r
}

func (r *AsyncRecorder) Record(_ context.Context, event Event) {
	if r == nil || r.closed.Load() {
		return
	}
	prepare(&event)
	event = cloneEvent(event)
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed.Load() {
		return
	}
	select {
	case r.queue <- event:
	default:
		r.observe(ResultDropped)
	}
}

func (r *AsyncRecorder) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.queueCloseOnce.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.closed.Store(true)
		close(r.queue)
	})
	select {
	case <-r.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	r.sinkCloseOnce.Do(func() {
		go func() {
			r.sinkCloseErr = r.sink.Close(ctx)
			close(r.sinkCloseDone)
		}()
	})
	select {
	case <-r.sinkCloseDone:
		return r.sinkCloseErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *AsyncRecorder) run() {
	defer close(r.done)
	for event := range r.queue {
		if err := r.sink.Write(context.Background(), event); err != nil {
			r.observe(ResultSinkError)
			continue
		}
		r.observe(ResultWritten)
	}
}

func (r *AsyncRecorder) observe(result string) {
	if r.observer != nil {
		r.observer(result)
	}
}

type ChainSink []Sink

func (s ChainSink) Write(ctx context.Context, event Event) error {
	var errs []error
	for _, sink := range s {
		if sink != nil {
			errs = append(errs, sink.Write(ctx, cloneEvent(event)))
		}
	}
	return errors.Join(errs...)
}

func (s ChainSink) Close(ctx context.Context) error {
	var errs []error
	for _, sink := range s {
		if sink != nil {
			errs = append(errs, sink.Close(ctx))
		}
	}
	return errors.Join(errs...)
}

func prepare(event *Event) {
	if event.SchemaVersion == "" {
		event.SchemaVersion = SchemaVersion
	}
	if event.ID == "" {
		event.ID = newID()
	}
	if event.Time.IsZero() {
		event.Time = timeNow()
	}
}

var timeNow = func() time.Time { return time.Now().UTC() }

func cloneEvent(event Event) Event {
	if event.Fields != nil {
		event.Fields = maps.Clone(event.Fields)
	}
	if event.Actor != nil {
		actor := *event.Actor
		actor.Groups = slices.Clone(actor.Groups)
		event.Actor = &actor
	}
	if event.Connection != nil {
		value := *event.Connection
		event.Connection = &value
	}
	if event.Access != nil {
		value := *event.Access
		event.Access = &value
	}
	if event.Target != nil {
		value := *event.Target
		event.Target = &value
	}
	if event.Operation != nil {
		value := *event.Operation
		event.Operation = &value
	}
	if event.Authorization != nil {
		value := *event.Authorization
		event.Authorization = &value
	}
	if event.Outcome != nil {
		value := *event.Outcome
		if value.ExitCode != nil {
			exitCode := *value.ExitCode
			value.ExitCode = &exitCode
		}
		event.Outcome = &value
	}
	return event
}
