package audit

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
)

func BenchmarkCloneEvent(b *testing.B) {
	event := benchmarkEvent()
	b.ReportAllocs()
	for range b.N {
		_ = cloneEvent(event)
	}
}

func BenchmarkStdoutSink(b *testing.B) {
	sink := NewStdoutSink(io.Discard)
	event := benchmarkEvent()
	b.ReportAllocs()
	for range b.N {
		if err := sink.Write(context.Background(), event); err != nil {
			b.Fatal(err)
		}
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
	b.ResetTimer()
	for range b.N {
		recorder.Record(context.Background(), event)
	}
	b.StopTimer()
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
func (benchmarkSink) Close(context.Context) error        { return nil }
