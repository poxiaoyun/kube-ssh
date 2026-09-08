package audit

import (
	"context"
	"io"
	"testing"
)

func BenchmarkStdoutSink(b *testing.B) {
	sink := NewStdoutSink(io.Discard)
	event := benchmarkEvent()
	b.ReportAllocs()
	for b.Loop() {
		if err := sink.Write(context.Background(), event); err != nil {
			b.Fatal(err)
		}
	}
}
