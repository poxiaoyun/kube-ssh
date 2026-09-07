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
	for range b.N {
		if err := sink.Write(context.Background(), event); err != nil {
			b.Fatal(err)
		}
	}
}
