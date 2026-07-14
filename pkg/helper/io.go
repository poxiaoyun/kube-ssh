package helper

import (
	"context"

	"k8s.io/streaming/pkg/httpstream"
)

type spdyStreamHalfCloser struct {
	httpstream.Stream
}

func (spdyStreamHalfCloser) CloseWrite() error { return nil }

type closeable interface {
	Close() error
}

func closeOnContext(ctx context.Context, c closeable) {
	<-ctx.Done()
	_ = c.Close()
}

func closeIfPossible(v any) error {
	if c, ok := v.(closeable); ok {
		return c.Close()
	}
	return nil
}
