package helper

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/moby/spdystream"
	"k8s.io/streaming/pkg/httpstream"
)

const createStreamResponseTimeout = 30 * time.Second

type clientSPDYConnection struct {
	conn             *spdystream.Connection
	newStreamHandler httpstream.NewStreamHandler

	// Keep the same stream registry semantics as k8s httpstream/spdy:
	// Close resets all registered streams, while RemoveStreams only removes
	// streams that have already been fully handled by the caller.
	streamLock sync.Mutex
	streams    map[uint32]httpstream.Stream
}

func newClientSPDYConnection(conn net.Conn, handler httpstream.NewStreamHandler) (*clientSPDYConnection, error) {
	spdyConn, err := spdystream.NewConnection(conn, false)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if handler == nil {
		handler = httpstream.NoOpNewStreamHandler
	}
	c := &clientSPDYConnection{
		conn:             spdyConn,
		newStreamHandler: handler,
		streams:          make(map[uint32]httpstream.Stream),
	}
	return c, nil
}

func (c *clientSPDYConnection) Serve() {
	c.conn.Serve(c.newStream)
}

func (c *clientSPDYConnection) CreateStream(headers http.Header) (httpstream.Stream, error) {
	stream, err := c.conn.CreateStream(headers, nil, false)
	if err != nil {
		return nil, err
	}
	if err := stream.WaitTimeout(createStreamResponseTimeout); err != nil {
		return nil, err
	}
	c.registerStream(stream)
	return stream, nil
}

func (c *clientSPDYConnection) Close() error {
	// Match k8s httpstream/spdy.Close: reset every active stream before closing
	// the underlying SPDY connection so shutdown does not wait on graceful stream
	// teardown.
	c.streamLock.Lock()
	for _, stream := range c.streams {
		stream.Reset()
	}
	c.streams = make(map[uint32]httpstream.Stream)
	c.streamLock.Unlock()
	return c.conn.Close()
}

func (c *clientSPDYConnection) CloseChan() <-chan bool {
	return c.conn.CloseChan()
}

func (c *clientSPDYConnection) SetIdleTimeout(timeout time.Duration) {
	c.conn.SetIdleTimeout(timeout)
}

func (c *clientSPDYConnection) RemoveStreams(streams ...httpstream.Stream) {
	// Match k8s httpstream/spdy.RemoveStreams: this only updates the registry.
	// The caller is responsible for closing or resetting the stream first.
	c.streamLock.Lock()
	defer c.streamLock.Unlock()
	for _, stream := range streams {
		if stream != nil {
			delete(c.streams, stream.Identifier())
		}
	}
}

func (c *clientSPDYConnection) registerStream(stream httpstream.Stream) {
	c.streamLock.Lock()
	c.streams[stream.Identifier()] = stream
	c.streamLock.Unlock()
}

func (c *clientSPDYConnection) newStream(stream *spdystream.Stream) {
	replySent := make(chan struct{})
	if err := c.newStreamHandler(stream, replySent); err != nil {
		stream.Reset()
		return
	}
	c.registerStream(stream)
	stream.SendReply(http.Header{}, false)
	close(replySent)
}
