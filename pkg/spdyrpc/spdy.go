package spdyrpc

import (
	"net/http"
	"time"

	"github.com/moby/spdystream"
	"k8s.io/streaming/pkg/httpstream"
)

const defaultCreateStreamResponseTimeout = 30 * time.Second

// ConnectionOptions configures an RPC connection.
type ConnectionOptions struct {
	// Codec encodes RPC envelopes and payloads. Nil uses JSONCodec.
	Codec Codec

	// CreateStreamResponseTimeout limits how long a locally created stream waits
	// for the peer to accept or reject it. Zero uses the default timeout.
	CreateStreamResponseTimeout time.Duration
}

// CreateStream creates a stream and waits for the peer reply.
func (s *Connection) CreateStream(headers http.Header) (httpstream.Stream, error) {
	stream, err := s.spdyConn.CreateStream(headers, nil, false)
	if err != nil {
		return nil, err
	}
	if err := stream.WaitTimeout(s.createStreamResponseTimeout); err != nil {
		return nil, err
	}
	return stream, nil
}

func (s *Connection) newSPDYStream(stream *spdystream.Stream) {
	streamType := stream.Headers().Get(StreamTypeHeader)
	switch streamType {
	case StreamTypeControl:
		s.handleRPCStream(stream)
	default:
		s.handleDataStream(streamType, stream)
	}
}

func (s *Connection) handleRPCStream(stream *spdystream.Stream) {
	if !s.beginWork() {
		_ = stream.Reset()
		return
	}
	if err := stream.SendReply(http.Header{}, false); err != nil {
		_ = stream.Reset()
		s.work.Done()
		return
	}
	go s.serveRPC(stream)
}

func (s *Connection) handleDataStream(streamType string, stream *spdystream.Stream) {
	s.streamMu.RLock()
	handler := s.streamHandlers[streamType]
	s.streamMu.RUnlock()
	if handler == nil {
		_ = stream.Reset()
		return
	}
	if err := stream.SendReply(http.Header{}, false); err != nil {
		_ = stream.Reset()
		return
	}
	if err := handler(stream); err != nil {
		_ = stream.Reset()
	}
}
