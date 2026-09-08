// Package spdyrpc provides bidirectional JSON RPC and streams over SPDY.
package spdyrpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/moby/spdystream"
	"k8s.io/streaming/pkg/httpstream"
)

var (
	ErrConnectionClosed  = errors.New("connection closed")
	ErrConnectionStarted = errors.New("connection already started")
)

// Handler handles one RPC method. The returned value is encoded into the
// response payload as JSON. Handler errors are returned to
// the caller as RPC errors.
type Handler interface {
	// Handle processes one decoded method payload and must return when ctx is
	// canceled so connection shutdown can wait for all handlers.
	Handle(ctx context.Context, payload RawMessage) (any, error)
}

// RawMessage contains an encoded RPC payload.
type RawMessage = json.RawMessage

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(context.Context, RawMessage) (any, error)

// Handle delegates the RPC method payload to f.
func (f HandlerFunc) Handle(ctx context.Context, payload RawMessage) (any, error) {
	return f(ctx, payload)
}

// StreamHandler handles a peer-initiated stream after its acceptance reply has
// been sent successfully. Returning an error resets the stream.
type StreamHandler func(httpstream.Stream) error

type connectionState uint8

const (
	connectionNew connectionState = iota
	connectionServing
	connectionClosing
	connectionClosed
)

// Connection is a bidirectional RPC and stream endpoint over SPDY.
type Connection struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	transport                   net.Conn
	spdyConn                    *spdystream.Connection
	createStreamResponseTimeout time.Duration

	mu       sync.Mutex
	state    connectionState
	handlers map[string]Handler
	work     sync.WaitGroup
	fatal    chan error

	streamMu       sync.RWMutex
	streamHandlers map[string]StreamHandler
}

type connectionCallResult struct {
	response rpcResponse
	err      error
}

// NewClientConnection creates a connection using the SPDY client role and
// takes ownership of transport.
func NewClientConnection(parent context.Context, transport net.Conn) (*Connection, error) {
	return newConnection(parent, transport, false)
}

// NewServerConnection creates a connection using the SPDY server role and
// takes ownership of transport.
func NewServerConnection(parent context.Context, transport net.Conn) (*Connection, error) {
	return newConnection(parent, transport, true)
}

func newConnection(parent context.Context, transport net.Conn, serverRole bool) (*Connection, error) {
	ctx, cancel := context.WithCancel(parent)
	spdyConn, err := spdystream.NewConnection(transport, serverRole)
	if err != nil {
		cancel()
		_ = transport.Close()
		return nil, err
	}
	return &Connection{
		ctx:                         ctx,
		cancel:                      cancel,
		transport:                   transport,
		spdyConn:                    spdyConn,
		createStreamResponseTimeout: defaultCreateStreamResponseTimeout,
		handlers:                    make(map[string]Handler),
		streamHandlers:              make(map[string]StreamHandler),
		fatal:                       make(chan error, 1),
	}, nil
}

// Register associates method with handler. Registrations are immutable once
// Serve starts.
func (s *Connection) Register(method string, handler Handler) error {
	if method == "" {
		return fmt.Errorf("RPC method is required")
	}
	if handler == nil {
		return fmt.Errorf("RPC handler for %q is nil", method)
	}
	if handlerFunc, ok := handler.(HandlerFunc); ok && handlerFunc == nil {
		return fmt.Errorf("RPC handler for %q is nil", method)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != connectionNew {
		return ErrConnectionStarted
	}
	if _, exists := s.handlers[method]; exists {
		return fmt.Errorf("RPC handler for %q is already registered", method)
	}
	s.handlers[method] = handler
	return nil
}

// RegisterStreamHandler registers a handler for peer-initiated streams.
func (s *Connection) RegisterStreamHandler(streamType string, handler StreamHandler) error {
	if streamType == "" || streamType == StreamTypeControl {
		return fmt.Errorf("invalid stream type %q", streamType)
	}
	if handler == nil {
		return fmt.Errorf("stream handler for %q is nil", streamType)
	}
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	s.mu.Lock()
	closed := s.state == connectionClosing || s.state == connectionClosed
	s.mu.Unlock()
	if closed {
		return ErrConnectionClosed
	}
	if _, exists := s.streamHandlers[streamType]; exists {
		return fmt.Errorf("stream handler for %q is already registered", streamType)
	}
	s.streamHandlers[streamType] = handler
	return nil
}

// Call invokes an RPC method registered by the peer.
func (s *Connection) Call(ctx context.Context, method string, in any, out any) error {
	if method == "" {
		return fmt.Errorf("RPC method is required")
	}
	headers := http.Header{}
	headers.Set(StreamTypeHeader, StreamTypeControl)
	stream, err := s.CreateStream(headers)
	if err != nil {
		return err
	}
	defer stream.Close()

	request, err := newRPCRequest(method, in)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stream).
		Encode(request); err != nil {
		return err
	}

	result := make(chan connectionCallResult, 1)
	go func() {
		response := rpcResponse{}
		err := json.NewDecoder(stream).
			Decode(&response)
		result <- connectionCallResult{response: response, err: err}
	}()
	select {
	case got := <-result:
		if got.err != nil {
			return got.err
		}
		return decodeRPCResponse(method, got.response, out)
	case <-ctx.Done():
		_ = stream.Reset()
		return ctx.Err()
	case <-s.ctx.Done():
		_ = stream.Reset()
		return ErrConnectionClosed
	}
}

// Serve accepts RPC streams until the parent context, transport, or a fatal
// handler error stops the connection. It waits for all registered work to finish.
func (s *Connection) Serve() error {
	s.mu.Lock()
	if s.state != connectionNew {
		s.mu.Unlock()
		return ErrConnectionStarted
	}
	s.state = connectionServing
	s.mu.Unlock()

	go s.spdyConn.Serve(s.newSPDYStream)

	var serveErr error
	select {
	case <-s.ctx.Done():
		serveErr = s.ctx.Err()
	case <-s.spdyConn.CloseChan():
		serveErr = s.ctx.Err()
	case serveErr = <-s.fatal:
	}

	s.shutdown()
	s.work.Wait()
	s.mu.Lock()
	s.state = connectionClosed
	s.mu.Unlock()
	return serveErr
}

// Go starts work owned by the connection. Serve waits for run to return during
// shutdown. A non-nil run error stops the connection. run must stop when its
// context is canceled.
func (s *Connection) Go(run func(context.Context) error) error {
	if run == nil {
		return fmt.Errorf("connection work function is nil")
	}
	if !s.beginWork() {
		return ErrConnectionClosed
	}
	go func() {
		defer s.work.Done()
		if err := run(s.ctx); err != nil {
			s.fail(err)
		}
	}()
	return nil
}

func (s *Connection) fail(err error) {
	select {
	case s.fatal <- err:
	default:
	}
}

// Close requests connection shutdown. Serve waits for registered work to
// finish before returning.
func (s *Connection) Close() error {
	s.shutdown()
	return nil
}

// Closed is closed when the connection context is canceled.
func (s *Connection) Closed() <-chan struct{} {
	return s.ctx.Done()
}

func (s *Connection) beginWork() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != connectionServing {
		return false
	}
	s.work.Add(1)
	return true
}

func (s *Connection) shutdown() {
	s.mu.Lock()
	if s.state == connectionClosing || s.state == connectionClosed {
		s.mu.Unlock()
		return
	}
	s.state = connectionClosing
	s.mu.Unlock()
	s.cancel()
	// Shutdown cancels active work, including RPC readers waiting for a peer.
	// Closing the transport lets SPDY release them without waiting for peer FIN.
	_ = s.transport.Close()
}

func (s *Connection) serveRPC(stream httpstream.Stream) {
	defer s.work.Done()
	defer stream.Close()

	request := rpcRequest{}
	if err := json.NewDecoder(stream).
		Decode(&request); err != nil {
		if err != io.EOF {
			_ = json.NewEncoder(stream).
				Encode(newRPCErrorResponse(err))
		}
		return
	}

	handler := s.handlers[request.Method]
	if handler == nil {
		_ = json.NewEncoder(stream).
			Encode(newRPCErrorResponse(fmt.Errorf("unsupported RPC method %q", request.Method)))
		return
	}
	payload, err := handler.Handle(s.ctx, request.Payload)
	if err != nil {
		_ = json.NewEncoder(stream).
			Encode(newRPCErrorResponse(err))
		return
	}
	response, err := newRPCResponse(payload)
	if err != nil {
		response = newRPCErrorResponse(err)
	}
	_ = json.NewEncoder(stream).
		Encode(response)
}

func newRPCResponse(payload any) (rpcResponse, error) {
	response := rpcResponse{OK: true}
	if payload == nil {
		return response, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return rpcResponse{}, err
	}
	response.Payload = data
	return response, nil
}

func newRPCErrorResponse(err error) rpcResponse {
	return rpcResponse{OK: false, Error: err.Error()}
}
