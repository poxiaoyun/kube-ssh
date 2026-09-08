package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

const agentForwardSocketName = "agent.sock"

const (
	methodAgentListen         = "agent-forward.listen"
	methodAgentStop           = "agent-forward.stop"
	streamTypeAgentConnection = "agent-forward.connection"
)

type agentListenResponse struct {
	SocketPath string `json:"socketPath"`
}

func agentConnectionHeaders() http.Header {
	headers := http.Header{}
	headers.Set(spdyrpc.StreamTypeHeader, streamTypeAgentConnection)
	return headers
}

// agentForwardService provides the helper side of agent forwarding.
type agentForwardService struct {
	connection *spdyrpc.Connection

	mu       sync.Mutex
	listener net.Listener
	dir      string
	closed   bool
}

func newAgentForwardService(connection *spdyrpc.Connection) *agentForwardService {
	return &agentForwardService{connection: connection}
}

// handleListen handles an agent-forward listen RPC.
func (m *agentForwardService) handleListen(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
	if err := decodeEmptyPayload(payload); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if m.listener != nil && !m.closed {
		m.mu.Unlock()
		return nil, fmt.Errorf("agent-forward listener already exists")
	}
	dir, err := os.MkdirTemp("", "kube-ssh-agent-")
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		m.mu.Unlock()
		return nil, err
	}
	socketPath := filepath.Join(dir, agentForwardSocketName)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		m.mu.Unlock()
		return nil, err
	}
	m.listener = listener
	m.dir = dir
	m.closed = false
	m.mu.Unlock()
	if err := m.connection.Go(func(ctx context.Context) error { return m.run(ctx, listener) }); err != nil {
		m.closeIfMatch(listener)
		return nil, err
	}
	return agentListenResponse{SocketPath: socketPath}, nil
}

// handleStop handles an agent-forward stop RPC.
func (m *agentForwardService) handleStop(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
	if err := decodeEmptyPayload(payload); err != nil {
		return nil, err
	}
	m.close()
	return nil, nil
}

func (m *agentForwardService) run(ctx context.Context, listener net.Listener) error {
	stopOnContext := context.AfterFunc(ctx, func() { m.closeIfMatch(listener) })
	defer stopOnContext()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !m.isClosed(listener) {
				m.closeIfMatch(listener)
				if !errors.Is(err, net.ErrClosed) {
					return err
				}
			}
			return nil
		}
		if err := m.connection.Go(func(ctx context.Context) error {
			m.proxy(ctx, conn)
			return nil
		}); err != nil {
			_ = conn.Close()
			return nil
		}
	}
}

func (m *agentForwardService) proxy(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stream, err := m.connection.CreateStream(agentConnectionHeaders())
	if err != nil {
		return
	}
	defer stream.Reset()
	_ = ioproxy.Proxy(ctx, conn.(*net.UnixConn), spdyStreamHalfCloser{Stream: stream})
}

func decodeEmptyPayload(payload spdyrpc.RawMessage) error {
	if len(payload) == 0 {
		return nil
	}
	return json.NewDecoder(bytes.NewReader(payload)).
		Decode(&struct{}{})
}

func (m *agentForwardService) close() bool {
	m.mu.Lock()
	listener := m.listener
	dir := m.dir
	active := listener != nil && !m.closed
	m.listener = nil
	m.dir = ""
	m.closed = true
	m.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	return active
}

func (m *agentForwardService) closeIfMatch(listener net.Listener) bool {
	m.mu.Lock()
	if m.listener != listener || m.closed {
		m.mu.Unlock()
		return false
	}
	dir := m.dir
	m.listener = nil
	m.dir = ""
	m.closed = true
	m.mu.Unlock()
	_ = listener.Close()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	return true
}

func (m *agentForwardService) isClosed(listener net.Listener) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed || m.listener != listener
}

// agentForwardClient owns the client side of the single agent-forward
// listener and dispatches server-initiated agent streams to it.
type agentForwardClient struct {
	helper *Client

	mu      sync.Mutex
	forward *AgentListener
}

// AgentListener represents the active agent-forward listener in the helper.
type AgentListener struct {
	client     *agentForwardClient
	socketPath string

	mu       sync.Mutex
	cond     *sync.Cond
	incoming []httpstream.Stream
	closed   bool
	closeErr error

	cancelOnce sync.Once
	cancelErr  error
}

func newAgentForwardClient(helper *Client) *agentForwardClient {
	return &agentForwardClient{helper: helper}
}

func (c *agentForwardClient) Listen(ctx context.Context) (*AgentListener, error) {
	forward := newAgentListener(c)
	c.mu.Lock()
	if c.forward != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("agent-forward listener already exists")
	}
	c.forward = forward
	c.mu.Unlock()

	response := agentListenResponse{}
	if err := c.helper.call(ctx, methodAgentListen, nil, &response); err != nil {
		c.removeIfMatch(forward)
		forward.closeLocal(err)
		return nil, err
	}
	forward.socketPath = response.SocketPath
	return forward, nil
}

func newAgentListener(client *agentForwardClient) *AgentListener {
	forward := &AgentListener{client: client}
	forward.cond = sync.NewCond(&forward.mu)
	return forward
}

func (c *agentForwardClient) dispatch(stream httpstream.Stream) {
	c.mu.Lock()
	forward := c.forward
	c.mu.Unlock()
	if forward == nil {
		_ = stream.Reset()
		return
	}
	forward.deliver(stream)
}

func (c *agentForwardClient) removeIfMatch(forward *AgentListener) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forward == forward {
		c.forward = nil
	}
}

func (c *agentForwardClient) close() {
	c.mu.Lock()
	forward := c.forward
	c.forward = nil
	c.mu.Unlock()
	if forward != nil {
		forward.closeLocal(ErrClientClosed)
	}
}

// SocketPath returns the target-side Unix socket for SSH_AUTH_SOCK.
func (f *AgentListener) SocketPath() string {
	return f.socketPath
}

// Accept waits for the next agent connection, listener closure, or cancellation.
// The caller owns the returned stream.
func (f *AgentListener) Accept(ctx context.Context) (ioproxy.HalfCloser, error) {
	stopWakeup := context.AfterFunc(ctx, func() {
		f.mu.Lock()
		f.cond.Broadcast()
		f.mu.Unlock()
	})
	defer stopWakeup()

	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		if len(f.incoming) > 0 {
			stream := f.incoming[0]
			copy(f.incoming, f.incoming[1:])
			f.incoming = f.incoming[:len(f.incoming)-1]
			return spdyStreamHalfCloser{Stream: stream}, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.closed && f.closeErr != nil {
			return nil, f.closeErr
		}
		select {
		case <-f.client.helper.closed:
			return nil, ErrClientClosed
		default:
		}
		if f.closed {
			return nil, context.Canceled
		}
		f.cond.Wait()
	}
}

// Cancel stops the agent socket and pending accepts without closing accepted streams.
// It is idempotent; closing the Client also releases the listener.
func (f *AgentListener) Cancel(ctx context.Context) error {
	f.cancelOnce.Do(func() {
		f.client.removeIfMatch(f)
		f.closeLocal(context.Canceled)
		f.cancelErr = f.client.helper.call(ctx, methodAgentStop, nil, nil)
		if errors.Is(f.cancelErr, ErrClientClosed) {
			f.cancelErr = nil
		}
	})
	return f.cancelErr
}

func (f *AgentListener) deliver(stream httpstream.Stream) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		_ = stream.Reset()
		return
	}
	select {
	case <-f.client.helper.closed:
		_ = stream.Reset()
		return
	default:
	}
	f.incoming = append(f.incoming, stream)
	f.cond.Signal()
}

func (f *AgentListener) closeLocal(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.closeErr = err
	for _, stream := range f.incoming {
		_ = stream.Reset()
	}
	f.incoming = nil
	f.cond.Broadcast()
}
