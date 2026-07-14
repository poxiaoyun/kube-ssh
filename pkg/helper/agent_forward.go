package helper

import (
	"bytes"
	"context"
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

const AgentForwardSocketName = "agent.sock"

const (
	MethodAgentListen         = "agent-forward.listen"
	MethodAgentStop           = "agent-forward.stop"
	StreamTypeAgentConnection = "agent-forward.connection"
)

type AgentListenResponse struct {
	SocketPath string `json:"socketPath"`
}

func AgentConnectionHeaders() http.Header {
	headers := http.Header{}
	headers.Set(spdyrpc.StreamTypeHeader, StreamTypeAgentConnection)
	return headers
}

// AgentForwardService provides the helper side of agent forwarding.
type AgentForwardService struct {
	connection *spdyrpc.Connection

	mu       sync.Mutex
	listener net.Listener
	dir      string
	closed   bool
}

// NewAgentForwardService creates an agent-forwarding service on connection.
func NewAgentForwardService(connection *spdyrpc.Connection) *AgentForwardService {
	return &AgentForwardService{connection: connection}
}

// HandleListen handles an agent-forward listen RPC.
func (m *AgentForwardService) HandleListen(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
	if err := decodeEmptyPayload(m.connection.Codec(), payload); err != nil {
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
	socketPath := filepath.Join(dir, AgentForwardSocketName)
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
	return AgentListenResponse{SocketPath: socketPath}, nil
}

// HandleStop handles an agent-forward stop RPC.
func (m *AgentForwardService) HandleStop(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
	if err := decodeEmptyPayload(m.connection.Codec(), payload); err != nil {
		return nil, err
	}
	m.close()
	return nil, nil
}

func (m *AgentForwardService) run(ctx context.Context, listener net.Listener) error {
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

func (m *AgentForwardService) proxy(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stream, err := m.connection.CreateStream(AgentConnectionHeaders())
	if err != nil {
		return
	}
	defer stream.Close()
	halfCloser, ok := conn.(ioproxy.HalfCloser)
	if !ok {
		return
	}
	_ = ioproxy.Proxy(ctx, halfCloser, spdyStreamHalfCloser{Stream: stream})
}

func decodeEmptyPayload(codec spdyrpc.Codec, payload spdyrpc.RawMessage) error {
	if len(payload) == 0 {
		return nil
	}
	return codec.Decode(bytes.NewReader(payload), &struct{}{})
}

func (m *AgentForwardService) close() bool {
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

func (m *AgentForwardService) closeIfMatch(listener net.Listener) bool {
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

func (m *AgentForwardService) isClosed(listener net.Listener) bool {
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

	response := AgentListenResponse{}
	if err := c.helper.Call(ctx, MethodAgentListen, nil, &response); err != nil {
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
		c.helper.closeStream(stream)
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

func (f *AgentListener) SocketPath() string {
	return f.socketPath
}

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

func (f *AgentListener) Cancel(ctx context.Context) error {
	f.cancelOnce.Do(func() {
		f.client.removeIfMatch(f)
		f.closeLocal(context.Canceled)
		f.cancelErr = f.client.helper.Call(ctx, MethodAgentStop, nil, nil)
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
		f.client.helper.closeStream(stream)
		return
	}
	select {
	case <-f.client.helper.closed:
		f.client.helper.closeStream(stream)
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
		f.client.helper.closeStream(stream)
	}
	f.incoming = nil
	f.cond.Broadcast()
}
