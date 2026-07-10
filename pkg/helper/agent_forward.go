package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

const agentForwardSocketName = "agent.sock"

type agentForwardManager struct {
	ctx    context.Context
	onIdle func(error)

	mu       sync.Mutex
	conn     httpstream.Connection
	listener net.Listener
	dir      string
	closed   bool
}

func newAgentForwardManager(ctx context.Context, onIdle func(error)) *agentForwardManager {
	return &agentForwardManager{ctx: ctx, onIdle: onIdle}
}

func (m *agentForwardManager) setConnection(conn httpstream.Connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conn = conn
}

func (m *agentForwardManager) handleListen(context.Context, json.RawMessage) (runtimeHandlerResult, error) {
	m.mu.Lock()
	if m.listener != nil && !m.closed {
		m.mu.Unlock()
		return runtimeHandlerResult{}, fmt.Errorf("agent-forward listener already exists")
	}
	dir, err := os.MkdirTemp("", "kube-ssh-agent-")
	if err != nil {
		m.mu.Unlock()
		return runtimeHandlerResult{}, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		m.mu.Unlock()
		return runtimeHandlerResult{}, err
	}
	socketPath := filepath.Join(dir, agentForwardSocketName)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		m.mu.Unlock()
		return runtimeHandlerResult{}, err
	}
	m.listener = listener
	m.dir = dir
	m.closed = false
	m.mu.Unlock()

	go m.run(listener)
	return runtimeHandlerResult{payload: AgentForwardListenResponse{SocketPath: socketPath}}, nil
}

func (m *agentForwardManager) handleStop(context.Context, json.RawMessage) (runtimeHandlerResult, error) {
	m.close()
	return runtimeHandlerResult{afterResponse: func() { m.onIdle(nil) }}, nil
}

func (m *agentForwardManager) run(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if !m.isClosed(listener) {
				m.onIdle(err)
			}
			return
		}
		go m.proxy(conn)
	}
}

func (m *agentForwardManager) proxy(conn net.Conn) {
	defer conn.Close()

	m.mu.Lock()
	spdyConn := m.conn
	m.mu.Unlock()
	if spdyConn == nil {
		return
	}

	stream, err := spdyConn.CreateStream(AgentForwardHeaders())
	if err != nil {
		return
	}
	defer func() {
		_ = stream.Close()
		spdyConn.RemoveStreams(stream)
	}()

	halfCloser, ok := conn.(ioproxy.HalfCloser)
	if !ok {
		return
	}
	_ = ioproxy.Proxy(m.ctx, halfCloser, StreamHalfCloser{Stream: stream})
}

func (m *agentForwardManager) close() {
	m.mu.Lock()
	listener := m.listener
	dir := m.dir
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
}

func (m *agentForwardManager) isClosed(listener net.Listener) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed || m.listener != listener
}
