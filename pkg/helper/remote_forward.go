package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

type remoteForwardManager struct {
	ctx    context.Context
	onIdle func(error)

	conn httpstream.Connection

	mu        sync.Mutex
	listeners map[string]*remoteForwardEntry
}

func newRemoteForwardManager(ctx context.Context, onIdle func(error)) *remoteForwardManager {
	return &remoteForwardManager{
		ctx:       ctx,
		onIdle:    onIdle,
		listeners: make(map[string]*remoteForwardEntry),
	}
}

func (m *remoteForwardManager) setConnection(conn httpstream.Connection) {
	m.conn = conn
}

func (m *remoteForwardManager) handleListen(_ context.Context, payload json.RawMessage) (runtimeHandlerResult, error) {
	request := RemoteForwardListenRequest{}
	if err := json.Unmarshal(payload, &request); err != nil {
		return runtimeHandlerResult{}, err
	}
	listener, err := newRemoteForwardListener(m.ctx, m.conn, request.Bind)
	if err != nil {
		return runtimeHandlerResult{}, err
	}
	entry := newRemoteForwardEntry(listener)

	m.mu.Lock()
	if _, exists := m.listeners[listener.actualBind]; exists {
		m.mu.Unlock()
		listener.stop()
		return runtimeHandlerResult{}, fmt.Errorf("remote-forward listener already exists")
	}
	m.listeners[listener.actualBind] = entry
	m.mu.Unlock()

	go m.run(entry)
	go m.stopOnConnectionClose(entry)
	go m.stopOnContextDone(entry)

	return runtimeHandlerResult{payload: RemoteForwardListenResponse{
		Bind:       request.Bind,
		ActualBind: listener.actualBind,
		ActualPort: listener.actualPort,
	}}, nil
}

func (m *remoteForwardManager) handleStop(_ context.Context, payload json.RawMessage) (runtimeHandlerResult, error) {
	request := RemoteForwardStopRequest{}
	if err := json.Unmarshal(payload, &request); err != nil {
		return runtimeHandlerResult{}, err
	}

	m.mu.Lock()
	entry := m.listeners[request.Bind]
	startStop := entry != nil && !entry.stopping
	if startStop {
		entry.stopping = true
		// Tell the accept loop that this close is RPC-driven. It must wait for
		// finishAfterResponse before it can mark the runtime idle.
		close(entry.stopRequested)
	}
	m.mu.Unlock()

	if entry == nil {
		return runtimeHandlerResult{afterResponse: func() { m.finishIfIdle(nil) }}, nil
	}
	if !startStop {
		return runtimeHandlerResult{}, nil
	}
	entry.listener.stop()
	return runtimeHandlerResult{afterResponse: func() { close(entry.finishAfterResponse) }}, nil
}

func (m *remoteForwardManager) run(entry *remoteForwardEntry) {
	err := entry.listener.run()
	if entry.stopWasRequested() {
		<-entry.finishAfterResponse
	}
	m.finishEntry(entry, err)
}

func (m *remoteForwardManager) stopOnConnectionClose(entry *remoteForwardEntry) {
	<-m.conn.CloseChan()
	entry.listener.stop()
}

func (m *remoteForwardManager) stopOnContextDone(entry *remoteForwardEntry) {
	<-m.ctx.Done()
	entry.listener.stop()
}

func (m *remoteForwardManager) finishEntry(entry *remoteForwardEntry, err error) {
	m.mu.Lock()
	if m.listeners[entry.listener.actualBind] == entry {
		delete(m.listeners, entry.listener.actualBind)
	}
	idle := len(m.listeners) == 0
	m.mu.Unlock()

	if err != nil {
		m.onIdle(err)
		return
	}
	if idle {
		m.onIdle(nil)
	}
}

func (m *remoteForwardManager) finishIfIdle(err error) {
	m.mu.Lock()
	idle := len(m.listeners) == 0
	m.mu.Unlock()
	if idle {
		m.onIdle(err)
	}
}

type remoteForwardEntry struct {
	listener *remoteForwardListener
	stopping bool
	// stopRequested is closed by the stop RPC path. The listener's run loop uses
	// it to distinguish an explicit cancel from context/connection shutdown.
	stopRequested chan struct{}
	// finishAfterResponse gates runtime idle completion until the stop RPC
	// response is fully sent back to the gateway.
	finishAfterResponse chan struct{}
}

func newRemoteForwardEntry(listener *remoteForwardListener) *remoteForwardEntry {
	return &remoteForwardEntry{
		listener:            listener,
		stopRequested:       make(chan struct{}),
		finishAfterResponse: make(chan struct{}),
	}
}

func (e *remoteForwardEntry) stopWasRequested() bool {
	select {
	case <-e.stopRequested:
		return true
	default:
		return false
	}
}

type remoteForwardListener struct {
	ctx           context.Context
	conn          httpstream.Connection
	listener      net.Listener
	requestedBind string
	actualBind    string
	actualPort    uint32

	active   sync.WaitGroup
	stopOnce sync.Once
}

func newRemoteForwardListener(ctx context.Context, conn httpstream.Connection, bind string) (*remoteForwardListener, error) {
	if bind == "" {
		return nil, fmt.Errorf("bind is required")
	}
	host, portText, err := net.SplitHostPort(bind)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 32)
	if err != nil {
		return nil, err
	}
	if port > 65535 {
		return nil, fmt.Errorf("port must be between 0 and 65535")
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(host, portText))
	if err != nil {
		return nil, err
	}
	actualBind := listener.Addr().String()
	_, actualPortText, err := net.SplitHostPort(actualBind)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	actualPort, err := strconv.ParseUint(actualPortText, 10, 32)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	return &remoteForwardListener{
		ctx:           ctx,
		conn:          conn,
		listener:      listener,
		requestedBind: bind,
		actualBind:    actualBind,
		actualPort:    uint32(actualPort),
	}, nil
}

func (l *remoteForwardListener) run() error {
	defer l.listener.Close()
	for {
		tcpConn, err := l.listener.Accept()
		if err != nil {
			l.active.Wait()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-l.conn.CloseChan():
				return nil
			case <-l.ctx.Done():
				return l.ctx.Err()
			default:
				return err
			}
		}
		l.active.Add(1)
		go func() {
			defer l.active.Done()
			proxyRemoteForwardConnection(l.ctx, l.conn, l.actualBind, l.requestedBind, tcpConn)
		}()
	}
}

func (l *remoteForwardListener) stop() {
	l.stopOnce.Do(func() {
		_ = l.listener.Close()
	})
}

func proxyRemoteForwardConnection(ctx context.Context, spdyConn httpstream.Connection, bind, requestedBind string, tcpConn net.Conn) {
	defer tcpConn.Close()

	originHost, originPortText, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
	originPort, _ := strconv.ParseUint(originPortText, 10, 32)
	stream, err := spdyConn.CreateStream(RemoteForwardHeaders(bind, requestedBind, originHost, strconv.FormatUint(originPort, 10)))
	if err != nil {
		return
	}
	defer spdyConn.RemoveStreams(stream)
	defer stream.Close()

	_ = ioproxy.Proxy(ctx, tcpHalfCloser{Conn: tcpConn}, StreamHalfCloser{Stream: stream})
}
