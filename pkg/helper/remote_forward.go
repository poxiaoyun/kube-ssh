package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

const (
	MethodRemoteListen         = "remote-forward.listen"
	MethodRemoteStop           = "remote-forward.stop"
	StreamTypeRemoteConnection = "remote-forward.connection"
)

const (
	remoteBindHeader          = "remoteForwardBind"
	requestedRemoteBindHeader = "remoteForwardRequestedBind"
	originHostHeader          = "originHost"
	originPortHeader          = "originPort"
)

type RemoteListenRequest struct {
	Bind string `json:"bind"`
}

type RemoteListenResponse struct {
	Bind       string `json:"bind"`
	ActualBind string `json:"actualBind"`
	ActualPort uint32 `json:"actualPort"`
}

type RemoteStopRequest struct {
	Bind string `json:"bind"`
}

type ConnectionInfo struct {
	Bind          string
	RequestedBind string
	OriginHost    string
	OriginPort    uint32
}

func RemoteConnectionHeaders(bind, requestedBind, originHost, originPort string) http.Header {
	headers := http.Header{}
	headers.Set(spdyrpc.StreamTypeHeader, StreamTypeRemoteConnection)
	headers.Set(remoteBindHeader, bind)
	headers.Set(requestedRemoteBindHeader, requestedBind)
	headers.Set(originHostHeader, originHost)
	headers.Set(originPortHeader, originPort)
	return headers
}

func RemoteConnectionHeaderValues(headers http.Header) (bind, requestedBind, originHost, originPort string) {
	return headers.Get(remoteBindHeader), headers.Get(requestedRemoteBindHeader), headers.Get(originHostHeader), headers.Get(originPortHeader)
}

// RemoteForwardService provides the helper side of remote TCP forwarding.
type RemoteForwardService struct {
	connection *spdyrpc.Connection

	mu        sync.Mutex
	listeners map[string]*remoteTCPListener
}

// NewRemoteForwardService creates a remote-forwarding service on connection.
func NewRemoteForwardService(connection *spdyrpc.Connection) *RemoteForwardService {
	return &RemoteForwardService{
		connection: connection,
		listeners:  make(map[string]*remoteTCPListener),
	}
}

// HandleListen handles a remote-forward listen RPC.
func (m *RemoteForwardService) HandleListen(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
	request := RemoteListenRequest{}
	if err := m.connection.Codec().Decode(bytes.NewReader(payload), &request); err != nil {
		return nil, err
	}
	listener, err := newRemoteTCPListener(m.connection, request.Bind)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.listeners[listener.actualBind] = listener
	m.mu.Unlock()
	if err := m.connection.Go(func(ctx context.Context) error { return m.run(ctx, listener) }); err != nil {
		m.remove(listener)
		_ = listener.Close()
		return nil, err
	}
	return RemoteListenResponse{
		Bind: request.Bind, ActualBind: listener.actualBind, ActualPort: listener.actualPort,
	}, nil
}

// HandleStop handles a remote-forward stop RPC.
func (m *RemoteForwardService) HandleStop(_ context.Context, payload spdyrpc.RawMessage) (any, error) {
	request := RemoteStopRequest{}
	if err := m.connection.Codec().Decode(bytes.NewReader(payload), &request); err != nil {
		return nil, err
	}
	m.mu.Lock()
	listener := m.listeners[request.Bind]
	delete(m.listeners, request.Bind)
	m.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	return nil, nil
}

func (m *RemoteForwardService) run(ctx context.Context, listener *remoteTCPListener) error {
	defer m.remove(listener)
	defer listener.Close()

	return listener.run(ctx)
}

func (m *RemoteForwardService) remove(listener *remoteTCPListener) {
	m.mu.Lock()
	if m.listeners[listener.actualBind] == listener {
		delete(m.listeners, listener.actualBind)
	}
	m.mu.Unlock()
}

type remoteTCPListener struct {
	connection    *spdyrpc.Connection
	listener      net.Listener
	requestedBind string
	actualBind    string
	actualPort    uint32
}

func newRemoteTCPListener(connection *spdyrpc.Connection, bind string) (*remoteTCPListener, error) {
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
	return &remoteTCPListener{
		connection: connection, listener: listener, requestedBind: bind,
		actualBind: actualBind, actualPort: uint32(actualPort),
	}, nil
}

func (l *remoteTCPListener) run(ctx context.Context) error {
	stopOnContext := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stopOnContext()
	for {
		tcpConn, err := l.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if err := l.connection.Go(func(ctx context.Context) error {
			proxyRemoteListenerConnection(ctx, l.connection, l.actualBind, l.requestedBind, tcpConn)
			return nil
		}); err != nil {
			_ = tcpConn.Close()
			return nil
		}
	}
}

func (l *remoteTCPListener) Close() error { return l.listener.Close() }

func proxyRemoteListenerConnection(ctx context.Context, server *spdyrpc.Connection, bind, requestedBind string, tcpConn net.Conn) {
	defer tcpConn.Close()
	originHost, originPortText, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
	originPort, _ := strconv.ParseUint(originPortText, 10, 32)
	stream, err := server.CreateStream(RemoteConnectionHeaders(bind, requestedBind, originHost, strconv.FormatUint(originPort, 10)))
	if err != nil {
		return
	}
	defer stream.Close()
	_ = ioproxy.Proxy(ctx, tcpHalfCloser{Conn: tcpConn}, spdyStreamHalfCloser{Stream: stream})
}

// remoteForwardClient manages the client side of remote forwarding. A
// listener is registered before its listen RPC completes because the helper
// can create a connection stream as soon as the remote socket starts serving.
type remoteForwardClient struct {
	helper *Client

	mu sync.Mutex
	// forwards is keyed by requested bind while listen is in flight, then
	// re-keyed to actual bind after the listen response. Dispatch also falls
	// back to requested bind so early connection streams are not dropped.
	forwards map[string]*RemoteListener
}

type RemoteListener struct {
	client     *remoteForwardClient
	actualBind string
	actualPort uint32

	// incoming and closed are protected by mu so cancel/close cannot race with
	// dispatch and enqueue a stream after the forward has been closed.
	mu       sync.Mutex
	cond     *sync.Cond
	incoming []remoteIncoming
	closed   bool
	closeErr error

	cancelOnce sync.Once
	cancelErr  error
}

type remoteIncoming struct {
	stream httpstream.Stream
	info   ConnectionInfo
}

func newRemoteForwardClient(helper *Client) *remoteForwardClient {
	return &remoteForwardClient{
		helper:   helper,
		forwards: make(map[string]*RemoteListener),
	}
}

func (c *remoteForwardClient) Listen(ctx context.Context, host string, port uint32) (*RemoteListener, error) {
	bind := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	forward := &RemoteListener{client: c}
	forward.cond = sync.NewCond(&forward.mu)
	// Register before the RPC completes. The helper may accept a connection
	// immediately after listen succeeds, before this call receives the response.
	if !c.add(bind, forward) {
		return nil, fmt.Errorf("remote-forward listener already exists for %s", bind)
	}
	response := RemoteListenResponse{}
	if err := c.helper.Call(ctx, MethodRemoteListen, RemoteListenRequest{Bind: bind}, &response); err != nil {
		c.removeIfMatch(bind, forward)
		forward.closeLocal(err)
		return nil, err
	}

	forward.actualBind = response.ActualBind
	forward.actualPort = response.ActualPort
	if !c.rekey(bind, forward.actualBind, forward) {
		forward.closeLocal(context.Canceled)
		return nil, fmt.Errorf("remote-forward listener closed")
	}
	return forward, nil
}

func (c *remoteForwardClient) add(bind string, forward *RemoteListener) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forwards[bind] != nil {
		return false
	}
	c.forwards[bind] = forward
	return true
}

func (c *remoteForwardClient) removeIfMatch(bind string, forward *RemoteListener) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forwards[bind] == forward {
		delete(c.forwards, bind)
	}
}

func (c *remoteForwardClient) rekey(oldBind, newBind string, forward *RemoteListener) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Close or failed Listen may have removed the in-flight requested bind.
	// In that case do not resurrect a closed forward under the actual bind.
	if c.forwards[oldBind] != forward {
		return false
	}
	if oldBind != newBind {
		delete(c.forwards, oldBind)
	}
	c.forwards[newBind] = forward
	return true
}

func (c *remoteForwardClient) dispatch(incoming remoteIncoming) {
	c.mu.Lock()
	forward := c.forwards[incoming.info.Bind]
	if forward == nil {
		// Port 0 listeners can produce a connection stream with the actual bind
		// before Listen has re-keyed the map under that actual address.
		forward = c.forwards[incoming.info.RequestedBind]
	}
	c.mu.Unlock()
	if forward == nil {
		c.helper.closeStream(incoming.stream)
		return
	}
	forward.deliver(incoming)
}

func (c *remoteForwardClient) removeForward(forward *RemoteListener) {
	c.mu.Lock()
	// A listener can be addressable by requested and actual bind during the
	// listen/rekey window; cancel removes every key owned by this forward.
	for bind, got := range c.forwards {
		if got == forward {
			delete(c.forwards, bind)
		}
	}
	c.mu.Unlock()
}

func (c *remoteForwardClient) close() {
	c.mu.Lock()
	forwards := make([]*RemoteListener, 0, len(c.forwards))
	for _, forward := range c.forwards {
		forwards = append(forwards, forward)
	}
	c.forwards = make(map[string]*RemoteListener)
	c.mu.Unlock()

	for _, forward := range forwards {
		forward.closeLocal(ErrClientClosed)
	}
}

func (f *RemoteListener) ActualPort() uint32 {
	return f.actualPort
}

func (f *RemoteListener) Accept(ctx context.Context) (ioproxy.HalfCloser, ConnectionInfo, error) {
	ctxDone := context.AfterFunc(ctx, func() {
		f.mu.Lock()
		f.cond.Broadcast()
		f.mu.Unlock()
	})
	defer ctxDone()

	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		if len(f.incoming) > 0 {
			incoming := f.incoming[0]
			copy(f.incoming, f.incoming[1:])
			f.incoming = f.incoming[:len(f.incoming)-1]
			return spdyStreamHalfCloser{Stream: incoming.stream}, incoming.info, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, ConnectionInfo{}, err
		}
		if f.closed && f.closeErr != nil {
			return nil, ConnectionInfo{}, f.closeErr
		}
		select {
		case <-f.client.helper.closed:
			return nil, ConnectionInfo{}, ErrClientClosed
		default:
		}
		if f.closed {
			return nil, ConnectionInfo{}, context.Canceled
		}
		f.cond.Wait()
	}
}

func (f *RemoteListener) Cancel(ctx context.Context) error {
	f.cancelOnce.Do(func() {
		f.client.removeForward(f)
		f.closeLocal(context.Canceled)
		f.cancelErr = f.client.helper.Call(ctx, MethodRemoteStop, RemoteStopRequest{Bind: f.actualBind}, nil)
		if errors.Is(f.cancelErr, ErrClientClosed) {
			f.cancelErr = nil
		}
	})
	return f.cancelErr
}

func (f *RemoteListener) deliver(incoming remoteIncoming) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		f.client.helper.closeStream(incoming.stream)
		return
	}
	select {
	case <-f.client.helper.closed:
		f.mu.Unlock()
		f.client.helper.closeStream(incoming.stream)
		return
	default:
	}
	f.incoming = append(f.incoming, incoming)
	f.cond.Signal()
	f.mu.Unlock()
}

func (f *RemoteListener) closeLocal(err error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.closeErr = err
	pending := f.incoming
	f.incoming = nil
	f.cond.Broadcast()
	f.mu.Unlock()

	for _, incoming := range pending {
		f.client.helper.closeStream(incoming.stream)
	}
}

func remoteIncomingFromStream(stream httpstream.Stream) (remoteIncoming, error) {
	bind, requestedBind, originHost, originPortText := RemoteConnectionHeaderValues(stream.Headers())
	originPort, err := strconv.ParseUint(originPortText, 10, 32)
	if err != nil {
		return remoteIncoming{}, fmt.Errorf("invalid origin port %q: %w", originPortText, err)
	}
	return remoteIncoming{
		stream: stream,
		info: ConnectionInfo{
			Bind:          bind,
			RequestedBind: requestedBind,
			OriginHost:    originHost,
			OriginPort:    uint32(originPort),
		},
	}, nil
}
