package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"k8s.io/streaming/pkg/httpstream/spdy"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

type RuntimeClient struct {
	conn httpstream.Connection

	remoteForward *RemoteForwardClient
	agentForward  *AgentForwardClient
	closed        chan struct{}

	closeOnce sync.Once
	closeErr  error
}

type RemoteForwardClient struct {
	runtime *RuntimeClient

	mu sync.Mutex
	// forwards is keyed by requested bind while listen is in flight, then
	// re-keyed to actual bind after the listen response. Dispatch also falls
	// back to requested bind so early connection streams are not dropped.
	forwards map[string]*RemoteForward
}

type AgentForwardClient struct {
	runtime *RuntimeClient

	mu      sync.Mutex
	forward *AgentForward
}

type RemoteForward struct {
	client     *RemoteForwardClient
	bind       string
	actualBind string
	actualPort uint32

	// incoming and closed are protected by mu so cancel/close cannot race with
	// dispatch and enqueue a stream after the forward has been closed.
	mu       sync.Mutex
	cond     *sync.Cond
	incoming []remoteForwardIncoming
	closed   bool

	cancelOnce sync.Once
	cancelErr  error
}

type AgentForward struct {
	client     *AgentForwardClient
	socketPath string

	mu       sync.Mutex
	cond     *sync.Cond
	incoming []httpstream.Stream
	closed   bool

	cancelOnce sync.Once
	cancelErr  error
}

type remoteForwardIncoming struct {
	stream httpstream.Stream
	info   RemoteForwardConnInfo
}

type runtimeCallResult struct {
	response RuntimeResponse
	err      error
}

func NewRuntimeClient(ctx context.Context, stdin io.WriteCloser, stdout io.ReadCloser) (*RuntimeClient, error) {
	client := &RuntimeClient{
		closed: make(chan struct{}),
	}
	client.remoteForward = newRemoteForwardClient(client)
	client.agentForward = newAgentForwardClient(client)

	stdioConn := NewStdioConn(stdout, stdin, func() error {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil
	})
	spdyConn, err := spdy.NewServerConnection(stdioConn, client.newStreamHandler())
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("create helper runtime spdy connection: %w", err)
	}
	client.conn = spdyConn

	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-spdyConn.CloseChan():
			_ = client.Close()
		}
	}()
	return client, nil
}

func (c *RuntimeClient) RemoteForward(ctx context.Context, host string, port uint32) (*RemoteForward, error) {
	return c.remoteForward.Listen(ctx, host, port)
}

func (c *RuntimeClient) AgentForward(ctx context.Context) (*AgentForward, error) {
	return c.agentForward.Listen(ctx)
}

func (c *RuntimeClient) call(ctx context.Context, requestType string, in any, out any) error {
	stream, err := c.openRuntimeStream(ctx)
	if err != nil {
		return err
	}
	defer c.closeStream(stream)

	request, err := newRuntimeRequest(requestType, in)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stream).Encode(request); err != nil {
		return err
	}

	result := readRuntimeResponse(stream)
	select {
	case got := <-result:
		if got.err != nil {
			return got.err
		}
		return decodeRuntimeResponse(requestType, got.response, out)
	case <-ctx.Done():
		_ = stream.Close()
		return ctx.Err()
	case <-c.closed:
		_ = stream.Close()
		return fmt.Errorf("helper runtime client closed")
	}
}

func (c *RuntimeClient) openRuntimeStream(ctx context.Context) (httpstream.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, fmt.Errorf("helper runtime client closed")
	default:
	}

	stream, err := c.conn.CreateStream(ControlHeaders())
	if err != nil {
		return nil, err
	}
	return stream, nil
}

func (c *RuntimeClient) closeStream(stream httpstream.Stream) {
	_ = stream.Close()
	c.conn.RemoveStreams(stream)
}

func (c *RuntimeClient) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.remoteForward.close()
		c.agentForward.close()
		if c.conn != nil {
			c.closeErr = c.conn.Close()
			if errors.Is(c.closeErr, io.ErrClosedPipe) {
				c.closeErr = nil
			}
		}
	})
	return c.closeErr
}

func (c *RuntimeClient) newStreamHandler() httpstream.NewStreamHandler {
	return func(stream httpstream.Stream, replySent <-chan struct{}) error {
		switch stream.Headers().Get(StreamTypeHeader) {
		case StreamTypeRemoteForwardConnection:
			incoming, err := remoteForwardIncomingFromStream(stream)
			if err != nil {
				return err
			}
			go func() {
				<-replySent
				c.remoteForward.dispatch(incoming)
			}()
		case StreamTypeAgentForwardConnection:
			go func() {
				<-replySent
				c.agentForward.dispatch(stream)
			}()
		case StreamTypeControl:
			return fmt.Errorf("helper must not create runtime control streams")
		default:
			return fmt.Errorf("unsupported helper stream type %q", stream.Headers().Get(StreamTypeHeader))
		}
		return nil
	}
}

func newRuntimeRequest(requestType string, payload any) (RuntimeRequest, error) {
	request := RuntimeRequest{Type: requestType}
	if payload == nil {
		return request, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return RuntimeRequest{}, err
	}
	request.Payload = data
	return request, nil
}

func readRuntimeResponse(stream httpstream.Stream) <-chan runtimeCallResult {
	result := make(chan runtimeCallResult, 1)
	go func() {
		response := RuntimeResponse{}
		err := json.NewDecoder(stream).Decode(&response)
		result <- runtimeCallResult{response: response, err: err}
	}()
	return result
}

func decodeRuntimeResponse(requestType string, response RuntimeResponse, out any) error {
	if !response.OK {
		return fmt.Errorf("helper runtime request %q failed: %s", requestType, response.Error)
	}
	if out == nil || len(response.Payload) == 0 {
		return nil
	}
	return json.Unmarshal(response.Payload, out)
}

func newRemoteForwardClient(runtime *RuntimeClient) *RemoteForwardClient {
	return &RemoteForwardClient{
		runtime:  runtime,
		forwards: make(map[string]*RemoteForward),
	}
}

func newAgentForwardClient(runtime *RuntimeClient) *AgentForwardClient {
	return &AgentForwardClient{runtime: runtime}
}

func (c *AgentForwardClient) Listen(ctx context.Context) (*AgentForward, error) {
	forward := newAgentForward(c)
	c.mu.Lock()
	if c.forward != nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("agent-forward listener already exists")
	}
	c.forward = forward
	c.mu.Unlock()

	response := AgentForwardListenResponse{}
	if err := c.runtime.call(ctx, ControlTypeAgentForwardListen, nil, &response); err != nil {
		c.removeIfMatch(forward)
		forward.closeLocal()
		return nil, err
	}
	forward.socketPath = response.SocketPath
	return forward, nil
}

func newAgentForward(client *AgentForwardClient) *AgentForward {
	forward := &AgentForward{client: client}
	forward.cond = sync.NewCond(&forward.mu)
	return forward
}

func (c *AgentForwardClient) dispatch(stream httpstream.Stream) {
	c.mu.Lock()
	forward := c.forward
	c.mu.Unlock()
	if forward == nil {
		c.runtime.closeStream(stream)
		return
	}
	forward.deliver(stream)
}

func (c *AgentForwardClient) removeIfMatch(forward *AgentForward) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forward == forward {
		c.forward = nil
	}
}

func (c *AgentForwardClient) close() {
	c.mu.Lock()
	forward := c.forward
	c.forward = nil
	c.mu.Unlock()
	if forward != nil {
		forward.closeLocal()
	}
}

func (f *AgentForward) SocketPath() string {
	return f.socketPath
}

func (f *AgentForward) Accept(ctx context.Context) (ioproxy.HalfCloser, error) {
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
			stream := f.incoming[0]
			copy(f.incoming, f.incoming[1:])
			f.incoming = f.incoming[:len(f.incoming)-1]
			return &remoteForwardStream{conn: f.client.runtime.conn, stream: stream}, nil
		}
		if f.closed {
			return nil, fmt.Errorf("agent-forward canceled")
		}
		select {
		case <-f.client.runtime.closed:
			return nil, fmt.Errorf("helper runtime client closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		f.cond.Wait()
	}
}

func (f *AgentForward) Cancel(ctx context.Context) error {
	f.cancelOnce.Do(func() {
		f.cancelErr = f.client.runtime.call(ctx, ControlTypeAgentForwardStop, nil, nil)
		f.client.removeIfMatch(f)
		f.closeLocal()
	})
	return f.cancelErr
}

func (f *AgentForward) deliver(stream httpstream.Stream) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		f.client.runtime.closeStream(stream)
		return
	}
	select {
	case <-f.client.runtime.closed:
		f.client.runtime.closeStream(stream)
		return
	default:
	}
	f.incoming = append(f.incoming, stream)
	f.cond.Signal()
}

func (f *AgentForward) closeLocal() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	for _, stream := range f.incoming {
		f.client.runtime.closeStream(stream)
	}
	f.incoming = nil
	f.cond.Broadcast()
}

func (c *RemoteForwardClient) Listen(ctx context.Context, host string, port uint32) (*RemoteForward, error) {
	bind := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	forward := newRemoteForward(c, bind)
	// Register before the RPC completes. The helper may accept a connection
	// immediately after listen succeeds, before this call receives the response.
	if !c.add(bind, forward) {
		return nil, fmt.Errorf("remote-forward listener already exists for %s", bind)
	}
	response := RemoteForwardListenResponse{}
	if err := c.runtime.call(ctx, ControlTypeRemoteForwardListen, RemoteForwardListenRequest{Bind: bind}, &response); err != nil {
		c.removeIfMatch(bind, forward)
		forward.closeLocal()
		return nil, err
	}

	forward.setListenResponse(response)
	if !c.rekey(bind, forward.actualBind, forward) {
		forward.closeLocal()
		return nil, fmt.Errorf("remote-forward listener closed")
	}
	return forward, nil
}

func newRemoteForward(client *RemoteForwardClient, bind string) *RemoteForward {
	forward := &RemoteForward{
		client: client,
		bind:   bind,
	}
	forward.cond = sync.NewCond(&forward.mu)
	return forward
}

func (c *RemoteForwardClient) add(bind string, forward *RemoteForward) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forwards[bind] != nil {
		return false
	}
	c.forwards[bind] = forward
	return true
}

func (c *RemoteForwardClient) removeIfMatch(bind string, forward *RemoteForward) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.forwards[bind] == forward {
		delete(c.forwards, bind)
	}
}

func (c *RemoteForwardClient) rekey(oldBind, newBind string, forward *RemoteForward) bool {
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

func (c *RemoteForwardClient) dispatch(incoming remoteForwardIncoming) {
	c.mu.Lock()
	forward := c.forwards[incoming.info.Bind]
	if forward == nil {
		// Port 0 listeners can produce a connection stream with the actual bind
		// before Listen has re-keyed the map under that actual address.
		forward = c.forwards[incoming.info.RequestedBind]
	}
	c.mu.Unlock()
	if forward == nil {
		c.runtime.closeStream(incoming.stream)
		return
	}
	forward.deliver(incoming)
}

func (c *RemoteForwardClient) removeForward(forward *RemoteForward) {
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

func (c *RemoteForwardClient) close() {
	c.mu.Lock()
	forwards := make([]*RemoteForward, 0, len(c.forwards))
	seen := make(map[*RemoteForward]struct{}, len(c.forwards))
	for _, forward := range c.forwards {
		// The same forward may temporarily appear under requested and actual
		// bind keys; close each logical forward once.
		if _, ok := seen[forward]; ok {
			continue
		}
		seen[forward] = struct{}{}
		forwards = append(forwards, forward)
	}
	c.forwards = make(map[string]*RemoteForward)
	c.mu.Unlock()

	for _, forward := range forwards {
		forward.closeLocal()
	}
}

func (f *RemoteForward) ActualPort() uint32 {
	return f.actualPort
}

func (f *RemoteForward) Accept(ctx context.Context) (ioproxy.HalfCloser, RemoteForwardConnInfo, error) {
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
			return f.newStream(incoming), incoming.info, nil
		}
		if f.closed {
			return nil, RemoteForwardConnInfo{}, context.Canceled
		}
		select {
		case <-f.client.runtime.closed:
			return nil, RemoteForwardConnInfo{}, fmt.Errorf("helper runtime client closed")
		case <-ctx.Done():
			return nil, RemoteForwardConnInfo{}, ctx.Err()
		default:
		}
		f.cond.Wait()
	}
}

func (f *RemoteForward) Cancel(ctx context.Context) error {
	f.cancelOnce.Do(func() {
		f.cancelErr = f.client.runtime.call(ctx, ControlTypeRemoteForwardStop, RemoteForwardStopRequest{Bind: f.actualBind}, nil)
		f.client.removeForward(f)
		f.closeLocal()
	})
	return f.cancelErr
}

func (f *RemoteForward) deliver(incoming remoteForwardIncoming) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		f.client.runtime.closeStream(incoming.stream)
		return
	}
	select {
	case <-f.client.runtime.closed:
		f.mu.Unlock()
		f.client.runtime.closeStream(incoming.stream)
		return
	default:
	}
	f.incoming = append(f.incoming, incoming)
	f.cond.Signal()
	f.mu.Unlock()
}

func (f *RemoteForward) closeLocal() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	pending := f.incoming
	f.incoming = nil
	f.cond.Broadcast()
	f.mu.Unlock()

	for _, incoming := range pending {
		f.client.runtime.closeStream(incoming.stream)
	}
}

func (f *RemoteForward) setListenResponse(response RemoteForwardListenResponse) {
	f.actualBind = response.ActualBind
	f.actualPort = response.ActualPort
}

func (f *RemoteForward) newStream(incoming remoteForwardIncoming) ioproxy.HalfCloser {
	return &remoteForwardStream{conn: f.client.runtime.conn, stream: incoming.stream}
}

func remoteForwardIncomingFromStream(stream httpstream.Stream) (remoteForwardIncoming, error) {
	info, err := remoteForwardConnInfo(stream.Headers())
	if err != nil {
		return remoteForwardIncoming{}, err
	}
	return remoteForwardIncoming{stream: stream, info: info}, nil
}

func remoteForwardConnInfo(headers http.Header) (RemoteForwardConnInfo, error) {
	originPort, err := strconv.ParseUint(headers.Get(OriginPortHeader), 10, 32)
	if err != nil {
		return RemoteForwardConnInfo{}, fmt.Errorf("invalid origin port %q: %w", headers.Get(OriginPortHeader), err)
	}
	return RemoteForwardConnInfo{
		Bind:          headers.Get(RemoteForwardBindHeader),
		RequestedBind: headers.Get(RemoteForwardRequestedBindHeader),
		OriginHost:    headers.Get(OriginHostHeader),
		OriginPort:    uint32(originPort),
	}, nil
}

type remoteForwardStream struct {
	conn      httpstream.Connection
	stream    httpstream.Stream
	closeOnce sync.Once
	closeErr  error
}

func (s *remoteForwardStream) Read(p []byte) (int, error) {
	return s.stream.Read(p)
}

func (s *remoteForwardStream) Write(p []byte) (int, error) {
	return s.stream.Write(p)
}

func (s *remoteForwardStream) Close() error {
	s.closeOnce.Do(func() {
		s.closeErr = s.stream.Close()
		s.conn.RemoveStreams(s.stream)
	})
	return s.closeErr
}

func (s *remoteForwardStream) CloseWrite() error {
	return nil
}
