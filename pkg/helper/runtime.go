package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
)

func RunRuntime(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	runtime := newRuntime(ctx)
	conn := NewStdioConn(stdin, stdout, nil)
	spdyConn, err := newClientSPDYConnection(conn, runtime.newStreamHandler())
	if err != nil {
		return err
	}
	defer spdyConn.Close()
	runtime.setConnection(spdyConn)
	go spdyConn.Serve()

	go func() {
		<-ctx.Done()
		_ = spdyConn.Close()
	}()

	select {
	case err := <-runtime.done:
		return err
	case <-spdyConn.CloseChan():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type runtimeHandler func(context.Context, json.RawMessage) (runtimeHandlerResult, error)

type runtimeHandlerResult struct {
	payload any
	// afterResponse runs only after the RPC response has been written and the
	// control stream has been removed. Stop operations use this to avoid closing
	// the runtime before the client can read the response.
	afterResponse func()
}

type runtimeServer struct {
	ctx      context.Context
	handlers map[string]runtimeHandler

	conn httpstream.Connection

	remoteForward *remoteForwardManager

	done     chan error
	doneOnce sync.Once
}

func newRuntime(ctx context.Context) *runtimeServer {
	runtime := &runtimeServer{
		ctx:      ctx,
		handlers: make(map[string]runtimeHandler),
		done:     make(chan error, 1),
	}
	runtime.remoteForward = newRemoteForwardManager(ctx, runtime.finish)
	runtime.handlers[ControlTypeRemoteForwardListen] = runtime.remoteForward.handleListen
	runtime.handlers[ControlTypeRemoteForwardStop] = runtime.remoteForward.handleStop
	return runtime
}

func (r *runtimeServer) setConnection(conn httpstream.Connection) {
	r.conn = conn
	r.remoteForward.setConnection(conn)
}

func (r *runtimeServer) finish(err error) {
	r.doneOnce.Do(func() {
		r.done <- err
	})
}

func (r *runtimeServer) newStreamHandler() httpstream.NewStreamHandler {
	return func(stream httpstream.Stream, replySent <-chan struct{}) error {
		switch stream.Headers().Get(StreamTypeHeader) {
		case StreamTypeControl:
			go func() {
				<-replySent
				r.handleRuntimeRPC(stream)
			}()
			return nil
		default:
			return fmt.Errorf("unsupported helper runtime stream type %q", stream.Headers().Get(StreamTypeHeader))
		}
	}
}

func (r *runtimeServer) handleRuntimeRPC(stream httpstream.Stream) {
	request := RuntimeRequest{}
	if err := json.NewDecoder(stream).Decode(&request); err != nil {
		r.closeStream(stream)
		if err != io.EOF {
			r.finish(err)
		}
		return
	}

	response, afterResponse := r.dispatch(request)
	if err := json.NewEncoder(stream).Encode(response); err != nil {
		r.closeStream(stream)
		r.finish(err)
		return
	}
	r.closeStream(stream)
	if afterResponse != nil {
		afterResponse()
	}
}

func (r *runtimeServer) dispatch(request RuntimeRequest) (RuntimeResponse, func()) {
	handler := r.handlers[request.Type]
	if handler == nil {
		return newRuntimeErrorResponse(fmt.Errorf("unsupported helper runtime control type %q", request.Type)), nil
	}
	result, err := handler(r.ctx, request.Payload)
	if err != nil {
		return newRuntimeErrorResponse(err), nil
	}
	response, err := newRuntimeResponse(result.payload)
	if err != nil {
		return newRuntimeErrorResponse(err), nil
	}
	return response, result.afterResponse
}

func (r *runtimeServer) closeStream(stream httpstream.Stream) {
	_ = stream.Close()
	r.conn.RemoveStreams(stream)
}

func newRuntimeResponse(payload any) (RuntimeResponse, error) {
	response := RuntimeResponse{OK: true}
	if payload == nil {
		return response, nil
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return RuntimeResponse{}, err
	}
	response.Payload = data
	return response, nil
}

func newRuntimeErrorResponse(err error) RuntimeResponse {
	return RuntimeResponse{OK: false, Error: err.Error()}
}

type closeable interface {
	Close() error
}

func closeConnOnContext(ctx context.Context, c closeable) {
	<-ctx.Done()
	_ = c.Close()
}

func closeIfPossible(v any) error {
	if c, ok := v.(closeable); ok {
		return c.Close()
	}
	return nil
}
