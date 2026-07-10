package helper

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"k8s.io/streaming/pkg/httpstream"
)

const (
	StreamTypeHeader                  = "streamType"
	StreamTypeControl                 = "control"
	StreamTypeRemoteForwardConnection = "remote-forward.connection"
	StreamTypeAgentForwardConnection  = "agent-forward.connection"
	// RemoteForwardBindHeader is the actual listener address. When the client
	// requests port 0 this value is only known after listen succeeds.
	RemoteForwardBindHeader = "remoteForwardBind"
	// RemoteForwardRequestedBindHeader preserves the bind requested by the
	// gateway so early connection streams can still be routed before the client
	// has re-keyed the forward under its actual bind.
	RemoteForwardRequestedBindHeader = "remoteForwardRequestedBind"
	OriginHostHeader                 = "originHost"
	OriginPortHeader                 = "originPort"

	ControlTypeRemoteForwardListen = "remote-forward.listen"
	ControlTypeRemoteForwardStop   = "remote-forward.stop"
	ControlTypeAgentForwardListen  = "agent-forward.listen"
	ControlTypeAgentForwardStop    = "agent-forward.stop"
)

type RuntimeRequest struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type RuntimeResponse struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type RemoteForwardListenRequest struct {
	Bind string `json:"bind"`
}

type RemoteForwardListenResponse struct {
	Bind       string `json:"bind"`
	ActualBind string `json:"actualBind"`
	ActualPort uint32 `json:"actualPort"`
}

type RemoteForwardStopRequest struct {
	Bind string `json:"bind"`
}

type AgentForwardListenResponse struct {
	SocketPath string `json:"socketPath"`
}

type RemoteForwardConnInfo struct {
	// Bind is the actual remote listener address.
	Bind string
	// RequestedBind is the address originally requested by the gateway.
	RequestedBind string
	OriginHost    string
	OriginPort    uint32
}

func ControlHeaders() http.Header {
	headers := http.Header{}
	headers.Set(StreamTypeHeader, StreamTypeControl)
	return headers
}

func RemoteForwardHeaders(bind, requestedBind, originHost, originPort string) http.Header {
	headers := http.Header{}
	headers.Set(StreamTypeHeader, StreamTypeRemoteForwardConnection)
	headers.Set(RemoteForwardBindHeader, bind)
	headers.Set(RemoteForwardRequestedBindHeader, requestedBind)
	headers.Set(OriginHostHeader, originHost)
	headers.Set(OriginPortHeader, originPort)
	return headers
}

func AgentForwardHeaders() http.Header {
	headers := http.Header{}
	headers.Set(StreamTypeHeader, StreamTypeAgentForwardConnection)
	return headers
}

type StdioConn struct {
	reader    io.Reader
	writer    io.Writer
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

func NewStdioConn(reader io.Reader, writer io.Writer, closeFn func() error) *StdioConn {
	if closeFn == nil {
		closeFn = func() error { return nil }
	}
	return &StdioConn{reader: reader, writer: writer, close: closeFn}
}

func (c *StdioConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *StdioConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *StdioConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.close()
	})
	return c.closeErr
}

func (c *StdioConn) LocalAddr() net.Addr              { return stdioAddr("stdio-local") }
func (c *StdioConn) RemoteAddr() net.Addr             { return stdioAddr("stdio-remote") }
func (c *StdioConn) SetDeadline(time.Time) error      { return nil }
func (c *StdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c *StdioConn) SetWriteDeadline(time.Time) error { return nil }

type stdioAddr string

func (a stdioAddr) Network() string { return "stdio" }
func (a stdioAddr) String() string  { return string(a) }

type StreamHalfCloser struct {
	Stream httpstream.Stream
}

func (s StreamHalfCloser) Read(p []byte) (int, error) {
	return s.Stream.Read(p)
}

func (s StreamHalfCloser) Write(p []byte) (int, error) {
	return s.Stream.Write(p)
}

func (s StreamHalfCloser) Close() error {
	return s.Stream.Close()
}

func (s StreamHalfCloser) CloseWrite() error {
	return nil
}
