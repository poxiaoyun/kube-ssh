package util

import (
	"io"
	"net"
	"sync"
	"time"
)

// StdioConn adapts separate input and output streams to net.Conn. Deadlines are
// unsupported because plain streams do not expose deadline control.
type StdioConn struct {
	reader    io.Reader
	writer    io.Writer
	close     func() error
	closeOnce sync.Once
	closeErr  error
}

// NewStdioConn creates a net.Conn backed by reader and writer. closeFn may be
// nil when the caller does not own the streams.
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

func (*StdioConn) LocalAddr() net.Addr              { return stdioAddr("stdio-local") }
func (*StdioConn) RemoteAddr() net.Addr             { return stdioAddr("stdio-remote") }
func (*StdioConn) SetDeadline(time.Time) error      { return nil }
func (*StdioConn) SetReadDeadline(time.Time) error  { return nil }
func (*StdioConn) SetWriteDeadline(time.Time) error { return nil }

type stdioAddr string

func (a stdioAddr) Network() string { return "stdio" }
func (a stdioAddr) String() string  { return string(a) }
