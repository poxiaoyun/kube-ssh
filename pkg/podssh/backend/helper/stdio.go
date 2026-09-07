package helper

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// stdioConn adapts separate input and output streams to net.Conn. Deadlines are
// unsupported because plain streams do not expose deadline control.
type stdioConn struct {
	reader         io.ReadCloser
	writer         io.WriteCloser
	closeOnce      sync.Once
	closeErr       error
	closeWriteOnce sync.Once
	closeWriteErr  error
}

// newStdioConn takes ownership of reader and writer.
func newStdioConn(reader io.ReadCloser, writer io.WriteCloser) *stdioConn {
	return &stdioConn{reader: reader, writer: writer}
}

func (c *stdioConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *stdioConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *stdioConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = errors.Join(c.reader.Close(), c.CloseWrite())
	})
	return c.closeErr
}

func (c *stdioConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.closeWriteErr = c.writer.Close()
	})
	return c.closeWriteErr
}

func (*stdioConn) LocalAddr() net.Addr              { return stdioAddr("stdio-local") }
func (*stdioConn) RemoteAddr() net.Addr             { return stdioAddr("stdio-remote") }
func (*stdioConn) SetDeadline(time.Time) error      { return nil }
func (*stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (*stdioConn) SetWriteDeadline(time.Time) error { return nil }

type stdioAddr string

func (a stdioAddr) Network() string { return "stdio" }
func (a stdioAddr) String() string  { return string(a) }
