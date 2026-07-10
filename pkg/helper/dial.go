package helper

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

func RunDial(ctx context.Context, host string, port uint, stdin io.Reader, stdout io.Writer) error {
	if host == "" {
		return fmt.Errorf("host is required")
	}
	if port == 0 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return err
	}
	return ioproxy.Proxy(ctx, tcpHalfCloser{Conn: conn}, newStdioProxyConn(stdin, stdout))
}

type tcpHalfCloser struct {
	net.Conn
}

func (c tcpHalfCloser) CloseWrite() error {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return c.Conn.Close()
}

type stdioProxyConn struct {
	reader         io.Reader
	writer         io.Writer
	closeOnce      sync.Once
	closeWriteOnce sync.Once
}

func newStdioProxyConn(reader io.Reader, writer io.Writer) *stdioProxyConn {
	return &stdioProxyConn{reader: reader, writer: writer}
}

func (c *stdioProxyConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *stdioProxyConn) Write(p []byte) (int, error) {
	return c.writer.Write(p)
}

func (c *stdioProxyConn) Close() error {
	c.closeOnce.Do(func() {
		_ = closeIfPossible(c.reader)
		_ = closeIfPossible(c.writer)
	})
	return nil
}

func (c *stdioProxyConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		_ = closeIfPossible(c.reader)
	})
	return nil
}
