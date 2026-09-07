package helper

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

// RunDial connects stdin and stdout to a TCP endpoint, preserving half-close in
// both directions. It owns both streams; Close must unblock their pending I/O.
func RunDial(ctx context.Context, host string, port uint, stdin io.ReadCloser, stdout io.WriteCloser) error {
	stdio := newStdioConn(stdin, stdout)
	defer stdio.Close()
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
	return ioproxy.Proxy(ctx, conn.(*net.TCPConn), stdio)
}
