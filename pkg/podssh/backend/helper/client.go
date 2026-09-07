package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

// ErrClientClosed indicates that an operation cannot continue because
// the helper connection has closed.
var ErrClientClosed = spdyrpc.ErrConnectionClosed

type Client struct {
	conn *spdyrpc.Connection

	remoteForward *remoteForwardClient
	agentForward  *agentForwardClient
	closed        chan struct{}

	closeOnce sync.Once
}

// NewClient starts a helper client and takes ownership of stdin and stdout.
// Closing either stream must unblock its pending I/O.
func NewClient(ctx context.Context, stdin io.WriteCloser, stdout io.ReadCloser) (*Client, error) {
	client := &Client{closed: make(chan struct{})}
	client.remoteForward = newRemoteForwardClient(client)
	client.agentForward = newAgentForwardClient(client)

	stdioConn := newStdioConn(stdout, stdin)
	connection, err := spdyrpc.NewServerConnection(ctx, stdioConn)
	if err != nil {
		return nil, fmt.Errorf("create helper SPDY connection: %w", err)
	}
	client.conn = connection
	if err := connection.RegisterStreamHandler(streamTypeRemoteConnection, client.handleRemoteStream); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.RegisterStreamHandler(streamTypeAgentConnection, client.handleAgentStream); err != nil {
		_ = connection.Close()
		return nil, err
	}
	go func() {
		_ = connection.Serve()
		_ = client.Close()
	}()
	return client, nil
}

func (c *Client) ListenRemote(ctx context.Context, host string, port uint32) (*RemoteListener, error) {
	return c.remoteForward.Listen(ctx, host, port)
}

func (c *Client) ListenAgent(ctx context.Context) (*AgentListener, error) {
	return c.agentForward.Listen(ctx)
}

func (c *Client) call(ctx context.Context, method string, in any, out any) error {
	err := c.conn.Call(ctx, method, in, out)
	if err != nil {
		select {
		case <-c.closed:
			return ErrClientClosed
		default:
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, spdyrpc.ErrConnectionClosed) {
			return ErrClientClosed
		}
		return err
	}
	return nil
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		c.remoteForward.close()
		c.agentForward.close()
	})
	return nil
}

func (c *Client) handleRemoteStream(stream httpstream.Stream) error {
	incoming, err := remoteIncomingFromStream(stream)
	if err != nil {
		return err
	}
	c.remoteForward.dispatch(incoming)
	return nil
}

func (c *Client) handleAgentStream(stream httpstream.Stream) error {
	c.agentForward.dispatch(stream)
	return nil
}
