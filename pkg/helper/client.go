package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"k8s.io/streaming/pkg/httpstream"
	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
	"xiaoshiai.cn/kube-ssh/pkg/util"
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
	closeErr  error
}

func NewClient(ctx context.Context, stdin io.WriteCloser, stdout io.ReadCloser) (*Client, error) {
	client := &Client{closed: make(chan struct{})}
	client.remoteForward = newRemoteForwardClient(client)
	client.agentForward = newAgentForwardClient(client)

	stdioConn := util.NewStdioConn(stdout, stdin, func() error {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil
	})
	connection, err := spdyrpc.NewServerConnection(ctx, stdioConn, spdyrpc.ConnectionOptions{})
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("create helper SPDY connection: %w", err)
	}
	client.conn = connection
	if err := connection.RegisterStreamHandler(StreamTypeRemoteConnection, client.handleRemoteStream); err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.RegisterStreamHandler(StreamTypeAgentConnection, client.handleAgentStream); err != nil {
		_ = connection.Close()
		return nil, err
	}
	go func() {
		_ = connection.Serve()
		_ = client.Close()
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-connection.Closed():
			_ = client.Close()
		}
	}()
	return client, nil
}

func (c *Client) ListenRemote(ctx context.Context, host string, port uint32) (*RemoteListener, error) {
	return c.remoteForward.Listen(ctx, host, port)
}

func (c *Client) ListenAgent(ctx context.Context) (*AgentListener, error) {
	return c.agentForward.Listen(ctx)
}

// Call invokes a registered server RPC method.
func (c *Client) Call(ctx context.Context, method string, in any, out any) error {
	err := c.conn.Call(ctx, method, in, out)
	if err == nil {
		return nil
	}
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

// RegisterStreamHandler registers a handler for server-initiated streams.
func (c *Client) RegisterStreamHandler(streamType string, handler spdyrpc.StreamHandler) error {
	return c.conn.RegisterStreamHandler(streamType, handler)
}

func (c *Client) closeStream(stream httpstream.Stream) {
	_ = stream.Close()
}

func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.remoteForward.close()
		c.agentForward.close()
		if c.conn != nil {
			c.closeErr = c.conn.Close()
			if errors.Is(c.closeErr, io.EOF) || errors.Is(c.closeErr, io.ErrClosedPipe) {
				c.closeErr = nil
			}
		}
	})
	return c.closeErr
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
