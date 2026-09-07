package helper

import (
	"context"
	"io"

	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
)

// ServeConnection runs the helper-side forwarding server over stdin and stdout
// until the context is canceled or the client closes the connection. It owns
// and closes both streams, whose Close methods must unblock pending I/O.
func ServeConnection(ctx context.Context, stdin io.ReadCloser, stdout io.WriteCloser) error {
	transport := newStdioConn(stdin, stdout)
	connection, err := spdyrpc.NewClientConnection(ctx, transport)
	if err != nil {
		return err
	}
	if err := registerForwardingServices(connection); err != nil {
		_ = connection.Close()
		return err
	}
	return connection.Serve()
}

func registerForwardingServices(connection *spdyrpc.Connection) error {
	remote := newRemoteForwardService(connection)
	agent := newAgentForwardService(connection)
	registrations := []struct {
		method  string
		handler spdyrpc.Handler
	}{
		{methodRemoteListen, spdyrpc.HandlerFunc(remote.handleListen)},
		{methodRemoteStop, spdyrpc.HandlerFunc(remote.handleStop)},
		{methodAgentListen, spdyrpc.HandlerFunc(agent.handleListen)},
		{methodAgentStop, spdyrpc.HandlerFunc(agent.handleStop)},
	}
	for _, registration := range registrations {
		if err := connection.Register(registration.method, registration.handler); err != nil {
			return err
		}
	}
	return nil
}
