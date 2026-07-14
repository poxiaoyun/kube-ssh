package helper

import (
	"context"
	"io"

	"xiaoshiai.cn/kube-ssh/pkg/spdyrpc"
	"xiaoshiai.cn/kube-ssh/pkg/util"
)

// ServeConnection runs the helper-side forwarding server over stdin and stdout
// until the context is canceled or the client closes the connection.
func ServeConnection(ctx context.Context, stdin io.Reader, stdout io.Writer, options spdyrpc.ConnectionOptions) error {
	transport := util.NewStdioConn(stdin, stdout, nil)
	connection, err := spdyrpc.NewClientConnection(ctx, transport, options)
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
	remote := NewRemoteForwardService(connection)
	agent := NewAgentForwardService(connection)
	registrations := []struct {
		method  string
		handler spdyrpc.Handler
	}{
		{MethodRemoteListen, spdyrpc.HandlerFunc(remote.HandleListen)},
		{MethodRemoteStop, spdyrpc.HandlerFunc(remote.HandleStop)},
		{MethodAgentListen, spdyrpc.HandlerFunc(agent.HandleListen)},
		{MethodAgentStop, spdyrpc.HandlerFunc(agent.HandleStop)},
	}
	for _, registration := range registrations {
		if err := connection.Register(registration.method, registration.handler); err != nil {
			return err
		}
	}
	return nil
}
