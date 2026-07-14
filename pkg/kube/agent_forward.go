package kube

import (
	"context"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

func (b *Backend) AgentForward(ctx context.Context, req backend.AgentForwardRequest) (backend.AgentForward, error) {
	session, err := b.startHelperSession(ctx, req.Target, helperpkg.CapabilityAgentForward)
	if err != nil {
		return nil, err
	}
	forward, err := session.client.ListenAgent(ctx)
	if err != nil {
		_ = session.Close()
		return nil, status.HelperUnavailable(err, "create helper agent-forward")
	}
	return &agentForward{helperSession: session, forward: forward}, nil
}

type agentForward struct {
	*helperSession
	forward *helperpkg.AgentListener
}

func (f *agentForward) SocketPath() string {
	return f.forward.SocketPath()
}

func (f *agentForward) Accept(ctx context.Context) (ioproxy.HalfCloser, error) {
	stream, err := f.forward.Accept(ctx)
	if err != nil {
		return nil, f.resolveClientError(err)
	}
	return stream, nil
}
