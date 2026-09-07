package backend

import (
	"context"
	"fmt"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

func (b *Executor) AgentForward(ctx context.Context, req AgentForwardRequest) (AgentForward, error) {
	session, err := b.startHelperSession(ctx, req.Target, helperpkg.CapabilityAgentForward)
	if err != nil {
		return nil, err
	}
	forward, err := session.client.ListenAgent(ctx)
	if err != nil {
		err = session.resolveClientError(err)
		_ = session.Close()
		return nil, fmt.Errorf("create helper agent-forward: %w", err)
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
