package podssh

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

type sessionAgentForward struct {
	forward backend.AgentForward
	finish  sshprotocol.FinishOperation
	done    chan struct{}

	closeOnce sync.Once
	closing   atomic.Bool
}

func (p *Protocol) acceptAgentForward(ctx context.Context, conn cryptossh.Conn) (*sessionAgentForward, bool) {
	operation := sshprotocol.Operation{ChannelType: sshprotocol.ChannelSession, RequestType: sshprotocol.RequestAgentForward}
	finish, err := p.begin(operation)
	if err != nil {
		if finish != nil {
			finish(sshprotocol.OperationResult{})
		}
		slog.WarnContext(ctx, "agent forwarding denied", "reason", err)
		return nil, false
	}
	forward, err := p.backend.AgentForward(ctx, backend.AgentForwardRequest{Target: p.target})
	if err != nil {
		finish(sshprotocol.OperationResult{Err: err})
		slog.ErrorContext(ctx, "agent forwarding failed", "err", err)
		return nil, false
	}

	state := &sessionAgentForward{forward: forward, finish: finish, done: make(chan struct{})}
	go p.serveAgentForward(ctx, conn, state)
	return state, true
}

func (p *Protocol) serveAgentForward(ctx context.Context, conn cryptossh.Conn, state *sessionAgentForward) {
	var result sshprotocol.OperationResult
	defer func() {
		state.finish(result)
		close(state.done)
	}()

	for {
		stream, err := state.forward.Accept(ctx)
		if err != nil {
			if state.closing.Load() || ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			result.Err = err
			slog.ErrorContext(ctx, "agent forwarding accept failed", "err", err)
			return
		}
		go p.proxyAgentForwardConnection(ctx, conn, stream)
	}
}

func (p *Protocol) proxyAgentForwardConnection(ctx context.Context, conn cryptossh.Conn, stream ioproxy.HalfCloser) {
	channel, requests, err := conn.OpenChannel(sshprotocol.ChannelAgent, nil)
	if err != nil {
		_ = stream.Close()
		slog.WarnContext(ctx, "open auth-agent channel failed", "err", err)
		return
	}
	go cryptossh.DiscardRequests(requests)
	_ = ioproxy.ProxyWithObserver(
		ctx,
		channel,
		stream,
		p.metrics,
		metrics.StreamKindAgentForward,
		metrics.StreamDirectionClientToBackend,
		metrics.StreamDirectionBackendToClient,
	)
}

func (f *sessionAgentForward) Close() {
	f.closeOnce.Do(func() {
		f.closing.Store(true)
		_ = f.forward.Close()
		<-f.done
	})
}
