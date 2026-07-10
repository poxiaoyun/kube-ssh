package server

import (
	"log/slog"
	"sync"
	"sync/atomic"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
	sshAuthSockEnv   = "SSH_AUTH_SOCK"
)

type agentForwardSession interface {
	AgentForward() backend.AgentForward
}

type sessionAgentForward struct {
	forward backend.AgentForward
	sc      *sessionContext
	spec    operationSpec
	finish  func(string)
	done    chan struct{}

	closeOnce sync.Once
	closing   atomic.Bool
}

func (s *Server) acceptAgentForward(ctx gossh.Context, conn *cryptossh.ServerConn) (*sessionAgentForward, bool) {
	sc, err := s.newConnectionContext(ctx)
	if err != nil {
		slog.WarnContext(ctx, "agent forwarding context failed", "err", err)
		return nil, false
	}

	spec := agentForwardOperationSpec(sc)
	finishOperation := s.startOperation(sc, spec)
	if !SessionPolicyFromContext(ctx).AgentForwarding {
		sc.audit.Type = spec.name + "_denied"
		sc.audit.Fields["capability"] = string(spec.capability)
		sc.audit.Fields["decision"] = string(authz.DecisionDeny)
		sc.audit.Fields["reason"] = "agent forwarding disabled"
		s.audit.Record(ctx, sc.audit)
		finishOperation(metrics.ResultDenied)
		return nil, false
	}

	reason, allowed := s.authorizeOperation(sc, spec)
	if !allowed {
		s.audit.Record(ctx, sc.audit)
		finishOperation(metrics.ResultDenied)
		slog.WarnContext(ctx, "agent forwarding denied", append(operationLogFields(sc, spec), "reason", reason)...)
		return nil, false
	}

	forward, err := s.backend.AgentForward(sc.ctx, backend.AgentForwardRequest{Target: sc.target})
	if err != nil {
		sc.audit.Type = spec.name + "_error"
		sc.audit.Fields["error"] = err.Error()
		s.audit.Record(ctx, sc.audit)
		finishOperation(metrics.ResultError)
		slog.ErrorContext(ctx, "agent forwarding failed", append(operationLogFields(sc, spec), "err", err)...)
		return nil, false
	}

	state := &sessionAgentForward{
		forward: forward,
		sc:      sc,
		spec:    spec,
		finish:  finishOperation,
		done:    make(chan struct{}),
	}
	sc.audit.Type = spec.name + "_start"
	sc.audit.Fields["socket_path"] = forward.SocketPath()
	s.audit.Record(ctx, sc.audit)
	slog.InfoContext(ctx, "agent forwarding start", append(operationLogFields(sc, spec), "socket_path", forward.SocketPath())...)

	go s.serveAgentForward(ctx, conn, state)
	return state, true
}

func (s *Server) serveAgentForward(ctx gossh.Context, conn *cryptossh.ServerConn, state *sessionAgentForward) {
	result := metrics.ResultSuccess
	defer func() {
		state.sc.audit.Type = state.spec.name + "_end"
		s.audit.Record(ctx, state.sc.audit)
		state.finish(result)
		close(state.done)
	}()

	for {
		stream, err := state.forward.Accept(ctx)
		if err != nil {
			if state.closing.Load() || ctx.Err() != nil {
				result = metrics.ResultSuccess
			} else {
				result = resultFromError(err)
				if result == metrics.ResultError {
					slog.ErrorContext(ctx, "agent forwarding accept failed", append(operationLogFields(state.sc, state.spec), "err", err)...)
				}
			}
			return
		}
		go s.proxyAgentForwardConnection(ctx, conn, stream)
	}
}

func (s *Server) proxyAgentForwardConnection(ctx gossh.Context, conn *cryptossh.ServerConn, stream ioproxy.HalfCloser) {
	ch, reqs, err := conn.OpenChannel(agentChannelType, nil)
	if err != nil {
		_ = stream.Close()
		slog.WarnContext(ctx, "open auth-agent channel failed", "err", err)
		return
	}
	go cryptossh.DiscardRequests(reqs)
	_ = ioproxy.ProxyWithObserver(
		ctx,
		ch,
		stream,
		s.metricsRecorder(),
		metrics.StreamKindAgentForward,
		metrics.StreamDirectionClientToBackend,
		metrics.StreamDirectionBackendToClient,
	)
}

func (f *sessionAgentForward) Close() {
	if f == nil || f.forward == nil {
		return
	}
	f.closeOnce.Do(func() {
		f.closing.Store(true)
		_ = f.forward.Close()
		<-f.done
	})
}

func agentForwardOperationSpec(sc *sessionContext) operationSpec {
	return operationSpec{
		name:       "agent_forward",
		capability: authz.CapabilityAgentForward,
		attrs: authz.Attributes{
			Action:    string(authz.CapabilityAgentForward),
			Resources: targetResources(*sc.target),
			Path:      sc.target.ToPath() + "/agent-forward",
		},
	}
}
