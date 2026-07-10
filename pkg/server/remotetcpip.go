package server

import (
	"log/slog"
	"net"
	"strconv"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

const forwardedTCPChannelType = "forwarded-tcpip"

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type remoteForwardBind string

func (s *Server) handleTCPIPForward(ctx gossh.Context, _ *gossh.Server, req *cryptossh.Request) (bool, []byte) {
	data := remoteForwardRequest{}
	if err := cryptossh.Unmarshal(req.Payload, &data); err != nil {
		slog.WarnContext(ctx, "parse tcpip-forward request failed", "err", err)
		return false, nil
	}
	conn, ok := ctx.Value(gossh.ContextKeyConn).(*cryptossh.ServerConn)
	if !ok || conn == nil {
		slog.WarnContext(ctx, "tcpip-forward missing ssh connection")
		return false, nil
	}

	sc, err := s.newConnectionContext(ctx)
	if err != nil {
		slog.WarnContext(ctx, "tcpip-forward context failed", "err", err)
		return false, nil
	}

	spec := remoteForwardOperationSpec(sc, data.BindAddr, data.BindPort)
	finishOperation := s.startOperation(sc, spec)
	reason, allowed := s.authorizeOperation(sc, spec)
	if !allowed {
		s.audit.Record(ctx, sc.audit)
		finishOperation(metrics.ResultDenied)
		slog.WarnContext(ctx, "tcpip-forward denied", append(operationLogFields(sc, spec), "reason", reason)...)
		return false, nil
	}

	forward, err := s.backend.RemoteForward(sc.ctx, backend.RemoteForwardRequest{
		Target:   sc.target,
		BindHost: data.BindAddr,
		BindPort: data.BindPort,
	})
	if err != nil {
		sc.audit.Type = spec.name + "_error"
		sc.audit.Fields["error"] = err.Error()
		s.audit.Record(ctx, sc.audit)
		finishOperation(metrics.ResultError)
		slog.ErrorContext(ctx, "tcpip-forward failed", append(operationLogFields(sc, spec), "err", err)...)
		return false, nil
	}

	actualPort := forward.ActualPort()
	state := s.getClientState(ctx, conn)
	bind := newRemoteForwardBind(data.BindAddr, actualPort)
	if !state.AddRemoteForward(bind, forward) {
		_ = forward.Close()
		sc.audit.Type = spec.name + "_error"
		sc.audit.Fields["error"] = "remote forward already exists"
		s.audit.Record(ctx, sc.audit)
		finishOperation(metrics.ResultDuplicate)
		return false, nil
	}

	sc.audit.Type = spec.name + "_start"
	sc.audit.Fields["actual_port"] = strconv.FormatUint(uint64(actualPort), 10)
	s.audit.Record(ctx, sc.audit)
	slog.InfoContext(ctx, "remote forward start", append(operationLogFields(sc, spec), "actual_port", actualPort)...)

	go s.serveRemoteForward(ctx, conn, state, bind, data.BindAddr, actualPort, forward, sc, spec, finishOperation)
	return true, cryptossh.Marshal(&remoteForwardSuccess{BindPort: actualPort})
}

func (s *Server) handleCancelTCPIPForward(ctx gossh.Context, _ *gossh.Server, req *cryptossh.Request) (bool, []byte) {
	data := remoteForwardRequest{}
	if err := cryptossh.Unmarshal(req.Payload, &data); err != nil {
		slog.WarnContext(ctx, "parse cancel-tcpip-forward request failed", "err", err)
		return false, nil
	}
	conn, ok := ctx.Value(gossh.ContextKeyConn).(*cryptossh.ServerConn)
	if !ok || conn == nil {
		return false, nil
	}

	if state := s.findClientState(conn); state != nil {
		bind := newRemoteForwardBind(data.BindAddr, data.BindPort)
		if forward, ok := state.RemoveRemoteForward(bind); ok {
			if err := forward.Cancel(); err != nil {
				slog.WarnContext(ctx, "remote forward cancel failed", "err", err)
				_ = forward.Close()
			}
		}
	}
	slog.InfoContext(ctx, "remote forward cancel",
		"user", ctx.User(),
		"bind_host", data.BindAddr,
		"bind_port", data.BindPort,
	)
	return true, nil
}

func (s *Server) serveRemoteForward(ctx gossh.Context, conn *cryptossh.ServerConn, state *clientState, bind remoteForwardBind, bindHost string, bindPort uint32, forward backend.RemoteForward, sc *sessionContext, spec operationSpec, finishOperation func(string)) {
	result := metrics.ResultSuccess
	defer func() {
		if f, ok := state.RemoveRemoteForward(bind); ok {
			_ = f.Close()
		}
		sc.audit.Type = spec.name + "_end"
		s.audit.Record(ctx, sc.audit)
		finishOperation(result)
	}()

	for {
		stream, info, err := forward.Accept(ctx)
		if err != nil {
			result = resultFromError(err)
			if ctx.Err() == nil && result == metrics.ResultError {
				slog.ErrorContext(ctx, "remote forward accept failed", append(operationLogFields(sc, spec), "err", err)...)
			}
			return
		}
		go s.proxyRemoteForwardConnection(ctx, conn, stream, info, bindHost, bindPort)
	}
}

func (s *Server) proxyRemoteForwardConnection(ctx gossh.Context, conn *cryptossh.ServerConn, stream ioproxy.HalfCloser, info backend.RemoteForwardConnInfo, bindHost string, bindPort uint32) {
	payload := cryptossh.Marshal(&remoteForwardChannelData{
		DestAddr:   bindHost,
		DestPort:   bindPort,
		OriginAddr: info.OriginHost,
		OriginPort: info.OriginPort,
	})
	ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
	if err != nil {
		_ = stream.Close()
		slog.WarnContext(ctx, "open forwarded-tcpip failed", "err", err)
		return
	}
	go cryptossh.DiscardRequests(reqs)
	_ = ioproxy.Proxy(ctx, ch, stream)
}

func newRemoteForwardBind(host string, port uint32) remoteForwardBind {
	return remoteForwardBind(net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
}

func remoteForwardOperationSpec(sc *sessionContext, bindHost string, bindPort uint32) operationSpec {
	port := strconv.FormatUint(uint64(bindPort), 10)
	return operationSpec{
		name:       "remote_forward",
		capability: authz.CapabilityRemoteForward,
		attrs: authz.Attributes{
			Action: string(authz.CapabilityRemoteForward),
			Resources: append(targetResources(*sc.target),
				authz.AttributeResource{Resource: "bind_hosts", Name: bindHost},
				authz.AttributeResource{Resource: "bind_ports", Name: port},
			),
			Path: sc.target.ToPath() + "/remote-forwards/" + bindHost + "/" + port,
			Extra: map[string][]string{
				"bind_host": {bindHost},
				"bind_port": {port},
			},
		},
		auditFields: map[string]string{
			"bind_host": bindHost,
			"bind_port": port,
		},
	}
}
