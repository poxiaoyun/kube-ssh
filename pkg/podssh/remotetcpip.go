package podssh

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

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

func (p *Protocol) handleTCPIPForward(conn cryptossh.Conn, request *cryptossh.Request) (bool, []byte) {
	data := remoteForwardRequest{}
	if err := cryptossh.Unmarshal(request.Payload, &data); err != nil {
		slog.WarnContext(p.ctx, "parse tcpip-forward request failed", "err", err)
		return false, nil
	}
	operation := sshprotocol.Operation{RequestType: sshprotocol.RequestTCPIPForward, BindHost: data.BindAddr, BindPort: data.BindPort}
	finish, err := p.begin(operation)
	if err != nil {
		if finish != nil {
			finish(sshprotocol.OperationResult{})
		}
		slog.WarnContext(p.ctx, "tcpip-forward denied", "reason", err)
		return false, nil
	}

	forward, err := p.backend.RemoteForward(p.ctx, backend.RemoteForwardRequest{
		Target:   p.target,
		BindHost: data.BindAddr,
		BindPort: data.BindPort,
	})
	if err != nil {
		finish(sshprotocol.OperationResult{Err: err})
		slog.ErrorContext(p.ctx, "tcpip-forward failed", "err", err)
		return false, nil
	}

	actualPort := forward.ActualPort()
	bind := newRemoteForwardBind(data.BindAddr, actualPort)
	if !p.forwards.AddRemoteForward(bind, forward) {
		_ = forward.Close()
		err := errors.New("remote forward already exists")
		finish(sshprotocol.OperationResult{Err: err})
		return false, nil
	}

	slog.InfoContext(p.ctx, "remote forward start", "bind_host", data.BindAddr, "bind_port", data.BindPort, "actual_port", actualPort)
	go p.serveRemoteForward(conn, bind, data.BindAddr, actualPort, forward, finish)
	return true, cryptossh.Marshal(&remoteForwardSuccess{BindPort: actualPort})
}

func (p *Protocol) handleCancelTCPIPForward(request *cryptossh.Request) (bool, []byte) {
	data := remoteForwardRequest{}
	if err := cryptossh.Unmarshal(request.Payload, &data); err != nil {
		slog.WarnContext(p.ctx, "parse cancel-tcpip-forward request failed", "err", err)
		return false, nil
	}
	bind := newRemoteForwardBind(data.BindAddr, data.BindPort)
	if forward, ok := p.forwards.RemoveRemoteForward(bind); ok {
		if err := forward.Cancel(); err != nil {
			slog.WarnContext(p.ctx, "remote forward cancel failed", "err", err)
			_ = forward.Close()
		}
	}
	slog.InfoContext(p.ctx, "remote forward cancel", "bind_host", data.BindAddr, "bind_port", data.BindPort)
	return true, nil
}

func (p *Protocol) serveRemoteForward(
	conn cryptossh.Conn,
	bind remoteForwardBind,
	bindHost string,
	bindPort uint32,
	forward backend.RemoteForward,
	finish sshprotocol.FinishOperation,
) {
	var result sshprotocol.OperationResult
	result.ActualBindPort = &bindPort
	defer func() {
		if current, ok := p.forwards.RemoveRemoteForward(bind); ok {
			_ = current.Close()
		}
		finish(result)
	}()

	for {
		stream, info, err := forward.Accept(p.ctx)
		if err != nil {
			if p.ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			result.Err = err
			slog.ErrorContext(p.ctx, "remote forward accept failed", "err", err)
			return
		}
		go p.proxyRemoteForwardConnection(conn, stream, info, bindHost, bindPort)
	}
}

func (p *Protocol) proxyRemoteForwardConnection(
	conn cryptossh.Conn,
	stream ioproxy.HalfCloser,
	info backend.RemoteForwardConnInfo,
	bindHost string,
	bindPort uint32,
) {
	payload := cryptossh.Marshal(&remoteForwardChannelData{
		DestAddr:   bindHost,
		DestPort:   bindPort,
		OriginAddr: info.OriginHost,
		OriginPort: info.OriginPort,
	})
	channel, requests, err := conn.OpenChannel(sshprotocol.ChannelForwardedTCPIP, payload)
	if err != nil {
		_ = stream.Close()
		slog.WarnContext(p.ctx, "open forwarded-tcpip failed", "err", err)
		return
	}
	go cryptossh.DiscardRequests(requests)
	_ = ioproxy.ProxyWithObserver(
		p.ctx,
		channel,
		stream,
		p.metrics,
		metrics.StreamKindRemoteForward,
		metrics.StreamDirectionClientToBackend,
		metrics.StreamDirectionBackendToClient,
	)
}

func newRemoteForwardBind(host string, port uint32) remoteForwardBind {
	return remoteForwardBind(net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
}
