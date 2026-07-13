package server

import (
	"log/slog"
	"strconv"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

type directTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *Server) handleDirectTCPIP(_ *gossh.Server, _ *cryptossh.ServerConn, newChan cryptossh.NewChannel, ctx gossh.Context) {
	data := directTCPIPData{}
	if err := cryptossh.Unmarshal(newChan.ExtraData(), &data); err != nil {
		_ = newChan.Reject(cryptossh.ConnectionFailed, "error parsing direct-tcpip data: "+err.Error())
		return
	}

	sc, err := s.newConnectionContext(ctx)
	if err != nil {
		_ = newChan.Reject(cryptossh.Prohibited, err.Error())
		return
	}

	spec := directTCPIPOperationSpec(sc, data)
	finishOperation := s.startOperation(sc, spec)
	reason, allowed := s.authorizeOperation(sc, spec)
	if !allowed {
		finishOperation(metrics.ResultDenied)
		_ = newChan.Reject(cryptossh.Prohibited, reason)
		return
	}

	remote, err := s.backend.PortForward(sc.ctx, backend.PortForwardRequest{
		Target: sc.target,
		Host:   data.DestAddr,
		Port:   data.DestPort,
	})
	if err != nil {
		sc.audit.Type = spec.name + "_error"
		sc.audit.Fields["error"] = err.Error()
		finishOperation(metrics.ResultError)
		_ = newChan.Reject(cryptossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = remote.Close()
		finishOperation(metrics.ResultError)
		return
	}
	go cryptossh.DiscardRequests(reqs)

	slog.InfoContext(ctx, spec.name+" start", operationLogFields(sc, spec)...)
	proxyErr := ioproxy.ProxyWithObserver(
		sc.ctx,
		ch,
		remote,
		s.metricsRecorder(),
		metrics.StreamKindDirectTCPIP,
		metrics.StreamDirectionClientToBackend,
		metrics.StreamDirectionBackendToClient,
	)
	sc.audit.Type = spec.name + "_end"
	if proxyErr != nil {
		sc.audit.Fields["error"] = proxyErr.Error()
		slog.ErrorContext(ctx, spec.name+" error", append(operationLogFields(sc, spec), "err", proxyErr)...)
	} else {
		slog.InfoContext(ctx, spec.name+" end", operationLogFields(sc, spec)...)
	}
	finishOperation(resultFromError(proxyErr))
}

func directTCPIPOperationSpec(sc *sessionContext, data directTCPIPData) operationSpec {
	destPort := strconv.FormatUint(uint64(data.DestPort), 10)
	originPort := strconv.FormatUint(uint64(data.OriginPort), 10)
	return operationSpec{
		name:       "portforward",
		capability: authz.CapabilityLocalForward,
		attrs: authz.Attributes{
			Action: string(authz.CapabilityLocalForward),
			Resources: append(targetResources(*sc.target),
				authz.AttributeResource{Resource: "hosts", Name: data.DestAddr},
				authz.AttributeResource{Resource: "ports", Name: destPort},
			),
			// Path includes host so authorizers can apply per-host policies
			// (e.g. allow only localhost/127.0.0.1 for Pod-self ports).
			Path: sc.target.ToPath() + "/hosts/" + data.DestAddr + "/ports/" + destPort,
			Extra: map[string][]string{
				"destination_host": {data.DestAddr},
				"destination_port": {destPort},
				"origin_host":      {data.OriginAddr},
				"origin_port":      {originPort},
			},
		},
		auditFields: map[string]string{
			"destination_host": data.DestAddr,
			"destination_port": destPort,
			"origin_host":      data.OriginAddr,
			"origin_port":      originPort,
		},
	}
}
