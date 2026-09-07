package podssh

import (
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
)

type directTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

func (s *Protocol) handleDirectTCPIP(newChan cryptossh.NewChannel) {
	data := directTCPIPData{}
	if err := cryptossh.Unmarshal(newChan.ExtraData(), &data); err != nil {
		_ = newChan.Reject(cryptossh.ConnectionFailed, "error parsing direct-tcpip data: "+err.Error())
		return
	}

	operation := sshprotocol.Operation{
		ChannelType:     sshprotocol.ChannelDirectTCPIP,
		DestinationHost: data.DestAddr,
		DestinationPort: data.DestPort,
		OriginHost:      data.OriginAddr,
		OriginPort:      data.OriginPort,
	}
	finish, err := s.begin(operation)
	if err != nil {
		if finish != nil {
			finish(sshprotocol.OperationResult{})
		}
		_ = newChan.Reject(cryptossh.Prohibited, err.Error())
		return
	}

	remote, err := s.backend.PortForward(s.ctx, backend.PortForwardRequest{
		Target: s.target,
		Host:   data.DestAddr,
		Port:   data.DestPort,
	})
	if err != nil {
		finish(sshprotocol.OperationResult{Err: err})
		_ = newChan.Reject(cryptossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = remote.Close()
		finish(sshprotocol.OperationResult{Err: err})
		return
	}
	go cryptossh.DiscardRequests(reqs)

	proxyErr := ioproxy.ProxyWithObserver(
		s.ctx,
		ch,
		remote,
		s.metrics,
		metrics.StreamKindDirectTCPIP,
		metrics.StreamDirectionClientToBackend,
		metrics.StreamDirectionBackendToClient,
	)
	finish(sshprotocol.OperationResult{Err: proxyErr})
}
