// Package podssh implements SSH operations for Pod targets without a target-side sshd.
package podssh

import (
	"context"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// Protocol terminates SSH protocol messages and executes accepted operations
// through the Pod backend.
type Protocol struct {
	ctx          context.Context
	target       *target.Target
	backend      backend.Backend
	begin        sshprotocol.BeginOperationFunc
	metrics      metrics.StreamRecorder
	defaultShell string
	envAllowed   func(key string) bool
	forwards     *clientState
}

// NewProtocol creates a Pod SSH adapter for one authenticated connection.
func NewProtocol(
	ctx context.Context,
	tgt *target.Target,
	operationBackend backend.Backend,
	begin sshprotocol.BeginOperationFunc,
	recorder metrics.StreamRecorder,
	defaultShell string,
	envAllowed func(key string) bool,
) *Protocol {
	return &Protocol{
		ctx:          ctx,
		target:       tgt,
		backend:      operationBackend,
		begin:        begin,
		metrics:      recorder,
		defaultShell: defaultShell,
		envAllowed:   envAllowed,
		forwards:     newClientState(),
	}
}

// HandleChannel accepts supported Pod SSH channels and rejects all others.
func (p *Protocol) HandleChannel(conn cryptossh.Conn, channel cryptossh.NewChannel) {
	switch channel.ChannelType() {
	case sshprotocol.ChannelSession:
		p.handleSessionChannel(conn, channel)
	case sshprotocol.ChannelDirectTCPIP:
		p.handleDirectTCPIP(channel)
	default:
		_ = channel.Reject(cryptossh.UnknownChannelType, "unsupported channel type")
	}
}

// HandleGlobalRequest executes supported Pod SSH global requests.
func (p *Protocol) HandleGlobalRequest(conn cryptossh.Conn, request *cryptossh.Request) (bool, []byte) {
	switch request.Type {
	case sshprotocol.RequestTCPIPForward:
		return p.handleTCPIPForward(conn, request)
	case sshprotocol.RequestCancelTCPIPForward:
		return p.handleCancelTCPIPForward(request)
	default:
		return false, nil
	}
}

// Close releases all remote forwards owned by the connection.
func (p *Protocol) Close() {
	p.forwards.Close()
}
