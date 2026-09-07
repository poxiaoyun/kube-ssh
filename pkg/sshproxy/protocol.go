package sshproxy

import (
	"context"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// Protocol adapts a complete upstream SSH connection to the connection-level
// SSH protocol seam. It must be constructed with NewProtocol.
type Protocol struct {
	ctx       context.Context
	connector ConnectionConnector
	target    *target.Target
	begin     sshprotocol.BeginOperationFunc
	env       func(key string) bool

	mu     sync.Mutex
	closed bool
	proxy  *proxy
}

// NewProtocol creates an SSH Proxy protocol adapter. The upstream
// connection is established lazily when the first protocol message arrives.
func NewProtocol(
	ctx context.Context,
	tgt *target.Target,
	connector ConnectionConnector,
	begin sshprotocol.BeginOperationFunc,
	envAllowed func(key string) bool,
) *Protocol {
	return &Protocol{ctx: ctx, connector: connector, target: tgt, begin: begin, env: envAllowed}
}

// HandleChannel forwards one downstream channel to the upstream SSH server.
func (p *Protocol) HandleChannel(conn cryptossh.Conn, newChannel cryptossh.NewChannel) {
	proxy := p.connectionProxy(conn)
	if proxy == nil {
		_ = newChannel.Reject(cryptossh.ConnectionFailed, "SSH connection is closed")
		return
	}
	proxy.handleChannel(newChannel)
}

// HandleGlobalRequest forwards one downstream global request to the upstream SSH server.
func (p *Protocol) HandleGlobalRequest(conn cryptossh.Conn, request *cryptossh.Request) (bool, []byte) {
	proxy := p.connectionProxy(conn)
	if proxy == nil {
		return false, nil
	}
	return proxy.handleRequest(request)
}

func (p *Protocol) connectionProxy(conn cryptossh.Conn) *proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.proxy == nil {
		p.proxy = newProxy(p.ctx, conn, p.connector, p.target, p.begin, p.env)
	}
	return p.proxy
}

// Close closes the lazily created connection proxy and both SSH transports.
func (p *Protocol) Close() {
	p.mu.Lock()
	p.closed = true
	proxy := p.proxy
	p.proxy = nil
	p.mu.Unlock()
	if proxy != nil {
		proxy.close()
	}
}
