package gateway

import (
	"context"
	"net"
	"sync"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// connectionState publishes authentication as one immutable result. Operations
// and audit readers take a coherent snapshot instead of reading separate fields.
type connectionState struct {
	context.Context
	mu            sync.RWMutex
	metadata      connectionMetadata
	authenticated *authenticatedConnection
	established   bool

	// Installed by the connection owner before authentication starts.
	audit      *connectionAuditState
	policyConn *sessionPolicyConn
}

type authenticatedConnection struct {
	info        authn.AuthenticateInfo
	target      *target.Target
	fingerprint string
	protocol    sshprotocol.ConnectionProtocol
}

type connectionMetadata struct {
	user, clientVersion, serverVersion string
	remote, local                      net.Addr
}

type connectionSnapshot struct {
	metadata      connectionMetadata
	authenticated *authenticatedConnection
	established   bool
}

func (c *connectionState) snapshot() connectionSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return connectionSnapshot{metadata: c.metadata, authenticated: c.authenticated, established: c.established}
}

func (c *connectionState) setMetadata(conn cryptossh.ConnMetadata) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metadata = connectionMetadata{
		user: conn.User(), clientVersion: string(conn.ClientVersion()), serverVersion: string(conn.ServerVersion()),
		remote: conn.RemoteAddr(), local: conn.LocalAddr(),
	}
}

func (c *connectionState) publishAuthenticated(result authenticatedConnection) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authenticated = &result
}

func (c *connectionState) markEstablished() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.established = true
}

func (c *connectionState) User() string         { return c.snapshot().metadata.user }
func (c *connectionState) RemoteAddr() net.Addr { return c.snapshot().metadata.remote }
