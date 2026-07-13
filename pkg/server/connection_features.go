package server

import (
	"net"
	"sync"

	gossh "github.com/gliderlabs/ssh"
)

// connectionFeature adds one independent behavior to an accepted connection.
// Features are applied in declaration order, with each feature wrapping the
// connection returned by the previous one.
type connectionFeature func(gossh.Context, net.Conn) net.Conn

func applyConnectionFeatures(ctx gossh.Context, conn net.Conn, features ...connectionFeature) net.Conn {
	for _, feature := range features {
		if feature != nil {
			conn = feature(ctx, conn)
		}
	}
	return conn
}

func (s *Server) connectionFeatures() []connectionFeature {
	return []connectionFeature{
		s.auditConnectionFeature,
		s.sessionPolicyConnectionFeature,
	}
}

func (s *Server) auditConnectionFeature(ctx gossh.Context, conn net.Conn) net.Conn {
	return newCloseNotifyConn(conn, s.startConnectionAudit(ctx, conn))
}

func (s *Server) sessionPolicyConnectionFeature(ctx gossh.Context, conn net.Conn) net.Conn {
	policyConn := newSessionPolicyConn(conn, buildGlobalSessionPolicy(s.opts))
	withSessionPolicyConn(ctx, policyConn)
	return policyConn
}

// closeNotifyConn reports the end of a connection without coupling the owner
// of the callback to another connection feature.
type closeNotifyConn struct {
	net.Conn
	onClose func()

	closeOnce sync.Once
	closeErr  error
}

func newCloseNotifyConn(conn net.Conn, onClose func()) *closeNotifyConn {
	return &closeNotifyConn{Conn: conn, onClose: onClose}
}

func (c *closeNotifyConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.closeErr
}
