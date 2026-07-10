package server

import (
	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
)

func (s *Server) handleSFTP(sess gossh.Session) {
	s.handleStreamOperation(sess, s.resolveSFTP, func(sc *sessionContext) (int, error) {
		return s.backend.SFTP(sc.ctx, backend.StreamRequest{
			Target: sc.target,
			Stdin:  sc.session,
			Stdout: sc.session,
			Stderr: sc.session.Stderr(),
		})
	})
}

func (s *Server) resolveSFTP(sc *sessionContext) (operationSpec, error) {
	return operationSpec{
		name:       "sftp",
		capability: authz.CapabilitySFTP,
		attrs: authz.Attributes{
			Action:    string(authz.CapabilitySFTP),
			Resources: targetResources(*sc.target),
			Path:      sc.target.ToPath(),
		},
	}, nil
}
