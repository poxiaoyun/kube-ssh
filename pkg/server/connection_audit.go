package server

import (
	"net"
	"time"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

// connectionAuditState carries correlation data across callbacks belonging to
// one SSH connection.
type connectionAuditState struct {
	id      string
	started time.Time
}

func (s *Server) startConnectionAudit(ctx gossh.Context, conn net.Conn) func() {
	state := &connectionAuditState{id: audit.NewID(), started: time.Now()}
	withConnectionAudit(ctx, state)
	event := s.connectionEvent(ctx, state, "connection.start")
	if conn != nil {
		event.Connection.RemoteAddress = addressString(conn.RemoteAddr())
		event.Connection.LocalAddress = addressString(conn.LocalAddr())
	}
	s.audit.Record(ctx, event)
	return func() {
		result := "rejected"
		if _, ok := AuthenticateFromContext(ctx); ok {
			result = "success"
		}
		end := s.connectionEvent(ctx, state, "connection.end")
		end.Outcome = &audit.Outcome{Result: result, DurationMS: time.Since(state.started).Milliseconds()}
		s.audit.Record(ctx, end)
	}
}

func (s *Server) connectionEvent(ctx gossh.Context, state *connectionAuditState, eventType string) audit.Event {
	event := audit.NewEvent(eventType)
	event.Connection = &audit.Connection{
		SSHUsername:   contextString(ctx, gossh.ContextKeyUser),
		RemoteAddress: contextAddress(ctx, gossh.ContextKeyRemoteAddr),
		LocalAddress:  contextAddress(ctx, gossh.ContextKeyLocalAddr),
		ClientVersion: contextString(ctx, gossh.ContextKeyClientVersion),
		ServerVersion: contextString(ctx, gossh.ContextKeyServerVersion),
	}
	if state == nil {
		return event
	}
	event.Correlation.ConnectionID = state.id
	if info, ok := AuthenticateFromContext(ctx); ok {
		event.Actor = auditActor(info, AuditFingerprintFromContext(ctx))
		event.Access = auditAccess(info)
	}
	if tgt, ok := TargetFromContext(ctx); ok {
		event.Target = auditTarget(tgt)
	}
	return event
}

func (s *Server) recordAuthentication(ctx gossh.Context, method, fingerprint, result string, info *authn.AuthenticateInfo, err error) {
	event := s.connectionEvent(ctx, connectionAuditFromContext(ctx), "authentication.result")
	event.Outcome = &audit.Outcome{Result: result}
	if err != nil {
		event.Outcome.Reason = "authentication rejected"
	}
	if info != nil {
		event.Actor = auditActor(*info, fingerprint)
		event.Access = auditAccess(*info)
	}
	if event.Actor == nil {
		event.Actor = &audit.Actor{AuthenticationMethod: method, PublicKeyFingerprint: fingerprint}
	}
	s.audit.Record(ctx, event)
}

func addressString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func contextString(ctx gossh.Context, key any) string {
	value, _ := ctx.Value(key).(string)
	return value
}

func contextAddress(ctx gossh.Context, key any) string {
	value, _ := ctx.Value(key).(net.Addr)
	return addressString(value)
}
