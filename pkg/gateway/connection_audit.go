package gateway

import (
	"net"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
)

// connectionAuditState carries correlation data across callbacks belonging to
// one SSH connection.
type connectionAuditState struct {
	id      string
	started time.Time
}

func (s *gateway) startConnectionAudit(ctx *connectionState) func() {
	state := &connectionAuditState{id: audit.NewID(), started: time.Now()}
	ctx.audit = state
	event := s.connectionEvent(ctx, "connection.start")

	s.audit.Record(ctx, event)
	return func() {
		result := "rejected"
		if ctx.snapshot().established {
			result = "success"
		}
		end := s.connectionEvent(ctx, "connection.end")
		end.Outcome = &audit.Outcome{
			Result: result,
			DurationMS: time.
				Since(state.started).
				Milliseconds(),
		}
		s.audit.Record(ctx, end)
	}
}

func (s *gateway) connectionEvent(ctx *connectionState, eventType string) audit.Event {
	event := audit.NewEvent(eventType)
	snapshot := ctx.snapshot()
	meta := snapshot.metadata
	event.Connection = &audit.Connection{
		SSHUsername: meta.user, RemoteAddress: addressString(meta.remote), LocalAddress: addressString(meta.local), ClientVersion: meta.clientVersion, ServerVersion: meta.serverVersion,
	}

	event.Correlation.ConnectionID = ctx.audit.id
	if result := snapshot.authenticated; result != nil {
		event.Actor = auditActor(result.info, result.fingerprint)
		event.Access = auditAccess(result.info)
		event.Target = auditTarget(result.target)
	}
	return event
}

func (s *gateway) recordAuthentication(ctx *connectionState, method, fingerprint, result string, info *authn.AuthenticateInfo, err error) {
	event := s.connectionEvent(ctx, "authentication.result")
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
