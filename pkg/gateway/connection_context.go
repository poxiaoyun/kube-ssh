package gateway

import (
	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type contextKey string

const (
	authenticateContextKey contextKey = "authenticate"
	targetContextKey       contextKey = "target"
	sessionPolicyConnKey   contextKey = "session-policy-conn"
	connectionProtocolKey  contextKey = "connection-protocol"
	connectionAuditKey     contextKey = "connection-audit"
	auditFingerprintKey    contextKey = "audit-public-key-fingerprint"
)

func withAuthenticate(ctx gossh.Context, info authn.AuthenticateInfo) {
	ctx.SetValue(authenticateContextKey, info)
}

func withAuditFingerprint(ctx gossh.Context, fingerprint string) {
	ctx.SetValue(auditFingerprintKey, fingerprint)
}

func auditFingerprintFromContext(ctx gossh.Context) string {
	fingerprint, _ := ctx.Value(auditFingerprintKey).(string)
	return fingerprint
}

func withConnectionAudit(ctx gossh.Context, state *connectionAuditState) {
	ctx.SetValue(connectionAuditKey, state)
}

func connectionAuditFromContext(ctx gossh.Context) *connectionAuditState {
	state, _ := ctx.Value(connectionAuditKey).(*connectionAuditState)
	return state
}

func authenticateFromContext(ctx gossh.Context) (authn.AuthenticateInfo, bool) {
	info, ok := ctx.Value(authenticateContextKey).(authn.AuthenticateInfo)
	return info, ok
}

func withTarget(ctx gossh.Context, tgt *target.Target) {
	ctx.SetValue(targetContextKey, tgt)
}

func targetFromContext(ctx gossh.Context) (*target.Target, bool) {
	tgt, ok := ctx.Value(targetContextKey).(*target.Target)
	return tgt, ok
}

func withConnectionProtocol(ctx gossh.Context, protocol sshprotocol.ConnectionProtocol) {
	ctx.SetValue(connectionProtocolKey, protocol)
}

func connectionProtocolFromContext(ctx gossh.Context) sshprotocol.ConnectionProtocol {
	return ctx.Value(connectionProtocolKey).(sshprotocol.ConnectionProtocol)
}

func withSessionPolicyConn(ctx gossh.Context, conn *sessionPolicyConn) {
	ctx.SetValue(sessionPolicyConnKey, conn)
}

func sessionPolicyConnFromContext(ctx gossh.Context) (*sessionPolicyConn, bool) {
	conn, ok := ctx.Value(sessionPolicyConnKey).(*sessionPolicyConn)
	return conn, ok && conn != nil
}
