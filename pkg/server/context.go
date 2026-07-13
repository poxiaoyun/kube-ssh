package server

import (
	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type contextKey string

const (
	authenticateContextKey contextKey = "authenticate"
	targetContextKey       contextKey = "target"
	requestTypeContextKey  contextKey = "request-type"
	sessionPolicyKey       contextKey = "session-policy"
	sessionPolicyConnKey   contextKey = "session-policy-conn"
	connectionAuditKey     contextKey = "connection-audit"
	auditFingerprintKey    contextKey = "audit-public-key-fingerprint"
)

func WithAuthenticate(ctx gossh.Context, info authn.AuthenticateInfo) {
	ctx.SetValue(authenticateContextKey, info)
}

func WithAuditFingerprint(ctx gossh.Context, fingerprint string) {
	ctx.SetValue(auditFingerprintKey, fingerprint)
}

func AuditFingerprintFromContext(ctx gossh.Context) string {
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

func AuthenticateFromContext(ctx gossh.Context) (authn.AuthenticateInfo, bool) {
	info, ok := ctx.Value(authenticateContextKey).(authn.AuthenticateInfo)
	return info, ok
}

func WithTarget(ctx gossh.Context, tgt *target.Target) {
	ctx.SetValue(targetContextKey, tgt)
}

func TargetFromContext(ctx gossh.Context) (*target.Target, bool) {
	tgt, ok := ctx.Value(targetContextKey).(*target.Target)
	return tgt, ok
}

func WithSessionPolicy(ctx gossh.Context, policy effectiveSessionPolicy) {
	ctx.SetValue(sessionPolicyKey, policy)
}

func SessionPolicyFromContext(ctx gossh.Context) effectiveSessionPolicy {
	policy, ok := ctx.Value(sessionPolicyKey).(effectiveSessionPolicy)
	if !ok {
		return buildGlobalSessionPolicy(nil)
	}
	return policy
}

func withSessionPolicyConn(ctx gossh.Context, conn *sessionPolicyConn) {
	ctx.SetValue(sessionPolicyConnKey, conn)
}

func sessionPolicyConnFromContext(ctx gossh.Context) (*sessionPolicyConn, bool) {
	conn, ok := ctx.Value(sessionPolicyConnKey).(*sessionPolicyConn)
	return conn, ok && conn != nil
}

func WithSessionRequestType(ctx gossh.Context, requestType string) {
	ctx.SetValue(requestTypeContextKey, requestType)
}

func SessionRequestTypeFromContext(ctx gossh.Context) string {
	requestType, _ := ctx.Value(requestTypeContextKey).(string)
	return requestType
}
