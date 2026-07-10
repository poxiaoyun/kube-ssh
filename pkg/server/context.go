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
	policyConnKey          contextKey = "policy-conn"
)

func WithAuthenticate(ctx gossh.Context, info authn.AuthenticateInfo) {
	ctx.SetValue(authenticateContextKey, info)
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

func WithPolicyConn(ctx gossh.Context, conn *policyConn) {
	ctx.SetValue(policyConnKey, conn)
}

func PolicyConnFromContext(ctx gossh.Context) (*policyConn, bool) {
	conn, ok := ctx.Value(policyConnKey).(*policyConn)
	return conn, ok && conn != nil
}

func WithSessionRequestType(ctx gossh.Context, requestType string) {
	ctx.SetValue(requestTypeContextKey, requestType)
}

func SessionRequestTypeFromContext(ctx gossh.Context) string {
	requestType, _ := ctx.Value(requestTypeContextKey).(string)
	return requestType
}
