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

func WithSessionRequestType(ctx gossh.Context, requestType string) {
	ctx.SetValue(requestTypeContextKey, requestType)
}

func SessionRequestTypeFromContext(ctx gossh.Context) string {
	requestType, _ := ctx.Value(requestTypeContextKey).(string)
	return requestType
}
