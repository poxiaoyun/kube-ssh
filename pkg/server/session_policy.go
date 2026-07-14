package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/util/pattern"
)

type accessSessionPolicyGetter interface {
	Get(ctx context.Context, namespace, name string) (*sshv1.Access, error)
}

type effectiveSessionPolicy struct {
	DefaultShell string

	globalEnvAllowlist  []string
	accessEnvAllowlist  []string
	accessEnvConfigured bool

	IdleTimeout time.Duration
	MaxDuration time.Duration
}

func buildGlobalSessionPolicy(opts *Options) effectiveSessionPolicy {
	if opts == nil {
		opts = NewDefaultOptions()
	}
	return effectiveSessionPolicy{
		DefaultShell:        opts.Policy.Defaults.DefaultShell,
		globalEnvAllowlist:  append([]string(nil), opts.Policy.Limits.EnvAllowlist...),
		accessEnvAllowlist:  append([]string(nil), opts.Policy.Defaults.EnvAllowlist...),
		accessEnvConfigured: true,
		IdleTimeout:         boundedDuration(opts.Policy.Defaults.IdleTimeout, opts.Policy.Limits.IdleTimeout),
		MaxDuration:         boundedDuration(opts.Policy.Defaults.MaxDuration, opts.Policy.Limits.MaxDuration),
	}
}

func buildAccessSessionPolicy(opts *Options, access *sshv1.Access) effectiveSessionPolicy {
	policy := buildGlobalSessionPolicy(opts)
	if access == nil || access.Spec.Session == nil {
		return policy
	}
	session := access.Spec.Session
	if session.DefaultShell != "" {
		policy.DefaultShell = session.DefaultShell
	}
	if session.EnvAllowlist != nil {
		policy.accessEnvConfigured = true
		policy.accessEnvAllowlist = append([]string(nil), session.EnvAllowlist...)
	}
	if session.IdleTimeout != nil {
		if duration := positiveDuration(session.IdleTimeout.Duration); duration > 0 {
			policy.IdleTimeout = boundedDuration(duration, opts.Policy.Limits.IdleTimeout)
		}
	}
	if session.MaxDuration != nil {
		if duration := positiveDuration(session.MaxDuration.Duration); duration > 0 {
			policy.MaxDuration = boundedDuration(duration, opts.Policy.Limits.MaxDuration)
		}
	}
	return policy
}

func boundedDuration(value, limit time.Duration) time.Duration {
	value = positiveDuration(value)
	limit = positiveDuration(limit)
	switch {
	case value == 0:
		return limit
	case limit == 0:
		return value
	default:
		return min(value, limit)
	}
}

func (p effectiveSessionPolicy) filterEnv(envs []string) []string {
	if len(envs) == 0 {
		return nil
	}
	result := make([]string, 0, len(envs))
	for _, env := range envs {
		key, _, found := strings.Cut(env, "=")
		if !found {
			continue
		}
		if strings.EqualFold(key, sshAuthSockEnv) {
			continue
		}
		if p.envAllowed(key) {
			result = append(result, env)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func (p effectiveSessionPolicy) envAllowed(key string) bool {
	if !envAllowlistAllows(p.globalEnvAllowlist, key) {
		return false
	}
	if p.accessEnvConfigured && !envAllowlistAllows(p.accessEnvAllowlist, key) {
		return false
	}
	return true
}

func envAllowlistAllows(allowlist []string, key string) bool {
	if len(allowlist) == 0 {
		return false
	}
	upper := strings.ToUpper(key)
	for _, pattern := range allowlist {
		p := strings.ToUpper(pattern)
		if p == "*" {
			return true
		}
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(upper, p[:len(p)-1]) {
				return true
			}
			continue
		}
		if upper == p {
			return true
		}
	}
	return false
}

func positiveDuration(duration time.Duration) time.Duration {
	return max(duration, 0)
}

func (s *Server) resolveSessionPolicy(ctx context.Context, sshUser string, infoExtra map[string][]string) (effectiveSessionPolicy, error) {
	access, err := s.sessionPolicyAccess(ctx, sshUser, infoExtra)
	if err != nil {
		return effectiveSessionPolicy{}, err
	}
	opts := s.opts
	if opts == nil {
		opts = NewDefaultOptions()
	}
	policy := buildAccessSessionPolicy(opts, access)
	if !stringAllowed(opts.Policy.Limits.Shells, policy.DefaultShell) {
		return effectiveSessionPolicy{}, fmt.Errorf("shell %q exceeds global policy limits", policy.DefaultShell)
	}
	return policy, nil
}

func stringAllowed(patterns []string, value string) bool {
	return pattern.MatchAny(patterns, value)
}

func (s *Server) sessionPolicyAccess(ctx context.Context, sshUser string, infoExtra map[string][]string) (*sshv1.Access, error) {
	if s == nil || s.accessPolicy == nil {
		return nil, nil
	}
	namespace := firstExtraValue(infoExtra, accesspolicy.ExtraAccessNamespace)
	name := firstExtraValue(infoExtra, accesspolicy.ExtraAccessName)
	if namespace != "" || name != "" {
		if namespace == "" || name == "" {
			return nil, fmt.Errorf("incomplete access policy identity")
		}
		return s.accessPolicy.Get(ctx, namespace, name)
	}
	namespace, name, ok := parseAccessSSHUser(sshUser)
	if !ok {
		return nil, nil
	}
	access, err := s.accessPolicy.Get(ctx, namespace, name)
	if err != nil {
		return nil, nil
	}
	return access, nil
}

func parseAccessSSHUser(sshUser string) (string, string, bool) {
	namespace, name, ok := strings.Cut(sshUser, ".")
	if !ok || namespace == "" || name == "" {
		return "", "", false
	}
	return namespace, name, true
}

func firstExtraValue(extra map[string][]string, key string) string {
	values := extra[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
