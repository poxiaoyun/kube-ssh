package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
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

	AgentForwarding bool
}

func buildGlobalSessionPolicy(opts *Options) effectiveSessionPolicy {
	if opts == nil {
		opts = NewDefaultOptions()
	}
	return effectiveSessionPolicy{
		DefaultShell:       opts.DefaultShell,
		globalEnvAllowlist: append([]string(nil), opts.EnvAllowlist...),
		IdleTimeout:        positiveDuration(opts.SSH.IdleTimeout),
		MaxDuration:        positiveDuration(opts.SSH.MaxDuration),
		AgentForwarding:    opts.SSH.AgentForwarding,
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
		policy.IdleTimeout = stricterDuration(policy.IdleTimeout, session.IdleTimeout.Duration)
	}
	if session.MaxDuration != nil {
		policy.MaxDuration = stricterDuration(policy.MaxDuration, session.MaxDuration.Duration)
	}
	if session.AgentForwarding != nil {
		policy.AgentForwarding = policy.AgentForwarding && *session.AgentForwarding
	}
	return policy
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

func stricterDuration(global, access time.Duration) time.Duration {
	global = positiveDuration(global)
	access = positiveDuration(access)
	switch {
	case global <= 0:
		return access
	case access <= 0:
		return global
	case access < global:
		return access
	default:
		return global
	}
}

func positiveDuration(duration time.Duration) time.Duration {
	if duration <= 0 {
		return 0
	}
	return duration
}

func (s *Server) resolveSessionPolicy(ctx context.Context, sshUser string, infoExtra map[string][]string) (effectiveSessionPolicy, error) {
	access, err := s.sessionPolicyAccess(ctx, sshUser, infoExtra)
	if err != nil {
		return effectiveSessionPolicy{}, err
	}
	return buildAccessSessionPolicy(s.opts, access), nil
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
