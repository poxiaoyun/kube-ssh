package server

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestAuthorizeOperationAllow(t *testing.T) {
	ctx := newTestSSHContext()
	sc := &sessionContext{
		ctx:    ctx,
		info:   authn.AuthenticateInfo{User: authn.UserInfo{Name: "alice"}, Method: "crd-password", Extra: map[string][]string{"access": {"default/notebook"}}},
		target: targetFixturePtr(),
		audit:  audit.Event{Fields: map[string]string{}},
	}
	spec := operationSpec{
		name:       "session",
		capability: authz.CapabilityExec,
		attrs:      authz.Attributes{Action: string(authz.CapabilityExec)},
		auditFields: map[string]string{
			"command": "id",
		},
	}
	s := &Server{
		authz: authz.AuthorizerFunc(func(_ context.Context, req authz.Request) (authz.Decision, string, error) {
			if req.User.Name != "alice" {
				t.Fatalf("user = %q, want alice", req.User.Name)
			}
			if req.AuthMethod != "crd-password" {
				t.Fatalf("auth method = %q, want crd-password", req.AuthMethod)
			}
			if len(req.AuthExtra["access"]) != 1 || req.AuthExtra["access"][0] != "default/notebook" {
				t.Fatalf("auth extra = %#v", req.AuthExtra)
			}
			if req.Attributes.Action != string(authz.CapabilityExec) {
				t.Fatalf("action = %q, want exec", req.Attributes.Action)
			}
			return authz.DecisionAllow, "", nil
		}),
	}

	reason, allowed := s.authorizeOperation(sc, spec)
	if !allowed {
		t.Fatalf("allowed = false, reason = %q", reason)
	}
	if reason != "" {
		t.Fatalf("reason = %q, want empty", reason)
	}
	if sc.audit.Fields["capability"] != string(authz.CapabilityExec) {
		t.Fatalf("audit capability = %q", sc.audit.Fields["capability"])
	}
	if sc.audit.Fields["command"] != "id" {
		t.Fatalf("audit command = %q", sc.audit.Fields["command"])
	}
	if sc.audit.Type != "" {
		t.Fatalf("audit type = %q, want empty", sc.audit.Type)
	}
}

func TestAuthorizeOperationDenyAndError(t *testing.T) {
	tests := []struct {
		name       string
		decision   authz.Decision
		reason     string
		err        error
		wantReason string
	}{
		{
			name:       "deny reason",
			decision:   authz.DecisionDeny,
			reason:     "policy denied",
			wantReason: "policy denied",
		},
		{
			name:       "no opinion uses default reason",
			decision:   authz.DecisionNoOpinion,
			wantReason: "access denied",
		},
		{
			name:       "error becomes reason",
			decision:   authz.DecisionNoOpinion,
			err:        errors.New("authorizer unavailable"),
			wantReason: "authorizer unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := &sessionContext{
				ctx:    newTestSSHContext(),
				info:   authn.AuthenticateInfo{User: authn.UserInfo{Name: "alice"}},
				target: targetFixturePtr(),
				audit:  audit.Event{Fields: map[string]string{}},
			}
			s := &Server{
				authz: authz.AuthorizerFunc(func(context.Context, authz.Request) (authz.Decision, string, error) {
					return tt.decision, tt.reason, tt.err
				}),
			}
			spec := operationSpec{name: "session", capability: authz.CapabilityExec, attrs: authz.Attributes{}}

			reason, allowed := s.authorizeOperation(sc, spec)
			if allowed {
				t.Fatal("allowed = true, want false")
			}
			if reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tt.wantReason)
			}
			if sc.audit.Type != "session_denied" {
				t.Fatalf("audit type = %q, want session_denied", sc.audit.Type)
			}
			if sc.audit.Fields["reason"] != tt.wantReason {
				t.Fatalf("audit reason = %q, want %q", sc.audit.Fields["reason"], tt.wantReason)
			}
			if sc.audit.Fields["decision"] != string(tt.decision) {
				t.Fatalf("audit decision = %q, want %q", sc.audit.Fields["decision"], tt.decision)
			}
		})
	}
}

func TestForwardOperationSpecs(t *testing.T) {
	sc := &sessionContext{target: targetFixturePtr()}

	direct := directTCPIPOperationSpec(sc, directTCPIPData{
		DestAddr:   "redis.default.svc",
		DestPort:   6379,
		OriginAddr: "127.0.0.1",
		OriginPort: 51111,
	})
	if direct.capability != authz.CapabilityLocalForward {
		t.Fatalf("direct capability = %q", direct.capability)
	}
	if direct.attrs.Path != "kube/namespaces/default/pods/nginx/containers/app/hosts/redis.default.svc/ports/6379" {
		t.Fatalf("direct path = %q", direct.attrs.Path)
	}
	if !reflect.DeepEqual(direct.attrs.Extra["destination_host"], []string{"redis.default.svc"}) {
		t.Fatalf("direct destination extra = %#v", direct.attrs.Extra)
	}
	if direct.auditFields["origin_port"] != "51111" {
		t.Fatalf("direct audit origin_port = %q", direct.auditFields["origin_port"])
	}

	remote := remoteForwardOperationSpec(sc, "127.0.0.1", 2222)
	if remote.capability != authz.CapabilityRemoteForward {
		t.Fatalf("remote capability = %q", remote.capability)
	}
	if remote.attrs.Path != "kube/namespaces/default/pods/nginx/containers/app/remote-forwards/127.0.0.1/2222" {
		t.Fatalf("remote path = %q", remote.attrs.Path)
	}
	if !reflect.DeepEqual(remote.attrs.Extra["bind_port"], []string{"2222"}) {
		t.Fatalf("remote bind_port extra = %#v", remote.attrs.Extra)
	}
	if remote.auditFields["bind_host"] != "127.0.0.1" {
		t.Fatalf("remote audit bind_host = %q", remote.auditFields["bind_host"])
	}
}

func TestAcceptAuthenticatedResolvesTargetWithIdentity(t *testing.T) {
	ctx := newTestSSHContext()
	resolver := &captureResolver{target: targetFixturePtr()}
	s := &Server{resolver: resolver}
	info := &authn.AuthenticateInfo{
		User:   authn.UserInfo{Name: "alice", Groups: []string{"dev"}},
		Method: "publickey",
		Extra:  map[string][]string{"access": {"default/notebook"}},
		TargetHints: []authn.TargetHint{
			{
				Kind: "kube",
				Options: []authn.TargetHintOption{
					{Key: "namespaces", Value: "default"},
					{Key: "pods", Value: "nginx"},
				},
			},
		},
	}

	if !s.acceptAuthenticated(ctx, info, "SHA256:test", metrics.CredentialPublicKey) {
		t.Fatal("acceptAuthenticated() = false, want true")
	}
	if resolver.request.SSHUser != "default.nginx.app" {
		t.Fatalf("resolver SSHUser = %q, want default.nginx.app", resolver.request.SSHUser)
	}
	if resolver.request.User.Name != "alice" {
		t.Fatalf("resolver user = %q, want alice", resolver.request.User.Name)
	}
	if resolver.request.AuthMethod != "publickey" {
		t.Fatalf("resolver auth method = %q, want publickey", resolver.request.AuthMethod)
	}
	if len(resolver.request.AuthExtra["access"]) != 1 || resolver.request.AuthExtra["access"][0] != "default/notebook" {
		t.Fatalf("resolver auth extra = %#v", resolver.request.AuthExtra)
	}
	if resolver.request.PublicKeyFingerprint != "SHA256:test" {
		t.Fatalf("resolver fingerprint = %q, want SHA256:test", resolver.request.PublicKeyFingerprint)
	}
	if len(resolver.request.TargetHints) != 1 {
		t.Fatalf("resolver target hints = %#v, want one hint", resolver.request.TargetHints)
	}
	if resolver.request.TargetHints[0].Kind != "kube" {
		t.Fatalf("resolver target hint kind = %q, want kube", resolver.request.TargetHints[0].Kind)
	}
	if _, ok := AuthenticateFromContext(ctx); !ok {
		t.Fatal("AuthenticateFromContext() missing")
	}
	if _, ok := TargetFromContext(ctx); !ok {
		t.Fatal("TargetFromContext() missing")
	}
}

func TestAcceptAuthenticatedAppliesAccessSessionPolicy(t *testing.T) {
	ctx := newTestSSHContext()
	opts := NewDefaultOptions()
	opts.EnvAllowlist = []string{"LANG", "LC_*"}
	opts.SSH.IdleTimeout = time.Hour
	access := &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "notebook"},
		Spec: sshv1.AccessSpec{
			Session: &sshv1.SessionPolicy{
				DefaultShell: "/bin/bash",
				EnvAllowlist: []string{
					"LC_TIME",
					"PATH",
				},
				IdleTimeout: &metav1.Duration{Duration: 10 * time.Minute},
			},
		},
	}
	s := &Server{
		opts:         opts,
		resolver:     &captureResolver{target: targetFixturePtr()},
		accessPolicy: fakeAccessPolicyGetter{access: access},
	}
	info := &authn.AuthenticateInfo{
		User:   authn.UserInfo{Name: "alice"},
		Method: "crd-password",
		Extra: map[string][]string{
			accesspolicy.ExtraAccessNamespace: {"default"},
			accesspolicy.ExtraAccessName:      {"notebook"},
		},
	}

	if !s.acceptAuthenticated(ctx, info, "", metrics.CredentialPassword) {
		t.Fatal("acceptAuthenticated() = false, want true")
	}
	policy := SessionPolicyFromContext(ctx)
	if policy.DefaultShell != "/bin/bash" {
		t.Fatalf("DefaultShell = %q, want /bin/bash", policy.DefaultShell)
	}
	if policy.IdleTimeout != 10*time.Minute {
		t.Fatalf("IdleTimeout = %s, want 10m", policy.IdleTimeout)
	}
	got := policy.filterEnv([]string{
		"LANG=C",
		"LC_TIME=C",
		"LC_NUMERIC=C",
		"PATH=/usr/bin",
	})
	want := []string{"LC_TIME=C"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filterEnv() = %#v, want %#v", got, want)
	}
}

func TestAcceptAuthenticatedAppliesAccessSessionPolicyFromSSHUser(t *testing.T) {
	ctx := newTestSSHContext()
	opts := NewDefaultOptions()
	access := &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "nginx.app"},
		Spec: sshv1.AccessSpec{
			Session: &sshv1.SessionPolicy{
				DefaultShell: "/bin/zsh",
				MaxDuration:  &metav1.Duration{Duration: 15 * time.Minute},
			},
		},
	}
	s := &Server{
		opts:         opts,
		resolver:     &captureResolver{target: targetFixturePtr()},
		accessPolicy: fakeAccessPolicyGetter{access: access},
	}
	info := &authn.AuthenticateInfo{
		User:   authn.UserInfo{Name: "alice"},
		Method: "password",
	}

	if !s.acceptAuthenticated(ctx, info, "", metrics.CredentialPassword) {
		t.Fatal("acceptAuthenticated() = false, want true")
	}
	policy := SessionPolicyFromContext(ctx)
	if policy.DefaultShell != "/bin/zsh" {
		t.Fatalf("DefaultShell = %q, want /bin/zsh", policy.DefaultShell)
	}
	if policy.MaxDuration != 15*time.Minute {
		t.Fatalf("MaxDuration = %s, want 15m", policy.MaxDuration)
	}
}

func targetFixturePtr() *target.Target {
	tgt := targetFixture()
	return &tgt
}

type captureResolver struct {
	request target.ResolveRequest
	target  *target.Target
	err     error
}

func (r *captureResolver) Resolve(_ context.Context, req target.ResolveRequest) (*target.Target, error) {
	r.request = req
	return r.target, r.err
}

type fakeAccessPolicyGetter struct {
	access *sshv1.Access
	err    error
}

func (g fakeAccessPolicyGetter) Get(_ context.Context, namespace, name string) (*sshv1.Access, error) {
	if g.err != nil {
		return nil, g.err
	}
	if g.access == nil || g.access.Namespace != namespace || g.access.Name != name {
		return nil, errors.New("not found")
	}
	return g.access, nil
}

type testSSHContext struct {
	context.Context
	mu     sync.Mutex
	values map[any]any
}

func newTestSSHContext() *testSSHContext {
	return &testSSHContext{
		Context: context.Background(),
		values:  make(map[any]any),
	}
}

func (c *testSSHContext) Lock() {
	c.mu.Lock()
}

func (c *testSSHContext) Unlock() {
	c.mu.Unlock()
}

func (c *testSSHContext) User() string { return "default.nginx.app" }

func (c *testSSHContext) SessionID() string { return "session" }

func (c *testSSHContext) ClientVersion() string { return "client" }

func (c *testSSHContext) ServerVersion() string { return "server" }

func (c *testSSHContext) RemoteAddr() net.Addr { return testAddr("remote") }

func (c *testSSHContext) LocalAddr() net.Addr { return testAddr("local") }

func (c *testSSHContext) Permissions() *gossh.Permissions { return &gossh.Permissions{} }

func (c *testSSHContext) SetValue(key, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] = value
}

func (c *testSSHContext) Value(key any) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if value, ok := c.values[key]; ok {
		return value
	}
	return c.Context.Value(key)
}

func (c *testSSHContext) Deadline() (time.Time, bool) {
	return c.Context.Deadline()
}

func (c *testSSHContext) Done() <-chan struct{} {
	return c.Context.Done()
}

func (c *testSSHContext) Err() error {
	return c.Context.Err()
}

type testAddr string

func (a testAddr) Network() string { return "test" }

func (a testAddr) String() string { return string(a) }
