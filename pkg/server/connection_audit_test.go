package server

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

func TestConnectionFeaturesReportPolicyTimeout(t *testing.T) {
	recorder := &eventRecorder{}
	server := &Server{opts: NewDefaultOptions(), audit: recorder}
	sshCtx := newTestSSHContext()
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := applyConnectionFeatures(sshCtx, serverSide, server.connectionFeatures()...)
	policyConn, ok := sessionPolicyConnFromContext(sshCtx)
	if !ok {
		t.Fatal("session policy connection was not installed")
	}
	policyConn.ApplyPolicy(effectiveSessionPolicy{MaxDuration: 20 * time.Millisecond})

	deadline := time.Now().Add(time.Second)
	for len(recorder.Events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	events := recorder.Events()
	if len(events) < 2 {
		_ = conn.Close()
		t.Fatalf("policy timeout did not close the connection; events = %+v", events)
	}
	_ = conn.Close()
	if len(events) != 2 || events[0].Type != "connection.start" || events[1].Type != "connection.end" {
		t.Fatalf("events = %+v, want connection start and end", events)
	}
}

func TestConnectionAuditLifecycle(t *testing.T) {
	recorder := &eventRecorder{}
	server := &Server{audit: recorder}
	base, cancel := context.WithCancel(context.Background())
	sshCtx := newTestSSHContext()
	sshCtx.Context = base
	sshCtx.SetValue(gossh.ContextKeyUser, "default.nginx.app")
	sshCtx.SetValue(gossh.ContextKeyClientVersion, "SSH-2.0-test")
	sshCtx.SetValue(gossh.ContextKeyRemoteAddr, testAddr("client:2222"))

	finish := server.startConnectionAudit(sshCtx, nil)
	info := authn.AuthenticateInfo{User: authn.UserInfo{ID: "42", Name: "alice", Groups: []string{"dev"}}, Method: "publickey"}
	server.recordAuthentication(sshCtx, "publickey", "SHA256:test", "success", &info, nil)
	WithAuthenticate(sshCtx, info)
	WithTarget(sshCtx, targetFixturePtr())
	WithAuditFingerprint(sshCtx, "SHA256:test")
	finish()
	cancel()
	events := recorder.Events()
	if len(events) != 3 {
		t.Fatalf("events = %d, want connection start, authentication, connection end", len(events))
	}
	start, authentication, end := events[0], events[1], events[2]
	if start.Type != "connection.start" || authentication.Type != "authentication.result" || end.Type != "connection.end" {
		t.Fatalf("event types = %q, %q, %q", start.Type, authentication.Type, end.Type)
	}
	if start.Correlation.ConnectionID == "" || start.Correlation.ConnectionID != end.Correlation.ConnectionID {
		t.Fatalf("connection IDs = %q, %q", start.Correlation.ConnectionID, end.Correlation.ConnectionID)
	}
	if authentication.Actor == nil || authentication.Actor.Name != "alice" || authentication.Actor.PublicKeyFingerprint != "SHA256:test" {
		t.Fatalf("authentication actor = %+v", authentication.Actor)
	}
	if end.Actor == nil || end.Target == nil || end.Outcome == nil || end.Outcome.Result != "success" {
		t.Fatalf("connection end = %+v", end)
	}
}

func TestOperationAuditLifecycleAndCorrelation(t *testing.T) {
	recorder := &eventRecorder{}
	server := &Server{
		audit: recorder,
		authz: authz.AuthorizerFunc(func(context.Context, authz.Request) (authz.Decision, string, error) {
			return authz.DecisionAllow, "policy matched", nil
		}),
	}
	sshCtx := newTestSSHContext()
	withConnectionAudit(sshCtx, &connectionAuditState{id: "connection-1"})
	sc := &sessionContext{
		ctx:    sshCtx,
		info:   authn.AuthenticateInfo{User: authn.UserInfo{ID: "42", Name: "alice", Groups: []string{"dev"}}, Method: "publickey"},
		target: targetFixturePtr(),
		audit:  audit.Event{Fields: map[string]string{}},
	}
	spec := operationSpec{name: "session", capability: authz.CapabilityExec, auditFields: map[string]string{"command": "id"}}

	finish := server.startOperation(sc, spec)
	if reason, allowed := server.authorizeOperation(sc, spec); !allowed {
		t.Fatalf("authorize denied: %s", reason)
	}
	sc.audit.Fields["exit_code"] = "0"
	finish("success")
	finish("error")

	events := recorder.Events()
	if len(events) != 2 {
		t.Fatalf("events = %d, want start and end", len(events))
	}
	start, end := events[0], events[1]
	if start.Type != "operation.start" || end.Type != "operation.end" {
		t.Fatalf("event types = %q, %q", start.Type, end.Type)
	}
	if start.Correlation.ConnectionID != "connection-1" {
		t.Fatalf("start correlation = %+v", start.Correlation)
	}
	if start.Correlation.OperationID == "" || start.Correlation.OperationID != end.Correlation.OperationID {
		t.Fatalf("operation IDs = %q, %q", start.Correlation.OperationID, end.Correlation.OperationID)
	}
	if end.Authorization == nil || end.Authorization.Decision != string(authz.DecisionAllow) {
		t.Fatalf("authorization = %+v", end.Authorization)
	}
	if end.Outcome == nil || end.Outcome.ExitCode == nil || *end.Outcome.ExitCode != 0 {
		t.Fatalf("outcome = %+v", end.Outcome)
	}
}

func TestAuditAccessUsesAccessPolicyIdentity(t *testing.T) {
	info := authn.AuthenticateInfo{
		User:   authn.UserInfo{Name: "alice"},
		Method: "crd-publickey",
		Extra: map[string][]string{
			accesspolicy.ExtraAccessNamespace: {"default"},
			accesspolicy.ExtraAccessName:      {"notebook"},
			accesspolicy.ExtraCredentialUser:  {"developer"},
			accesspolicy.ExtraCredentialType:  {"publickey"},
		},
	}

	got := auditAccess(info)
	if got == nil || got.Namespace != "default" || got.Name != "notebook" || got.CredentialUsername != "developer" || got.CredentialType != "publickey" {
		t.Fatalf("audit access = %+v", got)
	}
}

type eventRecorder struct {
	mu      sync.Mutex
	events  []audit.Event
	changed chan struct{}
}

func (r *eventRecorder) Record(_ context.Context, event audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
	if r.changed != nil {
		close(r.changed)
	}
	r.changed = make(chan struct{})
}

func (r *eventRecorder) Events() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

func (r *eventRecorder) Wait(ctx context.Context, predicate func([]audit.Event) bool) ([]audit.Event, bool) {
	for {
		r.mu.Lock()
		events := append([]audit.Event(nil), r.events...)
		if predicate(events) {
			r.mu.Unlock()
			return events, true
		}
		if r.changed == nil {
			r.changed = make(chan struct{})
		}
		changed := r.changed
		r.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return events, false
		}
	}
}
