package gateway

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	gossh "github.com/gliderlabs/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestConnectionFeaturesReportPolicyTimeout(t *testing.T) {
	recorder := &eventRecorder{}
	server := &gateway{opts: NewDefaultOptions(), audit: recorder}
	sshCtx := newTestSSHContext()
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	conn := applyConnectionFeatures(sshCtx, serverSide, server.connectionFeatures()...)
	policyConn, ok := sessionPolicyConnFromContext(sshCtx)
	if !ok {
		t.Fatal("session policy connection was not installed")
	}
	policyConn.ApplyPolicy(effectiveSessionPolicy{MaxDuration: 20 * time.Millisecond})

	deadline := time.Now().
		Add(time.Second)
	for len(recorder.Events()) < 2 && time.Now().
		Before(deadline) {
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
	server := &gateway{audit: recorder}
	base, cancel := context.WithCancel(context.Background())
	sshCtx := newTestSSHContext()
	sshCtx.Context = base
	sshCtx.SetValue(gossh.ContextKeyUser, "default.nginx.app")
	sshCtx.SetValue(gossh.ContextKeyClientVersion, "SSH-2.0-test")
	sshCtx.SetValue(gossh.ContextKeyRemoteAddr, testAddr("client:2222"))

	finish := server.startConnectionAudit(sshCtx, nil)
	info := authn.AuthenticateInfo{User: authn.UserInfo{ID: "42", Name: "alice", Groups: []string{"dev"}}, Method: "publickey"}
	server.recordAuthentication(sshCtx, "publickey", "SHA256:test", "success", &info, nil)
	withAuthenticate(sshCtx, info)
	withTarget(sshCtx, targetFixturePtr())
	withAuditFingerprint(sshCtx, "SHA256:test")
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
	server := &gateway{
		audit: recorder,
		authz: authz.AuthorizerFunc(func(context.Context, authz.Request) (authz.Decision, string, error) {
			return authz.DecisionAllow, "policy matched", nil
		}),
	}
	sshCtx := newTestSSHContext()
	withConnectionAudit(sshCtx, &connectionAuditState{id: "connection-1"})
	sc := &operationContext{
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

func TestSSHAuditSuccessfulExecLifecycle(t *testing.T) {
	recorder := &eventRecorder{}
	execBackend := &agentForwardExecBackend{}
	addr := startAuditIntegrationServer(t, auditIntegrationDependencies(t, recorder, authz.AllowAll{}, &captureResolver{target: targetFixturePtr()}, execBackend))

	client := dialTestSSH(t, addr)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	if err := session.Run("id"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client Close() error = %v", err)
	}

	events := waitForAudit(t, recorder, func(events []audit.Event) bool {
		return countAuditType(events, "connection.end") == 1
	})
	wantTypes := []string{
		"connection.start",
		"authentication.result",
		"target_resolution.result",
		"connection.ready",
		"operation.start",
		"operation.end",
		"connection.end",
	}
	if got := auditTypes(events); !reflect.DeepEqual(got, wantTypes) {
		t.Fatalf("event types = %q, want %q", got, wantTypes)
	}
	assertSingleConnectionCorrelation(t, events)

	operationStart := events[4]
	operationEnd := events[5]
	if operationStart.Correlation.OperationID == "" || operationStart.Correlation.OperationID != operationEnd.Correlation.OperationID {
		t.Fatalf("operation IDs = %q, %q", operationStart.Correlation.OperationID, operationEnd.Correlation.OperationID)
	}
	if operationEnd.Actor == nil || operationEnd.Actor.Name != "alice" || operationEnd.Actor.AuthenticationMethod != "password" {
		t.Fatalf("operation actor = %+v", operationEnd.Actor)
	}
	if operationEnd.Target == nil || operationEnd.Target.Namespace != "default" || operationEnd.Target.Name != "nginx" || operationEnd.Target.Container != "app" {
		t.Fatalf("operation target = %+v", operationEnd.Target)
	}
	if operationEnd.Operation == nil || operationEnd.Operation.Capability != string(authz.CapabilityExec) || operationEnd.Operation.Command != "id" {
		t.Fatalf("operation = %+v", operationEnd.Operation)
	}
	if operationEnd.Authorization == nil || operationEnd.Authorization.Decision != string(authz.DecisionAllow) {
		t.Fatalf("authorization = %+v", operationEnd.Authorization)
	}
	if operationEnd.Outcome == nil || operationEnd.Outcome.Result != "success" || operationEnd.Outcome.ExitCode == nil || *operationEnd.Outcome.ExitCode != 0 {
		t.Fatalf("outcome = %+v", operationEnd.Outcome)
	}
	if got := execBackend.Command(); !reflect.DeepEqual(got, []string{"/bin/sh", "-c", "id"}) {
		t.Fatalf("backend command = %#v", got)
	}
}

func TestSSHAuditAuthenticationRejected(t *testing.T) {
	recorder := &eventRecorder{}
	addr := startAuditIntegrationServer(t, auditIntegrationDependencies(t, recorder, authz.AllowAll{}, &captureResolver{target: targetFixturePtr()}, &agentForwardExecBackend{}))

	dialUntilAuditRejection(t, addr, auditIntegrationClientConfig("wrong-password"), recorder, "authentication.result")

	events := waitForAudit(t, recorder, func(events []audit.Event) bool {
		return countAuditType(events, "connection.end") == 1
	})
	if got, want := auditTypes(events), []string{"connection.start", "authentication.result", "connection.end"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event types = %q, want %q", got, want)
	}
	if events[1].Outcome == nil || events[1].Outcome.Result != "rejected" || events[1].Outcome.Reason != "authentication rejected" {
		t.Fatalf("authentication outcome = %+v", events[1].Outcome)
	}
	if events[2].Outcome == nil || events[2].Outcome.Result != "rejected" {
		t.Fatalf("connection outcome = %+v", events[2].Outcome)
	}
	assertSingleConnectionCorrelation(t, events)
}

func TestSSHAuditTargetResolutionRejected(t *testing.T) {
	recorder := &eventRecorder{}
	resolver := &captureResolver{err: errors.New("target unavailable")}
	addr := startAuditIntegrationServer(t, auditIntegrationDependencies(t, recorder, authz.AllowAll{}, resolver, &agentForwardExecBackend{}))

	dialUntilAuditRejection(t, addr, auditIntegrationClientConfig("secret"), recorder, "target_resolution.result")
	events := waitForAudit(t, recorder, func(events []audit.Event) bool {
		return countAuditType(events, "connection.end") == 1
	})
	if got, want := auditTypes(events), []string{"connection.start", "authentication.result", "target_resolution.result", "connection.end"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event types = %q, want %q", got, want)
	}
	resolution := events[2]
	if resolution.Outcome == nil || resolution.Outcome.Result != "rejected" || resolution.Outcome.Error != "target unavailable" {
		t.Fatalf("target resolution outcome = %+v", resolution.Outcome)
	}
	assertSingleConnectionCorrelation(t, events)
}

func TestSSHAuditAuthorizationDenied(t *testing.T) {
	recorder := &eventRecorder{}
	execBackend := &agentForwardExecBackend{}
	addr := startAuditIntegrationServer(t, auditIntegrationDependencies(t, recorder, authz.DenyAll{}, &captureResolver{target: targetFixturePtr()}, execBackend))

	client := dialTestSSH(t, addr)
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	err = session.Run("id")
	var exitErr *cryptossh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 1 {
		t.Fatalf("Run() error = %T %v, want exit status 1", err, err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("client Close() error = %v", err)
	}

	events := waitForAudit(t, recorder, func(events []audit.Event) bool {
		return countAuditType(events, "connection.end") == 1
	})
	if got, want := auditTypes(events), []string{"connection.start", "authentication.result", "target_resolution.result", "connection.ready", "operation.start", "operation.end", "connection.end"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("event types = %q, want %q", got, want)
	}
	operationEnd := events[5]
	if operationEnd.Authorization == nil || operationEnd.Authorization.Decision != string(authz.DecisionDeny) {
		t.Fatalf("authorization = %+v", operationEnd.Authorization)
	}
	if operationEnd.Outcome == nil || operationEnd.Outcome.Result != "denied" || operationEnd.Outcome.ExitCode == nil || *operationEnd.Outcome.ExitCode != 1 {
		t.Fatalf("outcome = %+v", operationEnd.Outcome)
	}
	if got := execBackend.Command(); got != nil {
		t.Fatalf("backend command = %#v, want no Exec call", got)
	}
	assertSingleConnectionCorrelation(t, events)
}

func auditIntegrationDependencies(t *testing.T, recorder audit.Recorder, authorizer authz.Authorizer, resolver target.Resolver, execBackend backend.Backend) Dependencies {
	t.Helper()
	authenticator, err := authn.NewStaticPasswordAuthenticator([]authn.PasswordEntry{{Subject: "alice", Password: "secret"}})
	if err != nil {
		t.Fatalf("NewStaticPasswordAuthenticator() error = %v", err)
	}
	return Dependencies{
		Authenticator: authenticator,
		Authorizer:    authorizer,
		Resolver:      resolver,
		PodBackend:    execBackend,
		AuditRecorder: recorder,
	}
}

func startAuditIntegrationServer(t *testing.T, dependencies Dependencies) string {
	t.Helper()
	opts := NewDefaultOptions()
	opts.ListenAddress = freeTCPAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithDependencies(ctx, opts, dependencies)
	}()
	t.Cleanup(func() { stopTestServer(t, cancel, errCh) })
	return opts.ListenAddress
}

func auditIntegrationClientConfig(password string) *cryptossh.ClientConfig {
	return &cryptossh.ClientConfig{
		User:            "default.nginx",
		Auth:            []cryptossh.AuthMethod{cryptossh.Password(password)},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         200 * time.Millisecond,
	}
}

func dialUntilAuditRejection(t *testing.T, addr string, config *cryptossh.ClientConfig, recorder *eventRecorder, eventType string) {
	t.Helper()
	deadline := time.Now().
		Add(3 * time.Second)
	var lastErr error
	for time.Now().
		Before(deadline) {
		client, err := cryptossh.Dial("tcp", addr, config)
		if client != nil {
			_ = client.Close()
			t.Fatalf("SSH dial succeeded while waiting for %q rejection", eventType)
		}
		lastErr = err
		if countAuditType(recorder.Events(), eventType) > 0 {
			if err == nil {
				t.Fatalf("SSH dial error = nil after %q rejection", eventType)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("SSH rejection event %q was not recorded: %v", eventType, lastErr)
}

func waitForAudit(t *testing.T, recorder *eventRecorder, predicate func([]audit.Event) bool) []audit.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	events, ok := recorder.Wait(ctx, predicate)
	if !ok {
		t.Fatalf("timed out waiting for audit events; got %q", auditTypes(events))
	}
	return events
}

func countAuditType(events []audit.Event, eventType string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func auditTypes(events []audit.Event) []string {
	types := make([]string, len(events))
	for i := range events {
		types[i] = events[i].Type
	}
	return types
}

func assertSingleConnectionCorrelation(t *testing.T, events []audit.Event) {
	t.Helper()
	if len(events) == 0 || events[0].Correlation.ConnectionID == "" {
		t.Fatal("connection ID is empty")
	}
	want := events[0].Correlation.ConnectionID
	for _, event := range events {
		if event.Correlation.ConnectionID != want {
			t.Fatalf("event %q connection ID = %q, want %q", event.Type, event.Correlation.ConnectionID, want)
		}
	}
}
