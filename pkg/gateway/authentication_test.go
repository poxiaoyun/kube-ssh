package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"

	cryptossh "golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
)

func TestSSHAccessAuthenticationMethods(t *testing.T) {
	key := string(cryptossh.MarshalAuthorizedKey(authenticationTestSigner(t).PublicKey()))
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for name, credentials := range map[string][]sshv1.AccessCredential{
		"keys":      {{PublicKeys: []string{key}}},
		"passwords": {{Passwords: []string{"secret"}}},
		"both":      {{PublicKeys: []string{key}}, {Passwords: []string{"secret"}}},
		"empty":     {},
	} {
		if err := indexer.Add(&sshv1.Access{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: name}, Spec: sshv1.AccessSpec{Credentials: credentials}}); err != nil {
			t.Fatal(err)
		}
	}
	store := accesspolicy.NewPolicyCache(indexer, nil, accesspolicy.PolicyCacheOptions{})
	for _, gatewayMethods := range [][]string{nil, {"publickey"}, {"password"}} {
		opts := NewDefaultOptions()
		opts.Authentication.Methods = gatewayMethods
		addr := startAuthenticationTestServer(t, opts, authn.NewChain(), store)
		for user, accessMethods := range map[string][]string{
			"default.keys":               {"publickey"},
			"default.keys~pod.container": {"publickey"},
			"default.keys.container":     {"publickey"},
			"default.passwords":          {"password"},
			"default.both":               {"publickey", "password"},
			"default.empty":              {},
		} {
			var want, attempted []string
			for _, method := range accessMethods {
				if gatewayMethods == nil || reflect.DeepEqual(gatewayMethods, []string{method}) {
					want = append(want, method)
				}
			}
			client, err := connectAuthenticationTestClient(t, addr, []cryptossh.AuthMethod{
				cryptossh.PublicKeysCallback(func() ([]cryptossh.Signer, error) {
					attempted = append(attempted, "publickey")
					return []cryptossh.Signer{authenticationTestSigner(t)}, nil
				}),
				cryptossh.PasswordCallback(func() (string, error) {
					attempted = append(attempted, "password")
					return "wrong-password", nil
				}),
			}, user)
			if err == nil {
				client.Close()
				t.Fatal("unmatched credentials authenticated")
			}
			if !reflect.DeepEqual(attempted, want) {
				t.Errorf("gateway %v, user %s: attempted %v, want %v; %v", gatewayMethods, user, attempted, want, err)
			}
		}
	}
}

func TestSSHAuthenticationMethods(t *testing.T) {
	for _, tt := range []struct {
		name    string
		methods []string
		want    []string
	}{
		{name: "default", want: []string{"publickey", "password"}},
		{name: "both", methods: []string{"publickey", "password"}, want: []string{"publickey", "password"}},
		{name: "publickey only", methods: []string{"publickey"}, want: []string{"publickey"}},
		{name: "password only", methods: []string{"password"}, want: []string{"password"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := NewDefaultOptions()
			opts.Authentication.Methods = tt.methods
			addr := startAuthenticationTestServer(t, opts, authn.NewChain())
			var attempted []string
			client, err := connectAuthenticationTestClient(t, addr, []cryptossh.AuthMethod{
				cryptossh.PublicKeysCallback(func() ([]cryptossh.Signer, error) {
					attempted = append(attempted, "publickey")
					return []cryptossh.Signer{authenticationTestSigner(t)}, nil
				}),
				cryptossh.PasswordCallback(func() (string, error) {
					attempted = append(attempted, "password")
					return "wrong-password", nil
				}),
			})
			if err == nil {
				client.Close()
				t.Fatal("unmatched credentials authenticated")
			}
			if !reflect.DeepEqual(attempted, tt.want) {
				t.Fatalf("attempted methods = %v, want %v (handshake: %v)", attempted, tt.want, err)
			}
		})
	}
}

func TestSSHAuthenticationPublicKeyFallback(t *testing.T) {
	valid := authenticationTestSigner(t)
	authenticator, err := authn.NewStaticPublicKeyAuthenticator([]authn.AuthorizedKeyEntry{{
		Subject:   "alice",
		PublicKey: string(cryptossh.MarshalAuthorizedKey(valid.PublicKey())),
	}})
	if err != nil {
		t.Fatal(err)
	}
	opts := NewDefaultOptions()
	opts.Authentication.Methods = []string{"publickey"}
	addr := startAuthenticationTestServer(t, opts, authenticator)
	client, err := connectAuthenticationTestClient(t, addr, []cryptossh.AuthMethod{
		cryptossh.PublicKeys(authenticationTestSigner(t), valid),
	})
	if err != nil {
		t.Fatalf("second valid public key failed: %v", err)
	}
	client.Close()
}

func TestSSHAuthenticationPasswordFallback(t *testing.T) {
	authenticator, err := authn.NewStaticPasswordAuthenticator([]authn.PasswordEntry{{Subject: "alice", Password: "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	addr := startAuthenticationTestServer(t, NewDefaultOptions(), authenticator)
	client, err := connectAuthenticationTestClient(t, addr, []cryptossh.AuthMethod{
		cryptossh.PublicKeys(authenticationTestSigner(t)),
		cryptossh.Password("secret"),
	})
	if err != nil {
		t.Fatalf("default methods rejected valid password after unmatched public key: %v", err)
	}
	client.Close()
}

func TestSSHAuthenticationInvalidMethods(t *testing.T) {
	for _, tt := range []struct {
		name    string
		methods []string
		want    string
	}{
		{name: "empty", methods: []string{}, want: "at least one"},
		{name: "unknown", methods: []string{"keyboard-interactive"}, want: "unsupported authentication method"},
		{name: "duplicate", methods: []string{"publickey", "publickey"}, want: "duplicate authentication method"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := NewDefaultOptions()
			opts.Authentication.Methods = tt.methods
			stopped := false
			err := RunWithDependencies(context.Background(), opts, Dependencies{
				Start: func(context.Context) error { t.Fatal("started with invalid methods"); return nil },
				Stop:  func(context.Context) error { stopped = true; return nil },
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("startup error = %v, want %q", err, tt.want)
			}
			if !stopped {
				t.Fatal("constructed dependencies were not released on invalid configuration")
			}

		})
	}
}

func authenticationTestSigner(t *testing.T) cryptossh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func startAuthenticationTestServer(t *testing.T, opts *Options, authenticator authn.SSHAuthenticator, stores ...accesspolicy.AccessGetter) string {
	t.Helper()
	var store accesspolicy.AccessGetter
	if len(stores) > 0 {
		store = stores[0]
	}
	return startAuthenticationTestGateway(t, opts, Dependencies{
		Authenticator: authenticator,
		AccessPolicy:  store,
		Authorizer:    authz.AllowAll{},
		Resolver:      &captureResolver{target: targetFixturePtr()},
		PodBackend:    benchmarkBackend{},
		AuditRecorder: audit.NopRecorder{},
	})
}

func startAuthenticationTestGateway(t *testing.T, opts *Options, deps Dependencies) string {
	t.Helper()
	opts.ListenAddress = freeTCPAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunWithDependencies(ctx, opts, deps)
	}()
	t.Cleanup(func() { stopTestServer(t, cancel, errCh) })
	return opts.ListenAddress
}

// A public key offer is only a probe. A client which cannot sign must never
// trigger target resolution, success audit events or a business connection.
func TestSSHKeyProbeDoesNotAuthenticate(t *testing.T) {
	valid := authenticationTestSigner(t)
	authenticator, err := authn.NewStaticPublicKeyAuthenticator([]authn.AuthorizedKeyEntry{{Subject: "alice", PublicKey: string(cryptossh.MarshalAuthorizedKey(valid.PublicKey()))}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &captureResolver{target: targetFixturePtr()}
	recorder := &eventRecorder{}
	addr := startAuthenticationTestGateway(t, NewDefaultOptions(), Dependencies{
		Authenticator: authenticator, Authorizer: authz.AllowAll{}, Resolver: resolver,
		PodBackend: benchmarkBackend{}, AuditRecorder: recorder,
	})
	client, err := connectAuthenticationTestClient(t, addr, []cryptossh.AuthMethod{cryptossh.PublicKeys(unsignedTestKey{valid.PublicKey()})})
	if err == nil {
		client.Close()
		t.Fatal("unsigned public key authenticated")
	}
	events := waitForAudit(t, recorder, func(events []audit.Event) bool { return countAuditType(events, "connection.end") > 0 })
	for _, event := range events {
		if event.Type == "connection.ready" || event.Type == "target_resolution.result" || (event.Type == "authentication.result" && event.Outcome.Result == "success") {
			t.Fatalf("key probe produced success event: %+v", event)
		}
	}
}

type unsignedTestKey struct{ key cryptossh.PublicKey }

func (s unsignedTestKey) PublicKey() cryptossh.PublicKey { return s.key }
func (s unsignedTestKey) Sign(io.Reader, []byte) (*cryptossh.Signature, error) {
	return nil, errors.New("no private key available")
}

func TestSSHShutdownClosesUnauthenticatedConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := &gateway{metrics: metrics.NopRecorder{}, opts: NewDefaultOptions(), authn: authn.NewChain(), audit: audit.NopRecorder{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.serveSSH(ctx, listener, authenticationTestSigner(t), []string{"publickey"}) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	// Wait until the connection is accepted, then leave it before key exchange.
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown waited on unauthenticated client")
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("connection did not close: %v", err)
	}
}

func TestOpenSSHAccessPublicKeyAuthentication(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH client is not installed")
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	block, err := cryptossh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	if err := indexer.Add(&sshv1.Access{ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "keys"}, Spec: sshv1.AccessSpec{Credentials: []sshv1.AccessCredential{{Username: "alice", PublicKeys: []string{string(cryptossh.MarshalAuthorizedKey(signer.PublicKey()))}}}}}); err != nil {
		t.Fatal(err)
	}
	store := accesspolicy.NewPolicyCache(indexer, nil, accesspolicy.PolicyCacheOptions{})
	addr := startAuthenticationTestServer(t, NewDefaultOptions(), accesspolicy.NewAuthenticator(store), store)
	// Also verify that the normal Go client can negotiate and authenticate.
	client, err := connectAuthenticationTestClient(t, addr, []cryptossh.AuthMethod{cryptossh.PublicKeys(signer)}, "default.keys")
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	host, port, _ := net.SplitHostPort(addr)
	for _, identity := range []string{keyFile, "/dev/null"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cmd := exec.CommandContext(ctx, ssh, "-v", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey,password", "-i", identity, "-p", port, "default.keys@"+host, "true")
		output, err := cmd.CombinedOutput()
		cancel()
		if (err == nil) != (identity == keyFile) {
			t.Fatalf("OpenSSH error=%v, output=%s", err, output)
		}
		if !strings.Contains(string(output), "Authentications that can continue: publickey") || strings.Contains(string(output), "Authentications that can continue: password") || strings.Contains(string(output), "publickey,password") {
			t.Fatalf("unexpected OpenSSH authentication methods: %s", output)
		}
		if identity != keyFile && !strings.Contains(string(output), "Permission denied (publickey)") {
			t.Fatalf("unexpected rejection: %s", output)
		}
	}
}

func connectAuthenticationTestClient(t *testing.T, addr string, methods []cryptossh.AuthMethod, users ...string) (*cryptossh.Client, error) {
	user := "default.nginx"
	if len(users) > 0 {
		user = users[0]
	}
	t.Helper()
	var conn net.Conn
	var err error
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("gateway did not start: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	sshConn, channels, requests, err := cryptossh.NewClientConn(conn, addr, &cryptossh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cryptossh.NewClient(sshConn, channels, requests), nil
}
