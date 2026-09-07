package webhook_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"xiaoshiai.cn/kube-ssh/pkg/webhook"
)

func TestClientPostJSONAuthentication(t *testing.T) {
	for _, test := range []struct {
		name    string
		options webhook.Options
		auth    string
	}{
		{name: "anonymous"},
		{name: "bearer", options: webhook.Options{Token: "secret"}, auth: "Bearer secret"},
		{name: "basic", options: webhook.Options{Username: "alice", Password: "secret"}, auth: "Basic YWxpY2U6c2VjcmV0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
					t.Errorf("request = %s %v, want JSON POST", r.Method, r.Header)
				}
				if got := r.Header.Get("Authorization"); got != test.auth {
					t.Errorf("Authorization = %q, want %q", got, test.auth)
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).
					Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if body["hello"] != "world" {
					t.Errorf("body = %#v", body)
				}
				if err := json.NewEncoder(w).
					Encode(map[string]string{"ok": "true"}); err != nil {
					t.Errorf("encode response: %v", err)
				}
			}))
			defer server.Close()

			test.options.Server = server.URL
			client, err := webhook.NewClient(test.options)
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]string
			if err := client.Post(t.Context(), map[string]string{"hello": "world"}, &out); err != nil {
				t.Fatalf("Post() error = %v", err)
			}
			if out["ok"] != "true" {
				t.Fatalf("out = %#v", out)
			}
		})
	}
}

func TestClientPostReturnsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := webhook.NewClient(webhook.Options{Server: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	err = client.Post(t.Context(), nil, nil)
	if err != nil {
		if !strings.Contains(err.Error(), "403 Forbidden: denied") {
			t.Fatalf("Post() error = %v, want HTTP status and response", err)
		}
		return
	}
	t.Fatal("Post() succeeded for a forbidden response")
}

func TestClientPostUsesProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "webhook.invalid" || r.URL.Path != "/authenticate" {
			t.Errorf("proxy destination = %s", r.URL)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()

	client, err := webhook.NewClient(webhook.Options{Server: "http://webhook.invalid/authenticate", ProxyURL: proxy.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Post(t.Context(), nil, nil); err != nil {
		t.Fatalf("Post() through proxy: %v", err)
	}
}

func TestClientPostDoesNotFollowRedirects(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer destination.Close()

	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, destination.URL, status)
			}))
			defer server.Close()
			client, err := webhook.NewClient(webhook.Options{Server: server.URL, Token: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			err = client.Post(t.Context(), map[string]string{"password": "credential"}, nil)
			if err != nil {
				if !strings.Contains(err.Error(), fmt.Sprint(status)) {
					t.Fatalf("Post() error = %v, want redirect status %d", err, status)
				}
				if calls := destinationCalls.Load(); calls != 0 {
					t.Fatalf("redirect destination received %d requests", calls)
				}
				return
			}
			t.Fatal("Post() followed the redirect")
		})
	}
}

func TestClientPostTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	trustedCA := writeCertificate(t, server.Certificate())
	wrongCA, _ := clientCertificate(t)
	for _, test := range []struct {
		name      string
		options   webhook.Options
		untrusted bool
	}{
		{name: "trusted", options: webhook.Options{CAFile: trustedCA}},
		{name: "wrong CA", options: webhook.Options{CAFile: writeCertificate(t, wrongCA)}, untrusted: true},
		{name: "system trust", untrusted: true},
		{name: "insecure", options: webhook.Options{InsecureSkipTLSVerify: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.options.Server = server.URL
			client, err := webhook.NewClient(test.options)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Post(t.Context(), nil, nil)
			if test.untrusted {
				var unknownAuthority x509.UnknownAuthorityError
				if !errors.As(err, &unknownAuthority) {
					t.Fatalf("Post() error = %v, want unknown certificate authority", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Post() error = %v", err)
			}
		})
	}
}

func TestClientRedirectPolicyDoesNotChangeDefaultClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/result", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	// Without transport options or a positive timeout, client-go may reuse the default client.
	if _, err := webhook.NewClient(webhook.Options{Server: server.URL, Timeout: -1}); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("default HTTP client returned %s, want redirected response", response.Status)
	}
}

func TestClientPostMutualTLS(t *testing.T) {
	certificate, key := clientCertificate(t)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(certificate)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.TLS.PeerCertificates[0].Subject.CommonName; got != "webhook-client" {
			t.Errorf("client identity = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()

	keyPEM, err := keyutil.MarshalPrivateKeyToPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	opts := webhook.Options{
		Server:   server.URL,
		CAFile:   writeCertificate(t, server.Certificate()),
		CertFile: writeCertificate(t, certificate),
		KeyFile:  keyFile,
	}
	client, err := webhook.NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Post(t.Context(), nil, nil); err != nil {
		t.Fatalf("Post() with client certificate: %v", err)
	}

	opts.CertFile = ""
	opts.KeyFile = ""
	client, err = webhook.NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Post(t.Context(), nil, nil); err != nil {
		return
	}
	t.Fatal("Post() succeeded without the required client certificate")
}

func TestClientPostCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read request: %v", err)
		}
		close(started)
		ctx := r.Context()
		<-ctx.Done()
	}))
	defer server.Close()
	client, err := webhook.NewClient(webhook.Options{Server: server.URL, Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- client.Post(ctx, nil, nil) }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Post() error = %v, want context cancellation", err)
	}
}

func TestClientPostTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Errorf("read request: %v", err)
		}
		ctx := r.Context()
		<-ctx.Done()
	}))
	defer server.Close()
	for _, timeout := range []time.Duration{0, 20 * time.Millisecond} {
		t.Run(timeout.String(), func(t *testing.T) {
			client, err := webhook.NewClient(webhook.Options{Server: server.URL, Timeout: timeout})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Post(t.Context(), nil, nil); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("Post() error = %v, want timeout", err)
			}
		})
	}
}

func TestNewClientRejectsConflictingTransportOptions(t *testing.T) {
	certificate, _ := clientCertificate(t)
	for _, options := range []webhook.Options{
		{Server: "https://webhook.example", Username: "alice", Password: "secret", Token: "token"},
		{Server: "https://webhook.example", CAFile: writeCertificate(t, certificate), InsecureSkipTLSVerify: true},
	} {
		if _, err := webhook.NewClient(options); err != nil {
			continue
		}
		t.Error("NewClient() accepted conflicting transport options")
	}
}

func clientCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "webhook-client"}, key)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func writeCertificate(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()
	pem, err := certutil.EncodeCertificates(certificate)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, pem, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
