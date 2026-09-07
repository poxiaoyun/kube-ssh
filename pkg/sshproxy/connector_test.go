package sshproxy_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
)

func TestConnectorUsesGatewayPasswordAndPinnedHostKey(t *testing.T) {
	tests := []struct {
		name          string
		passwords     []string
		passwordsFrom []sshv1.LocalSecretKeyRef
		secrets       map[string][]byte
	}{
		{
			name:      "inline passwords",
			passwords: []string{"wrong", "upstream-secret"},
		},
		{
			name:          "referenced password",
			passwordsFrom: []sshv1.LocalSecretKeyRef{{Name: "upstream", Key: "password"}},
			secrets: map[string][]byte{
				"default/upstream:password": []byte("upstream-secret"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostSigner := newSigner(t)
			access := externalAccessFixture(hostSigner.PublicKey())
			access.Spec.Endpoints[0].Passwords = tt.passwords
			access.Spec.Endpoints[0].PasswordsFrom = tt.passwordsFrom
			source := &connectorSource{access: access, secrets: tt.secrets}
			serverConfig := &cryptossh.ServerConfig{
				PasswordCallback: func(metadata cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
					if metadata.User() != "jovyan" || string(password) != "upstream-secret" {
						return nil, fmt.Errorf("unexpected upstream credential")
					}
					return nil, nil
				},
			}
			serverConfig.AddHostKey(hostSigner)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				serveTestSSH(conn, serverConfig)
			}()
			host, port := listenerEndpoint(t, listener)
			access.Spec.Endpoints[0].Address = host
			access.Spec.Endpoints[0].Port = port
			connector := sshproxy.NewConnector(source, time.Second)

			connection, err := connector.Connect(context.Background(), sshproxy.NewTarget(access, "main"))
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
			if err := connection.Conn.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func TestConnectorRejectsChangedAccessBinding(t *testing.T) {
	hostSigner := newSigner(t)
	access := externalAccessFixture(hostSigner.PublicKey())
	tgt := sshproxy.NewTarget(access, "main")
	access.Generation++
	source := &connectorSource{access: access, secrets: map[string][]byte{}}
	connector := sshproxy.NewConnector(source, time.Second)

	if _, err := connector.Connect(context.Background(), tgt); !apierrors.IsConflict(err) {
		t.Fatalf("Connect() error = %v, want Conflict", err)
	}
}

func TestConnectorUsesGatewayPrivateKey(t *testing.T) {
	hostSigner := newSigner(t)
	_, wrongPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPrivateKeyBlock, err := cryptossh.MarshalPrivateKey(wrongPrivateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := cryptossh.NewSignerFromKey(clientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBlock, err := cryptossh.MarshalPrivateKey(clientPrivateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	access := externalAccessFixture(hostSigner.PublicKey())
	access.Spec.Endpoints[0].PasswordsFrom = nil
	access.Spec.Endpoints[0].PrivateKeys = []string{string(pem.EncodeToMemory(wrongPrivateKeyBlock))}
	access.Spec.Endpoints[0].PrivateKeysFrom = []sshv1.LocalSecretKeyRef{{Name: "upstream", Key: "private-key"}}
	source := &connectorSource{
		access: access,
		secrets: map[string][]byte{
			"default/upstream:private-key": pem.EncodeToMemory(privateKeyBlock),
		},
	}
	serverConfig := &cryptossh.ServerConfig{
		PublicKeyCallback: func(metadata cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
			if metadata.User() != "jovyan" || !bytes.Equal(key.Marshal(), clientSigner.PublicKey().
				Marshal()) {
				return nil, fmt.Errorf("unexpected upstream public key")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		serveTestSSH(conn, serverConfig)
	}()
	host, port := listenerEndpoint(t, listener)
	access.Spec.Endpoints[0].Address = host
	access.Spec.Endpoints[0].Port = port
	connector := sshproxy.NewConnector(source, time.Second)

	connection, err := connector.Connect(context.Background(), sshproxy.NewTarget(access, "main"))
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := connection.Conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestConnectorRejectsAddressOutsideDNSOrIP(t *testing.T) {
	hostSigner := newSigner(t)
	access := externalAccessFixture(hostSigner.PublicKey())
	access.Spec.Endpoints[0].Address = "ssh://notebook.example.com:22/path"
	source := &connectorSource{
		access: access,
		secrets: map[string][]byte{
			"default/upstream:password": []byte("upstream-secret"),
		},
	}
	connector := sshproxy.NewConnector(source, time.Second)

	if _, err := connector.Connect(context.Background(), sshproxy.NewTarget(access, "main")); err == nil {
		t.Fatal("Connect() error = nil, want invalid endpoint address error")
	}
}

type connectorSource struct {
	access  *sshv1.Access
	secrets map[string][]byte
}

func (s *connectorSource) Get(_ context.Context, namespace, name string) (*sshv1.Access, error) {
	if s.access == nil || s.access.Namespace != namespace || s.access.Name != name {
		return nil, fmt.Errorf("Access not found")
	}
	return s.access.DeepCopy(), nil
}

func (s *connectorSource) SecretValue(namespace string, ref sshv1.LocalSecretKeyRef) ([]byte, error) {
	value, ok := s.secrets[namespace+"/"+ref.Name+":"+ref.Key]
	if !ok {
		return nil, fmt.Errorf("Secret value not found")
	}
	return append([]byte(nil), value...), nil
}

func externalAccessFixture(hostKey cryptossh.PublicKey) *sshv1.Access {
	return &sshv1.Access{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "notebook", UID: types.UID("access-uid"), Generation: 3},
		Spec: sshv1.AccessSpec{
			Type: sshv1.AccessTypeExternal,
			Endpoints: []sshv1.AccessEndpoint{{
				Name:          "main",
				Address:       "notebook-ssh.default.svc",
				Port:          2222,
				Username:      "jovyan",
				PasswordsFrom: []sshv1.LocalSecretKeyRef{{Name: "upstream", Key: "password"}},
				PublicKeys:    []string{string(cryptossh.MarshalAuthorizedKey(hostKey))},
			}},
		},
	}
}

func newSigner(t *testing.T) cryptossh.Signer {
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

func listenerEndpoint(t *testing.T, listener net.Listener) (string, int32) {
	t.Helper()
	host, rawPort, err := net.SplitHostPort(listener.Addr().
		String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseInt(rawPort, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return host, int32(port)
}

func serveTestSSH(conn net.Conn, config *cryptossh.ServerConfig) {
	server, channels, requests, err := cryptossh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	go cryptossh.DiscardRequests(requests)
	for channel := range channels {
		_ = channel.Reject(cryptossh.UnknownChannelType, "not used")
	}
	_ = server.Close()
}
