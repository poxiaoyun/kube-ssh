package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// DefaultConnectTimeout bounds an upstream TCP dial and SSH handshake.
const DefaultConnectTimeout = 30 * time.Second

// Source provides the current Access and same-namespace Secret snapshots used
// to establish an upstream connection.
type Source interface {
	// Get returns an Access owned by this gateway.
	Get(ctx context.Context, namespace, name string) (*sshv1.Access, error)
	// SecretValue returns one key from a Secret in the Access namespace.
	SecretValue(namespace string, ref sshv1.LocalSecretKeyRef) ([]byte, error)
}

// Connection is a raw upstream SSH transport. Incoming channels and requests
// remain unconsumed for the protocol proxy.
type Connection struct {
	Conn     cryptossh.Conn
	Channels <-chan cryptossh.NewChannel
	Requests <-chan *cryptossh.Request
}

// ConnectionConnector establishes a raw upstream SSH transport for a bound
// External Access target.
type ConnectionConnector interface {
	// Connect resolves credentials and performs one TCP and SSH handshake.
	Connect(ctx context.Context, tgt *target.Target) (*Connection, error)
}

// Connector owns External Access endpoint resolution and upstream SSH trust.
type Connector struct {
	source         Source
	connectTimeout time.Duration
}

// NewConnector creates an upstream SSH connector.
func NewConnector(source Source, connectTimeout time.Duration) *Connector {
	return &Connector{source: source, connectTimeout: connectTimeout}
}

// Connect resolves and authenticates the endpoint bound to tgt.
func (c *Connector) Connect(ctx context.Context, tgt *target.Target) (*Connection, error) {
	connectCtx, cancel := context.WithTimeout(ctx, c.connectTimeout)
	defer cancel()
	bound, err := parseTarget(tgt)
	if err != nil {
		return nil, err
	}
	access, err := c.source.Get(ctx, bound.Namespace, bound.Access)
	if err != nil {
		return nil, fmt.Errorf("get External Access: %w", err)
	}
	if string(access.UID) != bound.AccessUID || access.Generation != bound.Generation {
		return nil, apierrors.NewConflict(sshv1.Resource("accesses"), bound.Access, fmt.Errorf("external Access %s/%s changed after target resolution", bound.Namespace, bound.Access))
	}
	if access.Spec.Type != sshv1.AccessTypeExternal {
		return nil, fmt.Errorf("access %s/%s is not External", bound.Namespace, bound.Access)
	}
	endpoint, ok := findEndpoint(access.Spec.Endpoints, bound.Endpoint)
	if !ok {
		return nil, fmt.Errorf("endpoint %q no longer exists in Access %s/%s", bound.Endpoint, bound.Namespace, bound.Access)
	}
	config, err := c.endpointConfig(access.Namespace, endpoint)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{}).
		DialContext(connectCtx, "tcp", config.address)
	if err != nil {
		return nil, fmt.Errorf("dial endpoint %q: %w", endpoint.Name, err)
	}
	deadline, _ := connectCtx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, fmt.Errorf("set endpoint %q handshake deadline: %w", endpoint.Name, err)
	}
	sshConn, channels, requests, err := cryptossh.NewClientConn(conn, config.address, &cryptossh.ClientConfig{
		User:            endpoint.Username,
		Auth:            []cryptossh.AuthMethod{config.auth},
		HostKeyCallback: config.hostKey,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("authenticate endpoint %q: %w", endpoint.Name, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		sshConn.Close()
		return nil, fmt.Errorf("clear endpoint %q handshake deadline: %w", endpoint.Name, err)
	}
	return &Connection{Conn: sshConn, Channels: channels, Requests: requests}, nil
}

type endpointConfig struct {
	address string
	auth    cryptossh.AuthMethod
	hostKey cryptossh.HostKeyCallback
}

func (c *Connector) endpointConfig(namespace string, endpoint sshv1.AccessEndpoint) (endpointConfig, error) {
	address, err := endpointAddress(endpoint)
	if err != nil {
		return endpointConfig{}, fmt.Errorf("load endpoint %q address: %w", endpoint.Name, err)
	}
	auth, err := c.authMethod(namespace, endpoint)
	if err != nil {
		return endpointConfig{}, fmt.Errorf("load endpoint %q authentication: %w", endpoint.Name, err)
	}
	hostKey, err := c.hostKeyCallback(namespace, endpoint)
	if err != nil {
		return endpointConfig{}, fmt.Errorf("load endpoint %q host keys: %w", endpoint.Name, err)
	}
	return endpointConfig{address: address, auth: auth, hostKey: hostKey}, nil
}

func endpointAddress(endpoint sshv1.AccessEndpoint) (string, error) {
	if net.ParseIP(endpoint.Address) == nil {
		if problems := validation.IsDNS1123Subdomain(endpoint.Address); len(problems) > 0 {
			return "", fmt.Errorf("address must be a DNS name or IP")
		}
	}
	return net.JoinHostPort(endpoint.Address, strconv.Itoa(int(endpoint.Port))), nil
}

func (c *Connector) authMethod(namespace string, endpoint sshv1.AccessEndpoint) (cryptossh.AuthMethod, error) {
	if len(endpoint.PrivateKeys) > 0 || len(endpoint.PrivateKeysFrom) > 0 {
		privateKeys := make([][]byte, 0, len(endpoint.PrivateKeys)+len(endpoint.PrivateKeysFrom))
		for _, value := range endpoint.PrivateKeys {
			privateKeys = append(privateKeys, []byte(value))
		}
		for _, ref := range endpoint.PrivateKeysFrom {
			value, err := c.source.SecretValue(namespace, ref)
			if err != nil {
				return nil, err
			}
			privateKeys = append(privateKeys, value)
		}
		signers := make([]cryptossh.Signer, 0, len(privateKeys))
		for _, value := range privateKeys {
			signer, err := cryptossh.ParsePrivateKey(value)
			if err != nil {
				return nil, fmt.Errorf("parse private key: %w", err)
			}
			signers = append(signers, signer)
		}
		return cryptossh.PublicKeys(signers...), nil
	}
	passwords := append([]string(nil), endpoint.Passwords...)
	for _, ref := range endpoint.PasswordsFrom {
		value, err := c.source.SecretValue(namespace, ref)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, string(value))
	}
	next := 0
	return cryptossh.RetryableAuthMethod(cryptossh.PasswordCallback(func() (string, error) {
		password := passwords[next]
		next++
		return password, nil
	}), len(passwords)), nil
}

func (c *Connector) hostKeyCallback(namespace string, endpoint sshv1.AccessEndpoint) (cryptossh.HostKeyCallback, error) {
	if endpoint.InsecureSkipVerification {
		return cryptossh.InsecureIgnoreHostKey(), nil
	}
	lines := append([]string(nil), endpoint.PublicKeys...)
	for _, ref := range endpoint.PublicKeysFrom {
		value, err := c.source.SecretValue(namespace, ref)
		if err != nil {
			return nil, err
		}
		lines = append(lines, splitLines(string(value))...)
	}
	keys := make([]cryptossh.PublicKey, 0, len(lines))
	for _, line := range lines {
		key, _, _, _, err := cryptossh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one public key is required unless insecureSkipVerification is true")
	}
	return func(_ string, _ net.Addr, presented cryptossh.PublicKey) error {
		for _, expected := range keys {
			if bytes.Equal(expected.Marshal(), presented.Marshal()) {
				return nil
			}
		}
		return fmt.Errorf("upstream host key %s is not pinned", cryptossh.FingerprintSHA256(presented))
	}, nil
}

func findEndpoint(endpoints []sshv1.AccessEndpoint, name string) (sshv1.AccessEndpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.Name == name {
			return endpoint, true
		}
	}
	return sshv1.AccessEndpoint{}, false
}

func splitLines(value string) []string {
	lines := bytes.Split([]byte(value), []byte{'\n'})
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) > 0 {
			result = append(result, string(line))
		}
	}
	return result
}
