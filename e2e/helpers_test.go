//go:build e2e

package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("%s content = %q, want %q", path, string(data), want)
	}
}

func (f *Framework) SSHClientExec(user string, auth cryptossh.AuthMethod, command string) (string, error) {
	f.T.Helper()
	config := &cryptossh.ClientConfig{
		User:            user,
		Auth:            []cryptossh.AuthMethod{auth},
		HostKeyCallback: cryptossh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}
	client, err := cryptossh.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", f.GatewayPort)), config)
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.CombinedOutput(command)
	return string(output), err
}

func newTestSigner(t *testing.T) (cryptossh.Signer, string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer, strings.TrimSpace(string(cryptossh.MarshalAuthorizedKey(signer.PublicKey())))
}

func waitRemoteForwardBody(t *testing.T, f *Framework, user string, port int, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last Result
	command := fmt.Sprintf("wget -qO- http://127.0.0.1:%d/", port)
	for time.Now().Before(deadline) {
		last = f.SSH(user, command)
		if last.Code == 0 && strings.Contains(last.Stdout, want) {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for remote forward body %q; last result:\n%s", want, last.Dump())
}
