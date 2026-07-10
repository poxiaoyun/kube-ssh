//go:build e2e

package e2e

import (
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestPublicKeyAuthentication(t *testing.T) {
	signer, authorizedKey := newTestSigner(t)
	otherSigner, _ := newTestSigner(t)
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authorization-allow-all",
			"--authorized-key", "alice@example.com=" + authorizedKey,
		},
	})
	user := f.Namespace + ".shell.app"

	output, err := f.SSHClientExec(user, cryptossh.PublicKeys(signer), "echo publickey-ok")
	if err != nil {
		t.Fatalf("public key auth exec failed: %v\n%s", err, output)
	}
	if output != "publickey-ok\n" {
		t.Fatalf("output = %q, want publickey-ok\\n", output)
	}

	if output, err := f.SSHClientExec(user, cryptossh.PublicKeys(otherSigner), "echo rejected"); err == nil {
		t.Fatalf("unexpected public key auth success:\n%s", output)
	}
}

func TestPasswordAuthentication(t *testing.T) {
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authorization-allow-all",
			"--authentication-password", "alice@example.com=secret",
		},
	})
	user := f.Namespace + ".shell.app"

	output, err := f.SSHClientExec(user, cryptossh.Password("secret"), "echo password-ok")
	if err != nil {
		t.Fatalf("password auth exec failed: %v\n%s", err, output)
	}
	if output != "password-ok\n" {
		t.Fatalf("output = %q, want password-ok\\n", output)
	}

	if output, err := f.SSHClientExec(user, cryptossh.Password("bad"), "echo rejected"); err == nil {
		t.Fatalf("unexpected password auth success:\n%s", output)
	}
}
