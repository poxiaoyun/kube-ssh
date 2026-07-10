//go:build e2e

package e2e

import (
	"fmt"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
)

func TestAccessCRDAuthentication(t *testing.T) {
	signer, authorizedKey := newTestSigner(t)
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--access-policy-enabled",
			"--authorization-allow-all",
		},
		BeforeStart: func(f *Framework) {
			f.InstallAccessCRD()
			f.ApplyManifest(fmt.Sprintf(`
apiVersion: ssh.xiaoshiai.cn/v1
kind: Access
metadata:
  name: shell
  namespace: %[1]s
spec:
  selector:
    app: shell
  credentials:
  - username: alice
    groups:
    - dev
    passwords:
    - crd-password
    publicKeys:
    - %q
`, f.Namespace, authorizedKey))
		},
	})
	f.WaitAccessReady("shell", 30*time.Second)

	user := f.Namespace + ".shell"
	output, err := f.SSHClientExec(user, cryptossh.Password("crd-password"), "echo crd-password-ok")
	if err != nil {
		t.Fatalf("crd password auth exec failed: %v\n%s", err, output)
	}
	if output != "crd-password-ok\n" {
		t.Fatalf("password output = %q, want crd-password-ok\\n", output)
	}

	output, err = f.SSHClientExec(user, cryptossh.PublicKeys(signer), "echo crd-key-ok")
	if err != nil {
		t.Fatalf("crd public key auth exec failed: %v\n%s", err, output)
	}
	if output != "crd-key-ok\n" {
		t.Fatalf("public key output = %q, want crd-key-ok\\n", output)
	}
}
