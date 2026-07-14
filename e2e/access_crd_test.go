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

func TestAccessCRDSharedPublicKeyIsScopedByTarget(t *testing.T) {
	signer, authorizedKey := newTestSigner(t)
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--access-policy-enabled",
			"--authorization-allow-all",
		},
		BeforeStart: func(f *Framework) {
			f.InstallAccessCRD()
			f.ApplyManifest(fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: shell-second
  namespace: %[1]s
  labels:
    app: shell-second
spec:
  containers:
  - name: app
    image: alpine:3.20
    command: ["sh", "-c", "sleep infinity"]
---
apiVersion: ssh.xiaoshiai.cn/v1
kind: Access
metadata:
  name: shell-first
  namespace: %[1]s
spec:
  selector:
    app: shell
  credentials:
  - username: alice
    publicKeys:
    - %[2]q
---
apiVersion: ssh.xiaoshiai.cn/v1
kind: Access
metadata:
  name: shell-second
  namespace: %[1]s
spec:
  selector:
    app: shell-second
  credentials:
  - username: bob
    publicKeys:
    - %[2]q
`, f.Namespace, authorizedKey))
			f.WaitPodReady("shell-second", 60*time.Second)
		},
	})
	f.WaitAccessReady("shell-first", 30*time.Second)
	f.WaitAccessReady("shell-second", 30*time.Second)

	for _, tc := range []struct {
		access string
		want   string
	}{
		{access: "shell-first", want: "shell"},
		{access: "shell-second", want: "shell-second"},
	} {
		user := f.Namespace + "." + tc.access
		output, err := f.SSHClientExec(user, cryptossh.PublicKeys(signer), "hostname")
		if err != nil {
			t.Fatalf("shared-key access through %s failed: %v\n%s", tc.access, err, output)
		}
		if output != tc.want+"\n" {
			t.Fatalf("shared-key access through %s output = %q, want %q", tc.access, output, tc.want+"\n")
		}
	}
}

func TestAccessExplicitStatefulSetPod(t *testing.T) {
	signer, authorizedKey := newTestSigner(t)
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--access-policy-enabled",
			"--authorization-allow-all",
		},
		BeforeStart: func(f *Framework) {
			f.InstallAccessCRD()
			f.ApplyManifest(fmt.Sprintf(`
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: stateful-shell
  namespace: %[1]s
spec:
  serviceName: stateful-shell-unused
  replicas: 3
  podManagementPolicy: Parallel
  selector:
    matchLabels:
      app: stateful-shell
  template:
    metadata:
      labels:
        app: stateful-shell
    spec:
      affinity:
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels:
                app: shell
            topologyKey: kubernetes.io/hostname
      containers:
      - name: app
        image: alpine:3.20
        command: ["sh", "-c", "sleep infinity"]
---
apiVersion: ssh.xiaoshiai.cn/v1
kind: Access
metadata:
  name: stateful-shell
  namespace: %[1]s
spec:
  selector:
    app: stateful-shell
  containers:
  - app
  credentials:
  - username: alice
    publicKeys:
    - %[2]q
`, f.Namespace, authorizedKey))
		},
	})
	for ordinal := range 3 {
		f.WaitPodReady(fmt.Sprintf("stateful-shell-%d", ordinal), 60*time.Second)
	}
	f.WaitAccessReady("stateful-shell", 30*time.Second)

	for ordinal := range 3 {
		pod := fmt.Sprintf("stateful-shell-%d", ordinal)
		user := fmt.Sprintf("%s.stateful-shell~%s", f.Namespace, pod)
		output, err := f.SSHClientExec(user, cryptossh.PublicKeys(signer), "hostname")
		if err != nil {
			t.Fatalf("explicit access to %s failed: %v\n%s", pod, err, output)
		}
		if output != pod+"\n" {
			t.Fatalf("explicit access to %s output = %q, want %q", pod, output, pod+"\n")
		}
	}

	outsideUser := f.Namespace + ".stateful-shell~shell"
	if output, err := f.SSHClientExec(outsideUser, cryptossh.PublicKeys(signer), "hostname"); err == nil {
		t.Fatalf("selector-external pod access unexpectedly succeeded: %s", output)
	}
}
