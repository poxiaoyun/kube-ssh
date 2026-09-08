//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

func TestSSHExec(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"

	result := f.SSH(user, "echo ok; exit 7")
	if result.Code != 7 {
		t.Fatalf("exit code = %d, want 7\n%s", result.Code, result.Dump())
	}
	if result.Stdout != "ok\n" {
		t.Fatalf("stdout = %q, want ok\\n\n%s", result.Stdout, result.Dump())
	}
}

func TestShell(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"

	result := f.Shell(user, "echo shell-ok\nexit\n")
	if result.Code != 0 {
		t.Fatalf("shell failed:\n%s", result.Dump())
	}
	if !strings.Contains(result.Stdout, "shell-ok") {
		t.Fatalf("shell stdout missing marker:\n%s", result.Dump())
	}
}

func TestAuthorizationDeniesSessionOperations(t *testing.T) {
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authentication-anonymous",
			"--policy-limit-capability", "shell",
		},
	})
	user := f.Namespace + ".shell.app"

	execResult := f.SSH(user, "echo denied")
	if execResult.Code == 0 {
		t.Fatalf("exec unexpectedly allowed:\n%s", execResult.Dump())
	}
}
