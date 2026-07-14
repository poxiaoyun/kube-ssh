//go:build e2e

package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidUsernameIsRejected(t *testing.T) {
	f := NewFramework(t)

	result := f.SSH("bad", "echo should-not-run")
	if result.Code == 0 {
		t.Fatalf("invalid username unexpectedly succeeded:\n%s", result.Dump())
	}
}

func TestMissingKubernetesTargetsAreRejected(t *testing.T) {
	f := NewFramework(t)

	tests := []struct {
		name string
		user string
	}{
		{name: "namespace", user: "kube-ssh-e2e-missing.shell.app"},
		{name: "pod", user: f.Namespace + ".missing.app"},
		{name: "container", user: f.Namespace + ".shell.missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := f.SSH(tt.user, "echo should-not-run")
			if result.Code == 0 {
				t.Fatalf("missing target unexpectedly succeeded:\n%s", result.Dump())
			}
			output := result.Stdout + result.Stderr
			if !strings.Contains(output, "Permission denied") {
				t.Fatalf("missing target error missing authentication rejection:\n%s", result.Dump())
			}
			if strings.Contains(output, "InvalidTarget") || strings.Contains(output, "BackendFailure") {
				t.Fatalf("missing target error leaked an internal failure reason:\n%s", result.Dump())
			}
		})
	}
}

func TestHelperUnavailableFailsClearly(t *testing.T) {
	missingHelper := filepath.Join(t.TempDir(), "missing-kube-ssh-helper")
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authentication-anonymous",
			"--authorization-allow-all",
			"--helper-path", missingHelper,
		},
	})
	user := f.Namespace + ".shell.app"

	sftp := f.SFTPBatch(user, "ls /tmp\n")
	if sftp.Code == 0 {
		t.Fatalf("sftp unexpectedly succeeded with missing helper:\n%s", sftp.Dump())
	}
	if !strings.Contains(sftp.Stdout+sftp.Stderr, "HelperUnavailable") {
		t.Fatalf("sftp error missing HelperUnavailable reason:\n%s", sftp.Dump())
	}
}
