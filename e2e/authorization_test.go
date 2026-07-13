//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

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

func TestAuthorizationDeniesFileTransfer(t *testing.T) {
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authentication-anonymous",
			"--policy-limit-capability", "shell",
		},
	})
	user := f.Namespace + ".shell.app"

	sftpResult := f.SFTPBatch(user, "ls /tmp\n")
	if sftpResult.Code == 0 {
		t.Fatalf("sftp unexpectedly allowed:\n%s", sftpResult.Dump())
	}
}

func TestAuthorizationDeniesForwarding(t *testing.T) {
	f := NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authentication-anonymous",
			"--policy-limit-capability", "shell",
		},
	})
	user := f.Namespace + ".shell.app"

	localPort := freePort(t)
	localAddress := fmt.Sprintf("127.0.0.1:%d", localPort)
	localForward := f.StartSSH(user, "-N", "-o", "ExitOnForwardFailure=yes", "-L", localAddress+":127.0.0.1:18080")
	f.waitTCP("127.0.0.1", localPort, 10*time.Second)
	localResult := f.HTTPGetTimeout("http://"+localAddress+"/", 3*time.Second)
	if localResult.Code == http.StatusOK {
		t.Fatalf("local forward unexpectedly allowed:\n%s", localResult.Dump())
	}
	localForward.Stop()

	local := f.StartLocalHTTPServer("denied\n")
	remoteForward := f.SSHOptionsTimeout(5*time.Second, user, "-N", "-o", "ExitOnForwardFailure=yes", "-R", fmt.Sprintf("127.0.0.1:%d:%s", freePort(t), local.Address))
	if remoteForward.Code == 0 {
		t.Fatalf("remote forward unexpectedly allowed:\n%s", remoteForward.Dump())
	}
}
