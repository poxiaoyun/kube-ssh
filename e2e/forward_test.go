//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestLocalForward(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	localPort := freePort(t)
	localAddress := fmt.Sprintf("127.0.0.1:%d", localPort)

	ssh := f.StartSSH(user, "-N", "-o", "ExitOnForwardFailure=yes", "-L", localAddress+":127.0.0.1:18080")
	f.waitTCP("127.0.0.1", localPort, 10*time.Second)
	f.WaitHTTPBody("http://"+localAddress+"/", "local-forward\n", 30*time.Second)
	ssh.Stop()
}

func TestLocalForwardToServiceUsesHelperDial(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	localPort := freePort(t)
	localAddress := fmt.Sprintf("127.0.0.1:%d", localPort)
	serviceHost := "echo." + f.Namespace + ".svc.cluster.local"

	ssh := f.StartSSH(user, "-N", "-o", "ExitOnForwardFailure=yes", "-L", localAddress+":"+serviceHost+":18080")
	f.waitTCP("127.0.0.1", localPort, 10*time.Second)
	f.WaitHTTPBody("http://"+localAddress+"/", "local-forward\n", 30*time.Second)
	ssh.Stop()
}

func TestRemoteForwardAndCancel(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	local := f.StartLocalHTTPServer("remote-forward\n")
	remotePort := freePort(t)
	controlPath := fmt.Sprintf("/tmp/kssh-%d.sock", time.Now().UnixNano())
	t.Cleanup(func() { _ = os.Remove(controlPath) })
	forwardSpec := fmt.Sprintf("127.0.0.1:%d:%s", remotePort, local.Address)

	ssh := f.StartSSH(user,
		"-M",
		"-S", controlPath,
		"-N",
		"-o", "ExitOnForwardFailure=yes",
		"-R", forwardSpec,
	)
	f.WaitHelperProcessCount(user, 1, 10*time.Second)
	waitRemoteForwardBody(t, f, user, remotePort, "remote-forward\n")

	cancel := f.SSHOptions(user, "-S", controlPath, "-O", "cancel", "-R", forwardSpec)
	if cancel.Code != 0 {
		t.Fatalf("remote forward cancel failed:\n%s", cancel.Dump())
	}
	ssh.Stop()
}
