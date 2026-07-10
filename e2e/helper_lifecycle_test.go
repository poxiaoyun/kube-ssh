//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func TestSFTPAbortDoesNotLeaveHelperProcess(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	f.WaitHelperProcessCount(user, 0, 5*time.Second)

	sftp := f.StartSFTP(user)
	f.WaitHelperProcessCount(user, 1, 5*time.Second)
	sftp.Stop()

	f.WaitHelperProcessCount(user, 0, 10*time.Second)
}

func TestSCPAbortDoesNotLeaveHelperProcess(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	f.WaitHelperProcessCount(user, 0, 5*time.Second)

	ssh := f.StartSSHCommandWithStdin(user, "scp -t "+f.RemotePath("scp-abort.bin"))
	if _, err := ssh.Stdin.(*io.PipeWriter).Write([]byte("C0644 1048576 scp-abort.bin\npartial")); err != nil {
		ssh.Stop()
		t.Fatalf("write scp protocol: %v", err)
	}
	f.WaitHelperProcessCount(user, 1, 5*time.Second)
	ssh.Stop()

	f.WaitHelperProcessCount(user, 0, 10*time.Second)
}

func TestHelperDialAbortDoesNotLeaveHelperProcess(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	serviceHost := "echo." + f.Namespace + ".svc.cluster.local"
	localPort := freePort(t)
	localAddress := fmt.Sprintf("127.0.0.1:%d", localPort)
	f.WaitHelperProcessCount(user, 0, 5*time.Second)

	ssh := f.StartSSH(user, "-N", "-o", "ExitOnForwardFailure=yes", "-L", localAddress+":"+serviceHost+":18081")
	f.waitTCP("127.0.0.1", localPort, 10*time.Second)
	conn, err := net.DialTimeout("tcp", localAddress, 5*time.Second)
	if err != nil {
		ssh.Stop()
		t.Fatalf("dial local forward: %v", err)
	}
	if _, err := conn.Write([]byte("hold\n")); err != nil {
		_ = conn.Close()
		ssh.Stop()
		t.Fatalf("write local forward: %v", err)
	}

	ssh.Stop()
	_ = conn.Close()
	f.WaitHelperProcessCount(user, 0, 10*time.Second)
}

func TestRemoteForwardAbortDoesNotLeaveHelperProcess(t *testing.T) {
	f := NewFramework(t)
	user := f.Namespace + ".shell.app"
	local := f.StartLocalHTTPServer("remote-forward\n")
	f.WaitHelperProcessCount(user, 0, 5*time.Second)

	ssh := f.StartSSH(user,
		"-N",
		"-o", "ExitOnForwardFailure=yes",
		"-R", "127.0.0.1:0:"+local.Address,
	)
	f.WaitHelperProcessCount(user, 1, 10*time.Second)
	ssh.Stop()

	f.WaitHelperProcessCount(user, 0, 10*time.Second)
}
