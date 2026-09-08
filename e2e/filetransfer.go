//go:build e2e

package e2e

import (
	"io"
	"os"
	"path/filepath"
	"time"
)

func (f *Framework) SCP(args ...string) Result {
	allArgs := []string{"-O", "-F", f.SSHConfig}
	allArgs = append(allArgs, args...)
	return runE2ECommand(45*time.Second, "scp", allArgs, nil, nil)
}

func (f *Framework) StartSCP(args ...string) *BackgroundCommand {
	allArgs := []string{"-O", "-F", f.SSHConfig}
	allArgs = append(allArgs, args...)
	return f.startCommandWithStdin("scp", allArgs, nil, nil)
}

func (f *Framework) SFTPBatch(user, batch string) Result {
	batchPath := filepath.Join(f.WorkDir, "sftp.batch")
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		f.T.Fatalf("write sftp batch: %v", err)
	}
	args := []string{"-F", f.SSHConfig, "-b", batchPath, user + "@kube-ssh-e2e"}
	return runE2ECommand(45*time.Second, "sftp", args, nil, nil)
}

func (f *Framework) StartSFTP(user string) *BackgroundCommand {
	stdinReader, stdinWriter := io.Pipe()
	args := []string{"-F", f.SSHConfig, user + "@kube-ssh-e2e"}
	cmd := f.startCommandWithStdin("sftp", args, stdinReader, nil)
	cmd.Stdin = stdinWriter
	return cmd
}

func (f *Framework) RemotePath(name string) string {
	return "/tmp/kube-ssh-e2e-" + f.TestID + "-" + name
}
