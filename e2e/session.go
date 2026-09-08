//go:build e2e

package e2e

import (
	"io"
	"strings"
	"time"
)

func (f *Framework) SSH(user string, args ...string) Result {
	allArgs := []string{"-F", f.SSHConfig, "-l", user, "kube-ssh-e2e"}
	allArgs = append(allArgs, args...)
	return runE2ECommand(30*time.Second, "ssh", allArgs, nil, nil)
}

func (f *Framework) SSHOptions(user string, args ...string) Result {
	return f.SSHOptionsTimeout(30*time.Second, user, args...)
}

func (f *Framework) SSHOptionsTimeout(timeout time.Duration, user string, args ...string) Result {
	allArgs := []string{"-F", f.SSHConfig}
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, "-l", user, "kube-ssh-e2e")
	return runE2ECommand(timeout, "ssh", allArgs, nil, nil)
}

func (f *Framework) Shell(user string, input string) Result {
	args := []string{"-F", f.SSHConfig, "-l", user, "kube-ssh-e2e"}
	return runE2ECommand(30*time.Second, "ssh", args, strings.NewReader(input), nil)
}

func (f *Framework) StartSSH(user string, args ...string) *BackgroundCommand {
	allArgs := []string{"-F", f.SSHConfig}
	allArgs = append(allArgs, args...)
	allArgs = append(allArgs, "-l", user, "kube-ssh-e2e")
	return f.startCommandWithStdin("ssh", allArgs, nil, nil)
}

func (f *Framework) StartSSHCommandWithStdin(user, command string) *BackgroundCommand {
	stdinReader, stdinWriter := io.Pipe()
	args := []string{"-F", f.SSHConfig, "-l", user, "kube-ssh-e2e", command}
	cmd := f.startCommandWithStdin("ssh", args, stdinReader, nil)
	cmd.Stdin = stdinWriter
	return cmd
}
