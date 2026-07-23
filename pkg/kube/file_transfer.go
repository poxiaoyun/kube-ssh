package kube

import (
	"context"
	"fmt"
	"io"
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func (b *Backend) SFTP(ctx context.Context, req backend.StreamRequest) (int, error) {
	return b.execHelperCommand(ctx, req.Target, helperpkg.CapabilitySFTP, []string{helperpkg.CapabilitySFTP}, req.Stdin, req.Stdout, req.Stderr)
}

func (b *Backend) SCP(ctx context.Context, req backend.SCPRequest) (int, error) {
	command := append([]string{helperpkg.CapabilitySCP}, req.Args...)
	return b.execHelperCommand(ctx, req.Target, helperpkg.CapabilitySCP, command, req.Stdin, req.Stdout, req.Stderr)
}

func (b *Backend) execHelperCommand(ctx context.Context, tgt *target.Target, capability string, command []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	exitCode, err := b.execHelper(ctx, tgt, capability, command, backend.StreamRequest{Target: tgt, Stdin: stdin, Stdout: stdout, Stderr: stderr})
	if err != nil {
		return exitCode, err
	}
	if exitCode != 0 {
		return exitCode, fmt.Errorf("helper %s exited with %d", strings.Join(command, " "), exitCode)
	}
	return exitCode, nil
}

func (b *Backend) execHelper(ctx context.Context, tgt *target.Target, capability string, command []string, stream backend.StreamRequest) (int, error) {
	if b.helperExecOverride != nil {
		return b.helperExecOverride(ctx, tgt, capability, command, stream)
	}
	helper, err := b.acquireHelper(ctx, tgt, capability)
	if err != nil {
		return 1, err
	}
	defer func() { _ = helper.Release(context.WithoutCancel(ctx)) }()

	return b.exec(ctx, backend.ExecRequest{
		Target:  tgt,
		Command: helper.Command(command...),
		Stdin:   stream.Stdin,
		Stdout:  stream.Stdout,
		Stderr:  stream.Stderr,
		TTY:     false,
	})
}
