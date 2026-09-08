package backend

import (
	"context"
	"fmt"
	"strings"

	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
)

// SFTP serves a file-transfer session through the target-side helper.
func (b *Executor) SFTP(ctx context.Context, req StreamRequest) (int, error) {
	return b.execHelperCommand(ctx, helperpkg.CapabilitySFTP, []string{helperpkg.CapabilitySFTP}, req)
}

// SCP serves a legacy SCP session through the target-side helper.
func (b *Executor) SCP(ctx context.Context, req SCPRequest) (int, error) {
	command := append([]string{helperpkg.CapabilitySCP}, req.Args...)
	return b.execHelperCommand(ctx, helperpkg.CapabilitySCP, command, req.StreamRequest)
}

func (b *Executor) execHelperCommand(ctx context.Context, capability string, command []string, stream StreamRequest) (int, error) {
	exitCode, err := b.execHelper(ctx, capability, command, stream)
	if err != nil {
		return exitCode, err
	}
	if exitCode != 0 {
		return exitCode, fmt.Errorf("helper %s exited with %d", strings.Join(command, " "), exitCode)
	}
	return exitCode, nil
}

func (b *Executor) execHelper(ctx context.Context, capability string, command []string, stream StreamRequest) (int, error) {
	return b.transport.ExecHelper(ctx, HelperExecRequest{
		StreamRequest: stream,
		Capability:    capability,
		Command:       command,
	})
}
