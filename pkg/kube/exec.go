package kube

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/status"
)

// Exec runs a command in a pod container and returns the process exit code.
// A nil error with a non-zero exit code means the command ran but exited non-zero;
// a non-nil error means the exec itself failed.
func (b *Backend) Exec(ctx context.Context, req backend.ExecRequest) (int, error) {
	podTarget, err := ParseTarget(req.Target)
	if err != nil {
		return 1, err
	}
	opts := &corev1.PodExecOptions{
		Container: podTarget.Container,
		Command:   req.Command,
		Stdin:     req.Stdin != nil,
		Stdout:    req.Stdout != nil,
		Stderr:    !req.TTY && req.Stderr != nil,
		TTY:       req.TTY,
	}
	restReq := b.client.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podTarget.Pod).
		Namespace(podTarget.Namespace).
		SubResource("exec").
		VersionedParams(opts, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(b.restConfig, "POST", restReq.URL())
	if err != nil {
		return 1, status.BackendFailure(err, "create executor")
	}
	streamOpts := remotecommand.StreamOptions{Stdin: req.Stdin, Stdout: req.Stdout, Tty: req.TTY}
	if req.TerminalSizeQueue != nil {
		streamOpts.TerminalSizeQueue = terminalSizeQueue{queue: req.TerminalSizeQueue}
	}
	if !req.TTY {
		streamOpts.Stderr = req.Stderr
	}
	if err := executor.StreamWithContext(ctx, streamOpts); err != nil {
		var exitError interface{ ExitStatus() int }
		if errors.As(err, &exitError) {
			return exitError.ExitStatus(), nil
		}
		return 1, status.BackendFailure(err, "exec stream")
	}
	return 0, nil
}

func (b *Backend) exec(ctx context.Context, req backend.ExecRequest) (int, error) {
	if b.execOverride != nil {
		return b.execOverride(ctx, req)
	}
	return b.Exec(ctx, req)
}

type terminalSizeQueue struct {
	queue backend.TerminalSizeQueue
}

func (q terminalSizeQueue) Next() *remotecommand.TerminalSize {
	size := q.queue.Next()
	if size == nil {
		return nil
	}
	return &remotecommand.TerminalSize{Width: size.Width, Height: size.Height}
}
