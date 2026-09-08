package apiserver

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	"xiaoshiai.cn/kube-ssh/pkg/podtarget"
)

// Exec runs a command in a pod container and returns the process exit code.
// A nil error with a non-zero exit code means the command ran but exited non-zero;
// a non-nil error means the exec itself failed.
func (b *Transport) Exec(ctx context.Context, req backend.ExecRequest) (int, error) {
	if b.execOverride != nil {
		return b.execOverride(ctx, req)
	}
	podTarget, err := podtarget.Parse(req.Target)
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
	restReq := b.client.
		CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(podTarget.Pod).
		Namespace(podTarget.Namespace).
		SubResource("exec").
		VersionedParams(opts, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(b.restConfig, "POST", restReq.URL())
	if err != nil {
		return 1, fmt.Errorf("create executor: %w", err)
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
		return 1, fmt.Errorf("exec stream: %w", err)
	}
	return 0, nil
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
