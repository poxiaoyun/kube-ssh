package backend

import (
	"context"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

const (
	operationExec          = "exec"
	operationPortForward   = "port_forward"
	operationRemoteForward = "remote_forward"
	operationAgentForward  = "agent_forward"
	operationSFTP          = "sftp"
	operationSCP           = "scp"
)

// WithMetrics records each completed backend operation; a nil recorder disables recording.
func WithMetrics(next Backend, recorder metrics.BackendRecorder) Backend {
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	return &metricsBackend{next: next, recorder: recorder}
}

type metricsBackend struct {
	next     Backend
	recorder metrics.BackendRecorder
}

func (b *metricsBackend) Exec(ctx context.Context, req ExecRequest) (int, error) {
	start := time.Now()
	exitCode, err := b.next.Exec(ctx, req)
	b.recorder.BackendOperationFinished(operationExec, backendResult(exitCode, err), time.Since(start))
	return exitCode, err
}

func (b *metricsBackend) PortForward(ctx context.Context, req PortForwardRequest) (ioproxy.HalfCloser, error) {
	start := time.Now()
	stream, err := b.next.PortForward(ctx, req)
	b.recorder.BackendOperationFinished(operationPortForward, errorResult(err), time.Since(start))
	return stream, err
}

func (b *metricsBackend) RemoteForward(ctx context.Context, req RemoteForwardRequest) (RemoteForward, error) {
	start := time.Now()
	forward, err := b.next.RemoteForward(ctx, req)
	b.recorder.BackendOperationFinished(operationRemoteForward, errorResult(err), time.Since(start))
	return forward, err
}

func (b *metricsBackend) AgentForward(ctx context.Context, req AgentForwardRequest) (AgentForward, error) {
	start := time.Now()
	forward, err := b.next.AgentForward(ctx, req)
	b.recorder.BackendOperationFinished(operationAgentForward, errorResult(err), time.Since(start))
	return forward, err
}

func (b *metricsBackend) SFTP(ctx context.Context, req StreamRequest) (int, error) {
	start := time.Now()
	exitCode, err := b.next.SFTP(ctx, req)
	b.recorder.BackendOperationFinished(operationSFTP, backendResult(exitCode, err), time.Since(start))
	return exitCode, err
}

func (b *metricsBackend) SCP(ctx context.Context, req SCPRequest) (int, error) {
	start := time.Now()
	exitCode, err := b.next.SCP(ctx, req)
	b.recorder.BackendOperationFinished(operationSCP, backendResult(exitCode, err), time.Since(start))
	return exitCode, err
}

func backendResult(exitCode int, err error) string {
	if err != nil {
		return metrics.ResultError
	}
	if exitCode != 0 {
		return metrics.ResultNonzeroExit
	}
	return metrics.ResultSuccess
}

func errorResult(err error) string {
	if err != nil {
		return metrics.ResultError
	}
	return metrics.ResultSuccess
}
