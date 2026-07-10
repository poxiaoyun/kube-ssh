package backend

import (
	"context"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

const (
	OperationExec          = "exec"
	OperationPortForward   = "port_forward"
	OperationRemoteForward = "remote_forward"
	OperationSFTP          = "sftp"
	OperationSCP           = "scp"
)

func WithMetrics(next Backend, recorder metrics.Recorder) Backend {
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	return &metricsBackend{next: next, recorder: recorder}
}

type metricsBackend struct {
	next     Backend
	recorder metrics.Recorder
}

func (b *metricsBackend) Exec(ctx context.Context, req ExecRequest) (int, error) {
	start := time.Now()
	exitCode, err := b.next.Exec(ctx, req)
	b.recorder.BackendOperationFinished(OperationExec, backendResult(exitCode, err), time.Since(start))
	return exitCode, err
}

func (b *metricsBackend) PortForward(ctx context.Context, req PortForwardRequest) (ioproxy.HalfCloser, error) {
	start := time.Now()
	stream, err := b.next.PortForward(ctx, req)
	b.recorder.BackendOperationFinished(OperationPortForward, errorResult(err), time.Since(start))
	return stream, err
}

func (b *metricsBackend) RemoteForward(ctx context.Context, req RemoteForwardRequest) (RemoteForward, error) {
	start := time.Now()
	forward, err := b.next.RemoteForward(ctx, req)
	b.recorder.BackendOperationFinished(OperationRemoteForward, errorResult(err), time.Since(start))
	return forward, err
}

func (b *metricsBackend) SFTP(ctx context.Context, req StreamRequest) (int, error) {
	start := time.Now()
	exitCode, err := b.next.SFTP(ctx, req)
	b.recorder.BackendOperationFinished(OperationSFTP, backendResult(exitCode, err), time.Since(start))
	return exitCode, err
}

func (b *metricsBackend) SCP(ctx context.Context, req SCPRequest) (int, error) {
	start := time.Now()
	exitCode, err := b.next.SCP(ctx, req)
	b.recorder.BackendOperationFinished(OperationSCP, backendResult(exitCode, err), time.Since(start))
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
