package backend

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
)

func TestMetricsBackendRecordsResults(t *testing.T) {
	recorder := &captureMetricsRecorder{}
	next := &metricsTestBackend{
		execExitCode: 23,
		portErr:      errors.New("dial failed"),
	}
	backend := WithMetrics(next, recorder)

	exitCode, err := backend.Exec(context.Background(), ExecRequest{})
	if err != nil {
		t.Fatalf("Exec() error = %v", err)
	}
	if exitCode != 23 {
		t.Fatalf("Exec() exit code = %d, want 23", exitCode)
	}
	if _, err := backend.PortForward(context.Background(), PortForwardRequest{}); err == nil {
		t.Fatal("PortForward() error = nil, want error")
	}
	if _, err := backend.AgentForward(context.Background(), AgentForwardRequest{}); err != nil {
		t.Fatalf("AgentForward() error = %v", err)
	}

	if got := recorder.backendResults[OperationExec]; got != "nonzero_exit" {
		t.Fatalf("exec result = %q, want nonzero_exit", got)
	}
	if got := recorder.backendResults[OperationPortForward]; got != "error" {
		t.Fatalf("port forward result = %q, want error", got)
	}
	if got := recorder.backendResults[OperationAgentForward]; got != "success" {
		t.Fatalf("agent forward result = %q, want success", got)
	}
}

type captureMetricsRecorder struct {
	backendResults map[string]string
}

func (r *captureMetricsRecorder) AuditDelivery(string)                                    {}
func (r *captureMetricsRecorder) AuthAttempt(string, string)                              {}
func (r *captureMetricsRecorder) ConnectionOpened(string)                                 {}
func (r *captureMetricsRecorder) ConnectionClosed(string)                                 {}
func (r *captureMetricsRecorder) OperationStarted(string, string)                         {}
func (r *captureMetricsRecorder) OperationFinished(string, string, string, time.Duration) {}
func (r *captureMetricsRecorder) StreamOpened(string)                                     {}
func (r *captureMetricsRecorder) StreamClosed(string)                                     {}
func (r *captureMetricsRecorder) StreamBytes(string, string, int64)                       {}
func (r *captureMetricsRecorder) HelperAcquired(string)                                   {}
func (r *captureMetricsRecorder) HelperAcquireFinished(string, string, time.Duration)     {}
func (r *captureMetricsRecorder) HelperReleased(string, string, time.Duration)            {}
func (r *captureMetricsRecorder) AccessPolicyCacheSyncFinished(string, string, time.Duration) {
}
func (r *captureMetricsRecorder) AccessPolicyObjects(string, int) {}
func (r *captureMetricsRecorder) AccessPolicyAuthFinished(string, string, time.Duration) {
}
func (r *captureMetricsRecorder) AccessPolicyResolveFinished(string, time.Duration) {
}
func (r *captureMetricsRecorder) AccessPolicyAuthorizeFinished(string, string, string, time.Duration) {
}
func (r *captureMetricsRecorder) BackendOperationFinished(operation, result string, _ time.Duration) {
	if r.backendResults == nil {
		r.backendResults = map[string]string{}
	}
	r.backendResults[operation] = result
}

type metricsTestBackend struct {
	execExitCode int
	execErr      error
	portErr      error
	agentErr     error
}

func (b *metricsTestBackend) Exec(context.Context, ExecRequest) (int, error) {
	return b.execExitCode, b.execErr
}

func (b *metricsTestBackend) PortForward(context.Context, PortForwardRequest) (ioproxy.HalfCloser, error) {
	if b.portErr != nil {
		return nil, b.portErr
	}
	return nopHalfCloser{}, nil
}

func (b *metricsTestBackend) RemoteForward(context.Context, RemoteForwardRequest) (RemoteForward, error) {
	return nil, errors.New("unexpected RemoteForward call")
}

func (b *metricsTestBackend) AgentForward(context.Context, AgentForwardRequest) (AgentForward, error) {
	if b.agentErr != nil {
		return nil, b.agentErr
	}
	return nopAgentForward{}, nil
}

func (b *metricsTestBackend) SFTP(context.Context, StreamRequest) (int, error) {
	return 1, errors.New("unexpected SFTP call")
}

func (b *metricsTestBackend) SCP(context.Context, SCPRequest) (int, error) {
	return 1, errors.New("unexpected SCP call")
}

type nopHalfCloser struct{}

func (nopHalfCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopHalfCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopHalfCloser) Close() error                { return nil }
func (nopHalfCloser) CloseWrite() error           { return nil }

type nopAgentForward struct{}

func (nopAgentForward) SocketPath() string { return "/tmp/agent.sock" }
func (nopAgentForward) Accept(context.Context) (ioproxy.HalfCloser, error) {
	return nil, errors.New("unexpected Accept call")
}
func (nopAgentForward) Close() error { return nil }
