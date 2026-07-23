package kube

import (
	"context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/ioproxy"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// Backend executes operations against Kubernetes pods.
type Backend struct {
	client              kubernetes.Interface
	restConfig          *rest.Config
	helperAcquirer      helperAcquirer
	metrics             metrics.Recorder
	execOverride        func(context.Context, backend.ExecRequest) (int, error)
	portForwardOverride func(context.Context, backend.PortForwardRequest) (ioproxy.HalfCloser, error)
	helperExecOverride  func(context.Context, *target.Target, string, []string, backend.StreamRequest) (int, error)
}

type BackendOptions struct {
	HelperPath      string
	HelperRemoteDir string
	Metrics         metrics.Recorder
	// ExecTransport, PortForwardTransport, and HelperExecTransport replace the
	// Kubernetes streaming transports while retaining the common pod/helper
	// backend behavior. They are primarily used by the node backend.
	ExecTransport        func(context.Context, backend.ExecRequest) (int, error)
	PortForwardTransport func(context.Context, backend.PortForwardRequest) (ioproxy.HalfCloser, error)
	HelperExecTransport  func(context.Context, *target.Target, string, []string, backend.StreamRequest) (int, error)
}

func NewBackend(client kubernetes.Interface, restConfig *rest.Config, options BackendOptions) *Backend {
	if options.HelperRemoteDir == "" {
		options.HelperRemoteDir = "/tmp"
	}
	b := &Backend{
		client: client, restConfig: restConfig, metrics: options.Metrics,
		execOverride:        options.ExecTransport,
		portForwardOverride: options.PortForwardTransport,
		helperExecOverride:  options.HelperExecTransport,
	}
	if b.metrics == nil {
		b.metrics = metrics.NopRecorder{}
	}
	if b.helperExecOverride == nil {
		b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{
			LocalPath: options.HelperPath,
			RemoteDir: options.HelperRemoteDir,
		})
	}
	return b
}
