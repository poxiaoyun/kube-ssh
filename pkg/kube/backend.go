package kube

import (
	"context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

// Backend executes operations against Kubernetes pods.
type Backend struct {
	client         kubernetes.Interface
	restConfig     *rest.Config
	helperAcquirer helperAcquirer
	metrics        metrics.Recorder
	execOverride   func(context.Context, backend.ExecRequest) (int, error)
}

type BackendOptions struct {
	HelperPath      string
	HelperRemoteDir string
	Metrics         metrics.Recorder
}

func NewBackend(client kubernetes.Interface, restConfig *rest.Config, options BackendOptions) *Backend {
	if options.HelperRemoteDir == "" {
		options.HelperRemoteDir = "/tmp"
	}
	b := &Backend{client: client, restConfig: restConfig, metrics: options.Metrics}
	if b.metrics == nil {
		b.metrics = metrics.NopRecorder{}
	}
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{
		LocalPath: options.HelperPath,
		RemoteDir: options.HelperRemoteDir,
	})
	return b
}
