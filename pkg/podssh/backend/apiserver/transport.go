// Package apiserver implements Pod backend transport through Kubernetes API Server streaming.
package apiserver

import (
	"context"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
)

// Options configures API Server streaming and helper preparation.
type Options struct {
	HelperPath      string
	HelperRemoteDir string
	Metrics         metrics.HelperRecorder
}

// Transport executes Pod backend primitives through the Kubernetes API Server.
type Transport struct {
	client         kubernetes.Interface
	restConfig     *rest.Config
	helperAcquirer helperAcquirer
	metrics        metrics.HelperRecorder

	execOverride func(context.Context, backend.ExecRequest) (int, error)
}

// New creates an API Server transport.
func New(client kubernetes.Interface, restConfig *rest.Config, options Options) *Transport {
	if options.HelperRemoteDir == "" {
		options.HelperRemoteDir = "/tmp"
	}
	if options.Metrics == nil {
		options.Metrics = metrics.NopRecorder{}
	}
	transport := &Transport{client: client, restConfig: restConfig, metrics: options.Metrics}
	transport.helperAcquirer = newCopyHelperAcquirer(transport, copyHelperAcquirerOptions{
		LocalPath: options.HelperPath,
		RemoteDir: options.HelperRemoteDir,
	})
	return transport
}
