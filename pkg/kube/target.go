package kube

import "xiaoshiai.cn/kube-ssh/pkg/target"

const (
	// KindTarget identifies Kubernetes pod/container targets.
	KindTarget = "kube"

	// OptionNamespaces is the Kubernetes namespace target option key.
	OptionNamespaces = "namespaces"
	// OptionPods is the Kubernetes pod target option key.
	OptionPods = "pods"
	// OptionContainers is the Kubernetes container target option key.
	OptionContainers = "containers"
)

func NewTarget(namespace, pod, container string) *target.Target {
	options := []target.KeyValue{
		{Key: OptionNamespaces, Value: namespace},
		{Key: OptionPods, Value: pod},
	}
	if container != "" {
		options = append(options, target.KeyValue{Key: OptionContainers, Value: container})
	}
	return &target.Target{Kind: KindTarget, Options: options}
}
