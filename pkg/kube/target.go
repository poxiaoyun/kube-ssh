package kube

import (
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

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

type PodTarget struct {
	Namespace string
	Pod       string
	Container string
}

func ParseTarget(tgt *target.Target) (PodTarget, error) {
	if tgt == nil {
		return PodTarget{}, status.InvalidTarget("target is not specified")
	}
	if tgt.Kind != KindTarget {
		return PodTarget{}, status.InvalidTarget("unsupported target kind %q", tgt.Kind)
	}
	namespace, pod, container := tgt.Option(OptionNamespaces), tgt.Option(OptionPods), tgt.Option(OptionContainers)
	if namespace == "" || pod == "" {
		return PodTarget{}, status.InvalidTarget("kube target requires %q and %q options", OptionNamespaces, OptionPods)
	}
	return PodTarget{Namespace: namespace, Pod: pod, Container: container}, nil
}
