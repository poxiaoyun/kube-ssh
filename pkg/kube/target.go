package kube

import (
	corev1 "k8s.io/api/core/v1"
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

	RuntimePodUID   = "kube.podUID"
	RuntimeNodeName = "kube.nodeName"
	RuntimeHostIP   = "kube.hostIP"
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

// NewTargetForPod binds the external target name to a specific Pod instance.
func NewTargetForPod(pod *corev1.Pod, container string) *target.Target {
	if pod == nil {
		return nil
	}
	tgt := NewTarget(pod.Namespace, pod.Name, container)
	target.WithRuntimeValue(tgt, RuntimePodUID, string(pod.UID))
	target.WithRuntimeValue(tgt, RuntimeNodeName, pod.Spec.NodeName)
	target.WithRuntimeValue(tgt, RuntimeHostIP, pod.Status.HostIP)
	return tgt
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
