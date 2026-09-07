// Package podtarget owns Kubernetes Pod target representation, resolution, and binding.
package podtarget

import (
	"fmt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

const (
	// OptionNamespaces is the Kubernetes namespace target option key.
	OptionNamespaces = "namespaces"
	// OptionPods is the Kubernetes pod target option key.
	OptionPods = "pods"
	// OptionContainers is the Kubernetes container target option key.
	OptionContainers = "containers"

	runtimePodUID   = "pod.uid"
	runtimeNodeName = "pod.nodeName"
	runtimeHostIP   = "pod.hostIP"
)

// New constructs a logical Pod target.
func New(namespace, pod, container string) *target.Target {
	options := []target.Option{
		{Key: OptionNamespaces, Value: namespace},
		{Key: OptionPods, Value: pod},
	}
	if container != "" {
		options = append(options, target.Option{Key: OptionContainers, Value: container})
	}
	return &target.Target{Kind: target.KindPod, Options: options}
}

// Bind constructs a target bound to one live Pod instance.
func Bind(pod *corev1.Pod, container string) *target.Target {
	tgt := New(pod.Namespace, pod.Name, container)
	bind(tgt, pod)
	return tgt
}

func bind(tgt *target.Target, pod *corev1.Pod) {
	tgt.Runtime = map[string]string{
		runtimePodUID:   string(pod.UID),
		runtimeNodeName: pod.Spec.NodeName,
		runtimeHostIP:   pod.Status.HostIP,
	}
}

// Reference is the logical namespace, Pod, and container address in a target.
type Reference struct {
	Namespace string
	Pod       string
	Container string
}

// Parse reads the logical Pod address from a target.
func Parse(tgt *target.Target) (Reference, error) {
	if tgt == nil {
		return Reference{}, apierrors.NewBadRequest("target is not specified")
	}
	if tgt.Kind != target.KindPod {
		return Reference{}, apierrors.NewBadRequest(fmt.Sprintf("unsupported target kind %q", tgt.Kind))
	}
	namespace, pod, container := tgt.Option(OptionNamespaces), tgt.Option(OptionPods), tgt.Option(OptionContainers)
	if namespace == "" || pod == "" {
		return Reference{}, apierrors.NewBadRequest(fmt.Sprintf("Pod target requires %q and %q options", OptionNamespaces, OptionPods))
	}
	return Reference{Namespace: namespace, Pod: pod, Container: container}, nil
}

// Binding is the runtime identity captured for one Pod target.
type Binding struct {
	UID      string
	NodeName string
	HostIP   string
}

// BoundIdentity reads the runtime identity captured by Bind.
func BoundIdentity(tgt *target.Target) Binding {
	return Binding{
		UID:      tgt.Runtime[runtimePodUID],
		NodeName: tgt.Runtime[runtimeNodeName],
		HostIP:   tgt.Runtime[runtimeHostIP],
	}
}
