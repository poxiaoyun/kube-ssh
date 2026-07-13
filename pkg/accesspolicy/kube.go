package accesspolicy

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type KubernetesPodLister struct {
	client kubernetes.Interface
}

func NewKubernetesPodLister(client kubernetes.Interface) *KubernetesPodLister {
	return &KubernetesPodLister{client: client}
}

func (l *KubernetesPodLister) List(ctx context.Context, namespace string, selector map[string]string) ([]corev1.Pod, error) {
	if l == nil || l.client == nil {
		return nil, fmt.Errorf("pod lister requires a kubernetes client")
	}
	pods, err := l.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(selector).String(),
	})
	if err != nil {
		return nil, err
	}
	return pods.Items, nil
}

func (l *KubernetesPodLister) Get(ctx context.Context, namespace, name string) (*corev1.Pod, error) {
	if l == nil || l.client == nil {
		return nil, fmt.Errorf("pod getter requires a kubernetes client")
	}
	return l.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
}

type InformerPodLister struct {
	indexer cache.Indexer
}

func NewInformerPodLister(indexer cache.Indexer) *InformerPodLister {
	return &InformerPodLister{indexer: indexer}
}

func (l *InformerPodLister) List(_ context.Context, namespace string, selector map[string]string) ([]corev1.Pod, error) {
	if l == nil || l.indexer == nil {
		return nil, fmt.Errorf("pod lister requires a pod indexer")
	}
	out := []corev1.Pod{}
	err := cache.ListAllByNamespace(l.indexer, namespace, labels.SelectorFromSet(selector), func(obj any) {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return
		}
		out = append(out, *pod.DeepCopy())
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (l *InformerPodLister) Get(_ context.Context, namespace, name string) (*corev1.Pod, error) {
	if l == nil || l.indexer == nil {
		return nil, fmt.Errorf("pod getter requires a pod indexer")
	}
	obj, exists, err := l.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("pod %s/%s not found", namespace, name)
	}
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("cached object %s/%s is not a pod", namespace, name)
	}
	return pod.DeepCopy(), nil
}
