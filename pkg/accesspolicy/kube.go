package accesspolicy

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
)

type KubernetesSecretReader struct {
	client kubernetes.Interface
}

func NewKubernetesSecretReader(client kubernetes.Interface) *KubernetesSecretReader {
	return &KubernetesSecretReader{client: client}
}

func (r *KubernetesSecretReader) GetSecretValue(ctx context.Context, namespace, name, key string) (string, error) {
	if r == nil || r.client == nil {
		return "", fmt.Errorf("secret reader requires a kubernetes client")
	}
	secret, err := r.client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	value, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s key %q not found", namespace, name, key)
	}
	return string(value), nil
}

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
