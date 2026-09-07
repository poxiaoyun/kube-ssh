package gateway

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// loadKubernetesConfig loads an explicit kubeconfig or the default client-go config.
func loadKubernetesConfig(kubeconfigPath string) (*rest.Config, error) {
	var (
		restConfig *rest.Config
		err        error
	)

	if kubeconfigPath != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return restConfig, nil
}

func newKubernetesClient(restConfig *rest.Config) (kubernetes.Interface, error) {
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}
	return client, nil
}
