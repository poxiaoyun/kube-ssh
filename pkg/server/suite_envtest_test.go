//go:build envtest

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	generatedclient "xiaoshiai.cn/kube-ssh/pkg/generated/clientset/versioned"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

var (
	envtestConfig       *rest.Config
	envtestKubeClient   kubernetes.Interface
	envtestAccessClient generatedclient.Interface
	envtestEnvironment  *envtest.Environment
)

func TestEnvtest(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Envtest Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	binaryDir := filepath.Join(os.Getenv("HOME"), ".cache", "envtest")
	Expect(os.MkdirAll(binaryDir, 0o755)).To(Succeed())

	envtestEnvironment = &envtest.Environment{
		CRDDirectoryPaths:        []string{filepath.Join("..", "..", "deploy", "kube-ssh", "crds")},
		ErrorIfCRDPathMissing:    true,
		DownloadBinaryAssets:     true,
		BinaryAssetsDirectory:    binaryDir,
		ControlPlaneStartTimeout: 60 * time.Second,
		ControlPlaneStopTimeout:  60 * time.Second,
	}

	var err error
	envtestConfig, err = envtestEnvironment.Start()
	Expect(err).NotTo(HaveOccurred())

	envtestKubeClient, err = kubernetes.NewForConfig(envtestConfig)
	Expect(err).NotTo(HaveOccurred())
	envtestAccessClient, err = generatedclient.NewForConfig(envtestConfig)
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	if envtestEnvironment != nil {
		Expect(envtestEnvironment.Stop()).To(Succeed())
	}
})

func startEnvtestAccessPolicyRuntime(namespace string) accessPolicyRuntime {
	return startEnvtestAccessPolicyRuntimeForGateway(namespace, "", nil)
}

func startEnvtestAccessPolicyRuntimeForGateway(namespace, gatewayClassName string, advertiseAddresses []string) accessPolicyRuntime {
	GinkgoHelper()

	opts := NewDefaultOptions()
	opts.AccessPolicy.Enabled = true
	opts.AccessPolicy.Namespace = namespace
	opts.GatewayClassName = gatewayClassName
	opts.AdvertiseAddresses = append([]string(nil), advertiseAddresses...)

	kubeClient, err := kubernetes.NewForConfig(envtestConfig)
	Expect(err).NotTo(HaveOccurred())

	runtime, err := buildAccessPolicyRuntime(opts, kubeClient, envtestConfig, metrics.NopRecorder{})
	Expect(err).NotTo(HaveOccurred())

	ctx, cancel := context.WithCancel(context.Background())
	DeferCleanup(cancel)

	errCh := make(chan error, 1)
	go func() {
		errCh <- runtime.start(ctx)
	}()
	Eventually(errCh, 20*time.Second, 100*time.Millisecond).Should(Receive(Succeed()))
	return runtime
}
