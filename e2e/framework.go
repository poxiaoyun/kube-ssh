//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	defaultClusterName = "kube-ssh-e2e"
	testNamespaceBase  = "kube-ssh-e2e"
)

type Framework struct {
	T           *testing.T
	WorkDir     string
	Namespace   string
	TestID      string
	Kubeconfig  string
	GatewayPort int
	SSHConfig   string
	GatewayArgs []string
}

type FrameworkOptions struct {
	GatewayArgs []string
	BeforeStart func(*Framework)
}

type BackgroundCommand struct {
	Cmd    *exec.Cmd
	Stdout *bytes.Buffer
	Stderr *bytes.Buffer
	Stdin  io.Closer
	cancel context.CancelFunc
}

type Result struct {
	Stdout string
	Stderr string
	Code   int
}

type suiteConfig struct {
	WorkDir    string
	Namespace  string
	Kubeconfig string
}

var e2eSuite = struct {
	once   sync.Once
	config suiteConfig
	err    error
}{}

func NewFramework(t *testing.T) *Framework {
	return NewFrameworkWithOptions(t, FrameworkOptions{
		GatewayArgs: []string{
			"--authentication-anonymous",
			"--authorization-allow-all",
		},
	})
}

func NewFrameworkWithOptions(t *testing.T, opts FrameworkOptions) *Framework {
	t.Helper()
	requireCommands(t, "kubectl", "ssh", "scp", "sftp", "ssh-keygen")
	if !useExistingCluster() {
		requireCommands(t, "kind")
	}
	requireFile(t, gatewayPath())
	requireFile(t, helperPath())

	suite := ensureE2ESuite(t)
	workDir := t.TempDir()
	f := &Framework{
		T:         t,
		WorkDir:   workDir,
		Namespace: suite.Namespace,
		TestID: fmt.Sprintf("%s-%d", sanitizeTestName(t.Name()), time.Now().
			UnixNano()),
		Kubeconfig:  suite.Kubeconfig,
		GatewayArgs: append([]string{}, opts.GatewayArgs...),
	}

	if opts.BeforeStart != nil {
		opts.BeforeStart(f)
	}
	f.startGateway()
	f.writeSSHConfig()
	return f
}

func ensureE2ESuite(t *testing.T) suiteConfig {
	t.Helper()
	e2eSuite.once.Do(func() {
		e2eSuite.config, e2eSuite.err = initE2ESuite()
	})
	if e2eSuite.err != nil {
		t.Fatalf("initialize e2e suite: %v", e2eSuite.err)
	}
	return e2eSuite.config
}

func initE2ESuite() (suiteConfig, error) {
	workDir, err := os.MkdirTemp("", "kube-ssh-e2e-")
	if err != nil {
		return suiteConfig{}, fmt.Errorf("create suite workdir: %w", err)
	}
	config := suiteConfig{
		WorkDir: workDir,
		Namespace: fmt.Sprintf("%s-%d", testNamespaceBase, time.Now().
			UnixNano()),
		Kubeconfig: os.Getenv("KUBECONFIG"),
	}
	if !useExistingCluster() {
		config.Kubeconfig = filepath.Join(workDir, "kubeconfig")
		if err := ensureKindCluster(config.Kubeconfig); err != nil {
			return config, err
		}
	}
	if err := ensureDefaultFixture(config.Kubeconfig, config.Namespace); err != nil {
		return config, err
	}
	return config, nil
}

func cleanupE2ESuite() {
	config := e2eSuite.config
	if config.Namespace != "" {
		_ = runE2ECommand(30*time.Second, "kubectl", []string{"delete", "namespace", config.Namespace, "--ignore-not-found", "--wait=false"}, nil, map[string]string{"KUBECONFIG": config.Kubeconfig})
	}
	if config.WorkDir != "" {
		_ = os.RemoveAll(config.WorkDir)
	}
}

func (f *Framework) Kubectl(args ...string) Result {
	return runE2ECommand(30*time.Second, "kubectl", args, nil, map[string]string{"KUBECONFIG": f.Kubeconfig})
}

// EnsureDefaultFixture prepares the shared namespace, shell pod, and service.
// It is intentionally idempotent so a test can call it after creating extra
// resources without depending on suite initialization order.
func (f *Framework) EnsureDefaultFixture() {
	f.T.Helper()
	if err := ensureDefaultFixture(f.Kubeconfig, f.Namespace); err != nil {
		f.T.Fatalf("ensure default fixture: %v", err)
	}
}

// ApplyManifest applies arbitrary test resources into the current cluster.
// Tests that need isolated pods should use unique names, then call WaitPodReady.
func (f *Framework) ApplyManifest(manifest string) {
	f.T.Helper()
	if err := applyManifest(f.Kubeconfig, manifest); err != nil {
		f.T.Fatalf("apply manifest: %v", err)
	}
}

func (f *Framework) WaitPodReady(name string, timeout time.Duration) {
	f.T.Helper()
	if err := waitPodReady(f.Kubeconfig, f.Namespace, name, timeout); err != nil {
		f.T.Fatalf("wait pod/%s ready: %v", name, err)
	}
}

func ensureKindCluster(kubeconfig string) error {
	clusters := runE2ECommand(30*time.Second, "kind", []string{"get", "clusters"}, nil, kindEnv())
	if clusters.Code != 0 {
		return fmt.Errorf("kind get clusters failed:\n%s", clusters.Dump())
	}
	if !containsLine(clusters.Stdout, defaultClusterName) {
		if err := recreateKindCluster(); err != nil {
			return err
		}
	}
	if err := writeKindKubeconfig(kubeconfig); err != nil {
		return err
	}
	if !clusterReachable(kubeconfig) {
		if err := recreateKindCluster(); err != nil {
			return err
		}
		if err := writeKindKubeconfig(kubeconfig); err != nil {
			return err
		}
		if !clusterReachable(kubeconfig) {
			return fmt.Errorf("kind cluster %q is not reachable after recreate", defaultClusterName)
		}
	}
	return nil
}

func recreateKindCluster() error {
	_ = runE2ECommand(2*time.Minute, "kind", []string{"delete", "cluster", "--name", defaultClusterName}, nil, kindEnv())
	args := []string{"create", "cluster", "--name", defaultClusterName}
	if image := os.Getenv("KUBE_SSH_E2E_KIND_IMAGE"); image != "" {
		args = append(args, "--image", image)
	}
	create := runE2ECommand(kindCreateTimeout(), "kind", args, nil, kindEnv())
	if create.Code != 0 {
		return fmt.Errorf("kind create cluster failed:\n%s", create.Dump())
	}
	return nil
}

func writeKindKubeconfig(path string) error {
	result := runE2ECommand(30*time.Second, "kind", []string{"get", "kubeconfig", "--name", defaultClusterName}, nil, kindEnv())
	if result.Code != 0 {
		return fmt.Errorf("kind get kubeconfig failed:\n%s", result.Dump())
	}
	if err := os.WriteFile(path, []byte(result.Stdout), 0o600); err != nil {
		return fmt.Errorf("write kubeconfig: %w", err)
	}
	return nil
}

func clusterReachable(kubeconfig string) bool {
	result := runE2ECommand(30*time.Second, "kubectl", []string{"cluster-info"}, nil, map[string]string{"KUBECONFIG": kubeconfig})
	return result.Code == 0
}

func ensureDefaultFixture(kubeconfig, namespace string) error {
	if err := ensureNamespace(kubeconfig, namespace); err != nil {
		return err
	}
	if err := applyManifest(kubeconfig, defaultShellManifest(namespace)); err != nil {
		return err
	}
	return waitPodReady(kubeconfig, namespace, "shell", 2*time.Minute)
}

func ensureNamespace(kubeconfig, namespace string) error {
	manifest := fmt.Sprintf(`apiVersion: v1
kind: Namespace
metadata:
  name: %s
`, namespace)
	return applyManifest(kubeconfig, manifest)
}

func defaultShellManifest(namespace string) string {
	return fmt.Sprintf(`
apiVersion: v1
kind: Pod
metadata:
  name: shell
  namespace: %[1]s
  labels:
    app: shell
spec:
  containers:
  - name: app
    image: alpine:3.20
    command: ["sh", "-c", "while true; do printf 'HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nlocal-forward\n' | nc -l -p 18080; done & while true; do nc -l -p 18081 >/dev/null; done & sleep infinity"]
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: %[1]s
spec:
  selector:
    app: shell
  ports:
  - name: http
    port: 18080
    targetPort: 18080
  - name: hold
    port: 18081
    targetPort: 18081
`, namespace)
}

func applyManifest(kubeconfig, manifest string) error {
	apply := runE2ECommand(30*time.Second, "kubectl", []string{"apply", "-f", "-"}, strings.NewReader(manifest), map[string]string{"KUBECONFIG": kubeconfig})
	if apply.Code != 0 {
		return fmt.Errorf("kubectl apply failed:\n%s", apply.Dump())
	}
	return nil
}

func waitPodReady(kubeconfig, namespace, pod string, timeout time.Duration) error {
	timeoutArg := fmt.Sprintf("--timeout=%s", timeout)
	wait := runE2ECommand(timeout+10*time.Second, "kubectl", []string{"-n", namespace, "wait", "--for=condition=Ready", "pod/" + pod, timeoutArg}, nil, map[string]string{"KUBECONFIG": kubeconfig})
	if wait.Code != 0 {
		describe := runE2ECommand(30*time.Second, "kubectl", []string{"-n", namespace, "describe", "pod/" + pod}, nil, map[string]string{"KUBECONFIG": kubeconfig})
		return fmt.Errorf("pod/%s not ready:\n%s\n%s", pod, wait.Dump(), describe.Dump())
	}
	return nil
}

func (f *Framework) startGateway() {
	hostKey := filepath.Join(f.WorkDir, "host_ed25519")
	genHost := runE2ECommand(30*time.Second, "ssh-keygen", []string{"-q", "-t", "ed25519", "-N", "", "-f", hostKey}, nil, nil)
	if genHost.Code != 0 {
		f.T.Fatalf("ssh-keygen host key failed:\n%s", genHost.Dump())
	}
	port := freePort(f.T)
	f.GatewayPort = port

	ctx, cancel := context.WithCancel(context.Background())
	f.T.Cleanup(cancel)
	args := []string{
		"--listen-address", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"--host-key-file", hostKey,
		"--helper-path", helperPath(),
	}
	args = append(args, f.GatewayArgs...)
	if f.Kubeconfig != "" {
		args = append(args, "--kubeconfig", f.Kubeconfig)
	}
	cmd := exec.CommandContext(ctx, gatewayPath(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		f.T.Fatalf("start kube-ssh: %v", err)
	}
	f.T.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if f.T.Failed() {
			f.T.Logf("kube-ssh stdout:\n%s", stdout.String())
			f.T.Logf("kube-ssh stderr:\n%s", stderr.String())
		}
	})
	f.waitTCP("127.0.0.1", port, 10*time.Second)
}

func (f *Framework) writeSSHConfig() {
	clientKey := filepath.Join(f.WorkDir, "client_ed25519")
	genClient := runE2ECommand(30*time.Second, "ssh-keygen", []string{"-q", "-t", "ed25519", "-N", "", "-f", clientKey}, nil, nil)
	if genClient.Code != 0 {
		f.T.Fatalf("ssh-keygen client key failed:\n%s", genClient.Dump())
	}
	config := fmt.Sprintf(`
Host kube-ssh-e2e
  HostName 127.0.0.1
  Port %d
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
  IdentityFile %s
  IdentitiesOnly yes
  BatchMode yes
  LogLevel ERROR
`, f.GatewayPort, clientKey)
	f.SSHConfig = filepath.Join(f.WorkDir, "ssh_config")
	if err := os.WriteFile(f.SSHConfig, []byte(config), 0o600); err != nil {
		f.T.Fatalf("write ssh config: %v", err)
	}
}

func (f *Framework) waitTCP(host string, port int, timeout time.Duration) {
	deadline := time.Now().
		Add(timeout)
	address := net.JoinHostPort(host, strconv.Itoa(port))
	for time.Now().
		Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = conn.Close()
		return
	}
	f.T.Fatalf("timed out waiting for %s", address)
}

func runE2ECommand(timeout time.Duration, name string, args []string, stdin *strings.Reader, env map[string]string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Env = commandEnv(env)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		Code:   0,
	}
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			result.Code = exitErr.ExitCode()
		} else if err := ctx.Err(); err != nil {
			result.Code = -1
			result.Stderr += "\n" + err.Error()
		} else {
			result.Code = -1
			result.Stderr += "\n" + err.Error()
		}
	}
	return result
}

func (f *Framework) startCommandWithStdin(name string, args []string, stdin io.Reader, env map[string]string) *BackgroundCommand {
	f.T.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv(env)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		f.T.Fatalf("start %s: %v", name, err)
	}
	bg := &BackgroundCommand{
		Cmd:    cmd,
		Stdout: &stdout,
		Stderr: &stderr,
		cancel: cancel,
	}
	f.T.Cleanup(func() {
		bg.Stop()
		if f.T.Failed() {
			f.T.Logf("%s stdout:\n%s", name, stdout.String())
			f.T.Logf("%s stderr:\n%s", name, stderr.String())
		}
	})
	return bg
}

// Stop terminates the command and waits for its I/O to finish. It is idempotent.
func (c *BackgroundCommand) Stop() {
	if c.cancel == nil {
		return
	}
	if c.Stdin != nil {
		_ = c.Stdin.Close()
	}
	c.cancel()
	_ = c.Cmd.Wait()
	c.cancel = nil
}

func (r Result) Dump() string {
	return fmt.Sprintf("exit code: %d\nstdout:\n%s\nstderr:\n%s", r.Code, r.Stdout, r.Stderr)
}

func requireCommands(t *testing.T, names ...string) {
	t.Helper()
	required := os.Getenv("KUBE_SSH_E2E_REQUIRED") == "true"
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			if required {
				t.Fatalf("required command %q not found: %v", name, err)
			}
			t.Skipf("command %q not found: %v", name, err)
		}
	}
}

func requireFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("required file %s not found: %v; run make build first", path, err)
	}
}

func useExistingCluster() bool {
	if os.Getenv("KUBE_SSH_E2E_USE_KIND") == "true" {
		return false
	}
	if value := os.Getenv("KUBE_SSH_E2E_USE_EXISTING_CLUSTER"); value != "" {
		return value != "false"
	}
	return true
}

func kindEnv() map[string]string {
	if os.Getenv("KUBE_SSH_E2E_KIND_KEEP_PROXY") == "true" {
		return nil
	}
	return map[string]string{
		"HTTP_PROXY":  "",
		"HTTPS_PROXY": "",
		"http_proxy":  "",
		"https_proxy": "",
	}
}

func kindCreateTimeout() time.Duration {
	if value := os.Getenv("KUBE_SSH_E2E_KIND_CREATE_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return 5 * time.Minute
		}
		return timeout
	}
	return 5 * time.Minute
}

func helperPath() string {
	if path := os.Getenv("KUBE_SSH_E2E_HELPER_PATH"); path != "" {
		return path
	}
	return filepath.Join("..", "bin", "e2e", "kube-ssh-helper-linux-"+runtimeGOARCH())
}

func gatewayPath() string {
	if path := os.Getenv("KUBE_SSH_E2E_GATEWAY_PATH"); path != "" {
		return path
	}
	currentBuild := filepath.Join("..", "bin", runtime.GOOS+"-"+runtime.GOARCH, "kube-ssh")
	if _, err := os.Stat(currentBuild); err != nil {
		return filepath.Join("..", "bin", "kube-ssh")
	}
	return currentBuild
}

func runtimeGOARCH() string {
	if arch := os.Getenv("KUBE_SSH_E2E_HELPER_GOARCH"); arch != "" {
		return arch
	}
	return runtime.GOARCH
}

func containsLine(text, want string) bool {
	for line := range strings.SplitSeq(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func sanitizeTestName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, name)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func commandEnv(overrides map[string]string) []string {
	values := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			values[key] = value
		}
	}
	for key, value := range overrides {
		if value == "" {
			delete(values, key)
			continue
		}
		values[key] = value
	}
	env := make([]string, 0, len(values))
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}
