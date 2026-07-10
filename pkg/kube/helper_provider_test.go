package kube

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"testing"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestValidateHelperHealth(t *testing.T) {
	valid := helperpkg.Health{
		Protocol:     helperpkg.ProtocolVersion,
		Capabilities: []string{helperpkg.CapabilityHealth, helperpkg.CapabilitySFTP},
	}
	if err := ValidateHelperHealth(valid, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("validateHelperHealth() error = %v", err)
	}

	wrongProtocol := valid
	wrongProtocol.Protocol = "old"
	if err := ValidateHelperHealth(wrongProtocol, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("validateHelperHealth() succeeded for wrong protocol")
	}

	missingHealth := valid
	missingHealth.Capabilities = []string{helperpkg.CapabilitySFTP}
	if err := ValidateHelperHealth(missingHealth, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("validateHelperHealth() succeeded without health capability")
	}

	missingRequired := valid
	if err := ValidateHelperHealth(missingRequired, helperpkg.CapabilitySCP); err == nil {
		t.Fatal("validateHelperHealth() succeeded without required capability")
	}
}

func TestDefaultHelperCapabilitiesAdvertiseProtocolCommands(t *testing.T) {
	health := helperpkg.Health{
		Protocol:     helperpkg.ProtocolVersion,
		Capabilities: helperpkg.DefaultCapabilities(),
	}

	for _, capability := range []string{
		helperpkg.CapabilityHealth,
		helperpkg.CapabilityChecksum,
		helperpkg.CapabilityDial,
		helperpkg.CapabilityRemoteForward,
		helperpkg.CapabilitySFTP,
		helperpkg.CapabilitySCP,
	} {
		if err := ValidateHelperHealth(health, capability); err != nil {
			t.Fatalf("validateHelperHealth(%q) error = %v", capability, err)
		}
	}
}

func TestAcquireHelperCopiesVerifiesHealthAndCaches(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	tgt := NewTarget("default", "nginx", "app")

	script := newHelperExecScript(t,
		helperShellCopySuccess,
		helperChecksum(expectedChecksum),
		helperHealth(validHelperHealth()),
	)
	b := script.backend()
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	handle, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP)
	if err != nil {
		t.Fatalf("acquireHelper() error = %v", err)
	}
	if script.helperData != "helper-binary" {
		t.Fatalf("helper data = %q, want helper-binary", script.helperData)
	}
	if got := handle.Command(helperpkg.CapabilitySFTP); !equalStrings(got, []string{script.remotePath, helperpkg.CapabilitySFTP}) {
		t.Fatalf("helper command = %#v", got)
	}

	if err := handle.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}

	second, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySCP)
	if err != nil {
		t.Fatalf("second acquireHelper() error = %v", err)
	}
	if got := second.Command(helperpkg.CapabilitySCP); !equalStrings(got, []string{script.remotePath, helperpkg.CapabilitySCP}) {
		t.Fatalf("second helper command = %#v", got)
	}

	if len(script.commands) != 3 {
		t.Fatalf("exec command count = %d, want 3", len(script.commands))
	}
	if script.commands[0][0] != "sh" || script.commands[0][4] == "" {
		t.Fatalf("copy command = %#v", script.commands[0])
	}
}

func TestAcquireHelperFallsBackToTarCopy(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	tgt := NewTarget("default", "nginx", "app")

	script := newHelperExecScript(t,
		helperShellCopyExit(127),
		helperTarCopySuccess("/work"),
		helperChecksum(expectedChecksum),
		helperHealth(validHelperHealth()),
	)
	b := script.backend()
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	handle, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP)
	if err != nil {
		t.Fatalf("acquireHelper() error = %v", err)
	}
	if got := handle.Command(helperpkg.CapabilitySFTP); !equalStrings(got, []string{script.remotePath, helperpkg.CapabilitySFTP}) {
		t.Fatalf("helper command = %#v", got)
	}
	assertSingleHelperTar(t, script.tarData, path.Base(script.remotePath), "helper-binary")
}

func TestAcquireHelperReportsAllCopyMethodFailures(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")

	var commands [][]string
	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			commands = append(commands, append([]string(nil), req.Command...))
			return 127, nil
		},
	}
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	_, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP)
	if err == nil {
		t.Fatal("acquireHelper() succeeded")
	}
	message := err.Error()
	for _, want := range []string{"sh/cat/chmod", "tar"} {
		if !strings.Contains(message, want) {
			t.Fatalf("acquireHelper() error = %q, want %q", message, want)
		}
	}
	if len(commands) != 2 {
		t.Fatalf("exec command count = %d, want 2", len(commands))
	}
}

func TestAcquireHelperChecksumMismatchDoesNotCache(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	tgt := NewTarget("default", "nginx", "app")

	script := newHelperExecScript(t,
		helperShellCopySuccess,
		helperChecksum("wrong"),
		helperShellCopySuccess,
		helperChecksum(expectedChecksum),
		helperHealth(validHelperHealth()),
	)
	b := script.backend()
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("acquireHelper() succeeded with checksum mismatch")
	}
	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("retry acquireHelper() error = %v", err)
	}
	if len(script.commands) != 5 {
		t.Fatalf("exec command count = %d, want 5", len(script.commands))
	}
}

func TestAcquireHelperHealthFailureDoesNotCache(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	tgt := NewTarget("default", "nginx", "app")

	script := newHelperExecScript(t,
		helperShellCopySuccess,
		helperChecksum(expectedChecksum),
		helperHealth(helperpkg.Health{Protocol: "old", Capabilities: []string{helperpkg.CapabilityHealth}}),
		helperShellCopySuccess,
		helperChecksum(expectedChecksum),
		helperHealth(validHelperHealth()),
	)
	b := script.backend()
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("acquireHelper() succeeded with invalid health")
	}
	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("retry acquireHelper() error = %v", err)
	}
	if len(script.commands) != 6 {
		t.Fatalf("exec command count = %d, want 6", len(script.commands))
	}
}

func TestAcquireHelperConcurrentSameTargetCopiesOnce(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	tgt := NewTarget("default", "nginx", "app")

	var mu sync.Mutex
	var copyCount int
	var checksumCount int
	var healthCount int
	var helperPathRemote string
	copyStarted := make(chan struct{})
	releaseCopy := make(chan struct{})
	var closeStarted sync.Once

	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			switch req.Command[len(req.Command)-1] {
			case helperpkg.CapabilityChecksum:
				mu.Lock()
				checksumCount++
				mu.Unlock()
				_, _ = req.Stdout.Write([]byte(expectedChecksum + "\n"))
			case helperpkg.CapabilityHealth:
				mu.Lock()
				healthCount++
				mu.Unlock()
				_ = json.NewEncoder(req.Stdout).Encode(helperpkg.Health{
					Protocol:     helperpkg.ProtocolVersion,
					Capabilities: helperpkg.DefaultCapabilities(),
				})
			default:
				mu.Lock()
				copyCount++
				helperPathRemote = req.Command[4]
				mu.Unlock()
				closeStarted.Do(func() { close(copyStarted) })
				<-releaseCopy
			}
			return 0, nil
		},
	}
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	paths := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			handle, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP)
			if err != nil {
				errs <- err
				return
			}
			got := handle.Command(helperpkg.CapabilitySFTP)
			if len(got) != 2 || got[1] != helperpkg.CapabilitySFTP {
				errs <- fmt.Errorf("helper command = %#v", got)
				return
			}
			paths <- got[0]
		}()
	}

	<-copyStarted
	close(releaseCopy)
	wg.Wait()
	close(errs)
	close(paths)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	mu.Lock()
	wantPath := helperPathRemote
	gotCopyCount := copyCount
	gotChecksumCount := checksumCount
	gotHealthCount := healthCount
	mu.Unlock()
	for gotPath := range paths {
		if gotPath != wantPath {
			t.Fatalf("helper path = %q, want %q", gotPath, wantPath)
		}
	}
	if gotCopyCount != 1 {
		t.Fatalf("copy count = %d, want 1", gotCopyCount)
	}
	if gotChecksumCount != 1 {
		t.Fatalf("checksum count = %d, want 1", gotChecksumCount)
	}
	if gotHealthCount != 1 {
		t.Fatalf("health count = %d, want 1", gotHealthCount)
	}
}

func TestCopyHelperProviderInvalidateTarget(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	tgt := NewTarget("default", "nginx", "app")

	var commands [][]string
	var helperPathRemote string
	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			commands = append(commands, append([]string(nil), req.Command...))
			switch req.Command[len(req.Command)-1] {
			case helperpkg.CapabilityChecksum:
				_, _ = req.Stdout.Write([]byte(expectedChecksum + "\n"))
			case helperpkg.CapabilityHealth:
				_ = json.NewEncoder(req.Stdout).Encode(helperpkg.Health{
					Protocol:     helperpkg.ProtocolVersion,
					Capabilities: helperpkg.DefaultCapabilities(),
				})
			default:
				if helperPathRemote == "" {
					helperPathRemote = req.Command[4]
				}
				if req.Command[4] != helperPathRemote {
					t.Fatalf("copy path = %q, want %q", req.Command[4], helperPathRemote)
				}
			}
			return 0, nil
		},
	}
	provider := NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})
	b.helperProvider = provider

	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("acquireHelper() error = %v", err)
	}
	provider.Invalidate(tgt)
	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("acquireHelper() after invalidate error = %v", err)
	}
	if len(commands) != 6 {
		t.Fatalf("exec command count = %d, want 6", len(commands))
	}
}

func TestAcquireHelperDifferentTargetsCopySeparately(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	expectedChecksum := sha256Hex([]byte("helper-binary"))
	targets := []*target.Target{
		NewTarget("default", "nginx-a", "app"),
		NewTarget("default", "nginx-b", "app"),
	}

	paths := map[string]struct{}{}
	var copyCount int
	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			switch req.Command[len(req.Command)-1] {
			case helperpkg.CapabilityChecksum:
				_, _ = req.Stdout.Write([]byte(expectedChecksum + "\n"))
			case helperpkg.CapabilityHealth:
				_ = json.NewEncoder(req.Stdout).Encode(helperpkg.Health{
					Protocol:     helperpkg.ProtocolVersion,
					Capabilities: helperpkg.DefaultCapabilities(),
				})
			default:
				copyCount++
				paths[req.Command[4]] = struct{}{}
			}
			return 0, nil
		},
	}
	b.helperProvider = NewCopyHelperProvider(b, CopyHelperProviderOptions{LocalPath: helperPath, RemoteDir: "/work"})

	for _, tgt := range targets {
		if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
			t.Fatalf("acquireHelper(%s) error = %v", tgt.ToPath(), err)
		}
	}
	if copyCount != 2 {
		t.Fatalf("copy count = %d, want 2", copyCount)
	}
	if len(paths) != 2 {
		t.Fatalf("copied helper paths = %d, want 2", len(paths))
	}
}

type helperExecStep func(*helperExecScript, backend.ExecRequest) (int, error)

type helperExecScript struct {
	t *testing.T

	steps      []helperExecStep
	commands   [][]string
	remotePath string
	helperData string
	tarData    []byte
}

func newHelperExecScript(t *testing.T, steps ...helperExecStep) *helperExecScript {
	t.Helper()
	return &helperExecScript{t: t, steps: steps}
}

func (s *helperExecScript) backend() *Backend {
	return &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			step := len(s.commands)
			s.commands = append(s.commands, append([]string(nil), req.Command...))
			if step >= len(s.steps) {
				s.t.Fatalf("unexpected exec command #%d: %#v", step+1, req.Command)
			}
			return s.steps[step](s, req)
		},
	}
}

func (s *helperExecScript) rememberRemotePath(req backend.ExecRequest) {
	s.t.Helper()
	if len(req.Command) < 5 {
		s.t.Fatalf("copy command = %#v, want remote path argument", req.Command)
	}
	if s.remotePath == "" {
		s.remotePath = req.Command[4]
	}
	if req.Command[4] != s.remotePath {
		s.t.Fatalf("copy path = %q, want %q", req.Command[4], s.remotePath)
	}
}

func helperShellCopySuccess(s *helperExecScript, req backend.ExecRequest) (int, error) {
	s.t.Helper()
	s.rememberRemotePath(req)
	if len(req.Command) < 5 || req.Command[0] != "sh" {
		s.t.Fatalf("shell copy command = %#v", req.Command)
	}
	data, err := io.ReadAll(req.Stdin)
	if err != nil {
		s.t.Fatalf("ReadAll(copy stdin) error = %v", err)
	}
	s.helperData = string(data)
	return 0, nil
}

func helperShellCopyExit(code int) helperExecStep {
	return func(s *helperExecScript, req backend.ExecRequest) (int, error) {
		s.t.Helper()
		s.rememberRemotePath(req)
		if len(req.Command) < 5 || req.Command[0] != "sh" {
			s.t.Fatalf("shell copy command = %#v", req.Command)
		}
		return code, nil
	}
}

func helperTarCopySuccess(remoteDir string) helperExecStep {
	return func(s *helperExecScript, req backend.ExecRequest) (int, error) {
		s.t.Helper()
		want := []string{"tar", "-xf", "-", "-C", remoteDir}
		if !equalStrings(req.Command, want) {
			s.t.Fatalf("tar command = %#v, want %#v", req.Command, want)
		}
		data, err := io.ReadAll(req.Stdin)
		if err != nil {
			s.t.Fatalf("ReadAll(tar stdin) error = %v", err)
		}
		s.tarData = data
		return 0, nil
	}
}

func helperChecksum(checksum string) helperExecStep {
	return func(s *helperExecScript, req backend.ExecRequest) (int, error) {
		s.t.Helper()
		want := []string{s.remotePath, helperpkg.CapabilityChecksum}
		if !equalStrings(req.Command, want) {
			s.t.Fatalf("checksum command = %#v, want %#v", req.Command, want)
		}
		_, _ = req.Stdout.Write([]byte(checksum + "\n"))
		return 0, nil
	}
}

func helperHealth(health helperpkg.Health) helperExecStep {
	return func(s *helperExecScript, req backend.ExecRequest) (int, error) {
		s.t.Helper()
		want := []string{s.remotePath, helperpkg.CapabilityHealth}
		if !equalStrings(req.Command, want) {
			s.t.Fatalf("health command = %#v, want %#v", req.Command, want)
		}
		_ = json.NewEncoder(req.Stdout).Encode(health)
		return 0, nil
	}
}

func validHelperHealth() helperpkg.Health {
	return helperpkg.Health{
		Protocol:     helperpkg.ProtocolVersion,
		Capabilities: helperpkg.DefaultCapabilities(),
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func writeTempHelper(t *testing.T, data string) string {
	t.Helper()
	path := t.TempDir() + "/kube-ssh-helper"
	if err := os.WriteFile(path, []byte(data), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func assertSingleHelperTar(t *testing.T, data []byte, name, content string) {
	t.Helper()
	reader := tar.NewReader(bytes.NewReader(data))
	header, err := reader.Next()
	if err != nil {
		t.Fatalf("tar Next() error = %v", err)
	}
	if header.Name != name {
		t.Fatalf("tar header name = %q, want %q", header.Name, name)
	}
	if header.Mode != 0o755 {
		t.Fatalf("tar header mode = %#o, want 0755", header.Mode)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll(tar file) error = %v", err)
	}
	if string(got) != content {
		t.Fatalf("tar content = %q, want %q", got, content)
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("second tar Next() error = %v, want EOF", err)
	}
}
