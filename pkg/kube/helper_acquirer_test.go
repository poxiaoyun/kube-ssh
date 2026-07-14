package kube

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func TestValidateHelperManifest(t *testing.T) {
	expected := validHelperManifest()
	valid := expected
	if err := validateHelperManifest(valid, expected, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("validateHelperManifest() error = %v", err)
	}

	wrongVersion := valid
	wrongVersion.Version = "old"
	if err := validateHelperManifest(wrongVersion, expected, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("validateHelperManifest() succeeded for wrong version")
	}

	wrongCommit := valid
	wrongCommit.Commit = "other"
	if err := validateHelperManifest(wrongCommit, expected, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("validateHelperManifest() succeeded for wrong commit")
	}

	wrongProtocol := valid
	wrongProtocol.ProtocolVersion = "old"
	if err := validateHelperManifest(wrongProtocol, expected, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("validateHelperManifest() succeeded for wrong protocol")
	}

	differentMetadata := valid
	differentMetadata.BuildDate = "another build"
	differentMetadata.OS = "another-os"
	differentMetadata.Arch = "another-arch"
	if err := validateHelperManifest(differentMetadata, expected, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("validateHelperManifest() rejected diagnostic metadata: %v", err)
	}

	missingRequired := valid
	missingRequired.Capabilities = []string{helperpkg.CapabilitySFTP}
	if err := validateHelperManifest(missingRequired, expected, helperpkg.CapabilitySCP); err == nil {
		t.Fatal("validateHelperManifest() succeeded without required capability")
	}
}

func TestDefaultHelperCapabilitiesAdvertiseProtocolCommands(t *testing.T) {
	manifest := validHelperManifest()

	for _, capability := range []string{
		helperpkg.CapabilityDial,
		helperpkg.CapabilityRemoteForward,
		helperpkg.CapabilityAgentForward,
		helperpkg.CapabilitySFTP,
		helperpkg.CapabilitySCP,
	} {
		if err := validateHelperManifest(manifest, manifest, capability); err != nil {
			t.Fatalf("validateHelperManifest(%q) error = %v", capability, err)
		}
	}
}

func TestAcquireHelperRecordsActiveUntilFirstRelease(t *testing.T) {
	recorder := &helperMetricsRecorder{}
	handle := &recordinghelperLease{}
	b := &Backend{
		helperAcquirer: statichelperAcquirer{handle: handle},
		metrics:        recorder,
	}

	acquired, err := b.acquireHelper(context.Background(), NewTarget("default", "nginx", "app"), helperpkg.CapabilitySFTP)
	if err != nil {
		t.Fatalf("acquireHelper() error = %v", err)
	}
	if recorder.acquired != 1 {
		t.Fatalf("acquired metrics = %d, want 1", recorder.acquired)
	}
	if err := acquired.Release(context.Background()); err != nil {
		t.Fatalf("Release() error = %v", err)
	}
	if err := acquired.Release(context.Background()); err != nil {
		t.Fatalf("second Release() error = %v", err)
	}
	if handle.releaseCount != 2 {
		t.Fatalf("underlying release count = %d, want 2", handle.releaseCount)
	}
	if recorder.released != 1 {
		t.Fatalf("release metrics = %d, want 1", recorder.released)
	}
}

func TestAcquireHelperCopiesProbesVersionAndCaches(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")

	script := newHelperExecScript(t,
		helperShellCopySuccess,
		helperVersion(validHelperManifest()),
	)
	b := script.backend()
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

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
	if err := os.Remove(helperPath); err != nil {
		t.Fatalf("Remove(helper) error = %v", err)
	}

	second, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySCP)
	if err != nil {
		t.Fatalf("second acquireHelper() error = %v", err)
	}
	if got := second.Command(helperpkg.CapabilitySCP); !equalStrings(got, []string{script.remotePath, helperpkg.CapabilitySCP}) {
		t.Fatalf("second helper command = %#v", got)
	}

	if len(script.commands) != 2 {
		t.Fatalf("exec command count = %d, want 2", len(script.commands))
	}
	if script.commands[0][0] != "sh" || script.commands[0][4] == "" {
		t.Fatalf("copy command = %#v", script.commands[0])
	}
}

func TestHelperCacheKeyUsesVersionIdentity(t *testing.T) {
	tgt := NewTarget("default", "nginx", "app")
	manifest := validHelperManifest()
	key := helperCacheKey(tgt, manifest)

	metadata := manifest
	metadata.BuildDate = "another build"
	metadata.OS = "another-os"
	metadata.Arch = "another-arch"
	if got := helperCacheKey(tgt, metadata); got != key {
		t.Fatalf("diagnostic metadata changed cache key: %q != %q", got, key)
	}

	otherVersion := manifest
	otherVersion.Version = "another-version"
	if got := helperCacheKey(tgt, otherVersion); got == key {
		t.Fatal("version did not change cache key")
	}

	otherCommit := manifest
	otherCommit.Commit = "another-commit"
	if got := helperCacheKey(tgt, otherCommit); got == key {
		t.Fatal("commit did not change cache key")
	}
}

type helperMetricsRecorder struct {
	metrics.NopRecorder
	acquired int
	released int
}

func (r *helperMetricsRecorder) HelperAcquired(string) {
	r.acquired++
}

func (r *helperMetricsRecorder) HelperReleased(string, string, time.Duration) {
	r.released++
}

type statichelperAcquirer struct {
	handle helperLease
}

func (p statichelperAcquirer) Acquire(context.Context, *target.Target, string) (helperLease, error) {
	return p.handle, nil
}

type recordinghelperLease struct {
	releaseCount int
}

func (h *recordinghelperLease) Command(args ...string) []string {
	return append([]string{"helper"}, args...)
}

func (h *recordinghelperLease) Release(context.Context) error {
	h.releaseCount++
	return nil
}

func TestAcquireHelperFallsBackToTarCopy(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")

	script := newHelperExecScript(t,
		helperShellCopyExit(127),
		helperTarCopySuccess("/work"),
		helperVersion(validHelperManifest()),
	)
	b := script.backend()
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

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
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

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

func TestAcquireHelperVersionMismatchDoesNotCache(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")
	wrong := validHelperManifest()
	wrong.Commit = "wrong"

	script := newHelperExecScript(t,
		helperShellCopySuccess,
		helperVersion(wrong),
		helperShellCopySuccess,
		helperVersion(validHelperManifest()),
	)
	b := script.backend()
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("acquireHelper() succeeded with version mismatch")
	}
	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("retry acquireHelper() error = %v", err)
	}
	if len(script.commands) != 4 {
		t.Fatalf("exec command count = %d, want 4", len(script.commands))
	}
}

func TestAcquireHelperProtocolFailureDoesNotCache(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")
	invalid := validHelperManifest()
	invalid.ProtocolVersion = "old"

	script := newHelperExecScript(t,
		helperShellCopySuccess,
		helperVersion(invalid),
		helperShellCopySuccess,
		helperVersion(validHelperManifest()),
	)
	b := script.backend()
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err == nil {
		t.Fatal("acquireHelper() succeeded with invalid protocol")
	}
	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("retry acquireHelper() error = %v", err)
	}
	if len(script.commands) != 4 {
		t.Fatalf("exec command count = %d, want 4", len(script.commands))
	}
}

func TestAcquireHelperConcurrentSameTargetCopiesOnce(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")

	var mu sync.Mutex
	var copyCount int
	var versionCount int
	var helperPathRemote string
	copyStarted := make(chan struct{})
	releaseCopy := make(chan struct{})
	var closeStarted sync.Once

	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			switch req.Command[len(req.Command)-1] {
			case helperpkg.CommandVersion:
				mu.Lock()
				versionCount++
				mu.Unlock()
				_ = json.NewEncoder(req.Stdout).Encode(validHelperManifest())
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
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

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
	gotVersionCount := versionCount
	mu.Unlock()
	for gotPath := range paths {
		if gotPath != wantPath {
			t.Fatalf("helper path = %q, want %q", gotPath, wantPath)
		}
	}
	if gotCopyCount != 1 {
		t.Fatalf("copy count = %d, want 1", gotCopyCount)
	}
	if gotVersionCount != 1 {
		t.Fatalf("version count = %d, want 1", gotVersionCount)
	}
}

func TestCopyHelperAcquirerInvalidateTarget(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	tgt := NewTarget("default", "nginx", "app")

	var commands [][]string
	var helperPathRemote string
	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			commands = append(commands, append([]string(nil), req.Command...))
			switch req.Command[len(req.Command)-1] {
			case helperpkg.CommandVersion:
				_ = json.NewEncoder(req.Stdout).Encode(validHelperManifest())
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
	provider := newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})
	b.helperAcquirer = provider

	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("acquireHelper() error = %v", err)
	}
	provider.Invalidate(tgt)
	if _, err := b.acquireHelper(context.Background(), tgt, helperpkg.CapabilitySFTP); err != nil {
		t.Fatalf("acquireHelper() after invalidate error = %v", err)
	}
	if len(commands) != 4 {
		t.Fatalf("exec command count = %d, want 4", len(commands))
	}
}

func TestAcquireHelperDifferentTargetsCopySeparately(t *testing.T) {
	helperPath := writeTempHelper(t, "helper-binary")
	targets := []*target.Target{
		NewTarget("default", "nginx-a", "app"),
		NewTarget("default", "nginx-b", "app"),
	}

	paths := map[string]struct{}{}
	var copyCount int
	b := &Backend{
		execOverride: func(_ context.Context, req backend.ExecRequest) (int, error) {
			switch req.Command[len(req.Command)-1] {
			case helperpkg.CommandVersion:
				_ = json.NewEncoder(req.Stdout).Encode(validHelperManifest())
			default:
				copyCount++
				paths[req.Command[4]] = struct{}{}
			}
			return 0, nil
		},
	}
	b.helperAcquirer = newCopyHelperAcquirer(b, copyHelperAcquirerOptions{LocalPath: helperPath, RemoteDir: "/work"})

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

func helperVersion(manifest helperpkg.Manifest) helperExecStep {
	return func(s *helperExecScript, req backend.ExecRequest) (int, error) {
		s.t.Helper()
		want := []string{s.remotePath, helperpkg.CommandVersion}
		if !equalStrings(req.Command, want) {
			s.t.Fatalf("version command = %#v, want %#v", req.Command, want)
		}
		_ = json.NewEncoder(req.Stdout).Encode(manifest)
		return 0, nil
	}
}

func validHelperManifest() helperpkg.Manifest {
	return helperpkg.CurrentManifest()
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
