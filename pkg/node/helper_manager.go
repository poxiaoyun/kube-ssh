package node

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
)

type helperManager struct {
	ctx            context.Context
	runtime        runtimeClient
	remoteDir      string
	manifest       helperpkg.Manifest
	prepareTimeout time.Duration
	cacheTTL       time.Duration
	load           func() ([]byte, error)
	inject         func(context.Context, string, string, []byte) error
	ready          *utilcache.LRUExpireCache
	inflight       singleflight.Group
}

const (
	helperPrepareTimeout = time.Minute
	helperCacheTTL       = 24 * time.Hour
	helperCacheSize      = 4096
)

func newHelperManager(ctx context.Context, runtime runtimeClient, localPath, remoteDir string) *helperManager {
	if remoteDir == "" {
		remoteDir = "/tmp"
	}
	manager := &helperManager{
		ctx:            ctx,
		runtime:        runtime,
		remoteDir:      remoteDir,
		manifest:       helperpkg.CurrentManifest(),
		prepareTimeout: helperPrepareTimeout,
		cacheTTL:       helperCacheTTL,
		ready:          utilcache.NewLRUExpireCache(helperCacheSize),
	}
	manager.load = sync.OnceValues(func() ([]byte, error) {
		if localPath == "" {
			return nil, fmt.Errorf("helper path is required")
		}
		return os.ReadFile(localPath)
	})
	manager.inject = manager.copy
	return manager
}

func (m *helperManager) prepare(ctx context.Context, containerID, capability string) (string, error) {
	if !slices.Contains(m.manifest.Capabilities, capability) {
		return "", fmt.Errorf("helper does not advertise capability %q", capability)
	}
	key := containerID + "\x00" + m.manifest.Version + "\x00" + m.manifest.Commit
	if remotePath, ok := m.ready.Get(key); ok {
		return remotePath.(string), nil
	}

	result := m.inflight.DoChan(key, func() (any, error) {
		prepareCtx, cancel := context.WithTimeout(m.ctx, m.prepareTimeout)
		defer cancel()
		if remotePath, ok := m.ready.Get(key); ok {
			return remotePath, nil
		}
		remotePath := m.remotePath(key)
		data, err := m.load()
		if err != nil {
			return nil, fmt.Errorf("read helper binary: %w", err)
		}
		if err := m.inject(prepareCtx, containerID, remotePath, data); err != nil {
			return nil, err
		}
		if err := m.probe(prepareCtx, containerID, remotePath); err != nil {
			return nil, fmt.Errorf("verify injected helper: %w", err)
		}
		m.ready.Add(key, remotePath, m.cacheTTL)
		return remotePath, nil
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case completed := <-result:
		if completed.Err != nil {
			return "", completed.Err
		}
		return completed.Val.(string), nil
	}
}

func (m *helperManager) remotePath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return path.Join(m.remoteDir, "kube-ssh-helper-"+hex.EncodeToString(sum[:])[:32])
}

func (m *helperManager) probe(ctx context.Context, containerID, remotePath string) error {
	probe, err := m.runtime.ExecSync(ctx, &runtimeapi.ExecSyncRequest{
		ContainerId: containerID,
		Cmd:         []string{remotePath, helperpkg.CommandVersion},
		Timeout:     30,
	})
	if err != nil {
		return fmt.Errorf("probe helper version: %w", err)
	}
	if probe.ExitCode != 0 {
		return fmt.Errorf("helper version exited with %d: %s", probe.ExitCode, bytes.TrimSpace(probe.Stderr))
	}
	var actual helperpkg.Manifest
	if err := json.Unmarshal(probe.Stdout, &actual); err != nil {
		return fmt.Errorf("decode helper version: %w", err)
	}
	if actual.ProtocolVersion != helperpkg.ProtocolVersion || actual.Version != m.manifest.Version || actual.Commit != m.manifest.Commit {
		return fmt.Errorf("helper identity mismatch: got %s/%s protocol %s, want %s/%s protocol %s", actual.Version, actual.Commit, actual.ProtocolVersion, m.manifest.Version, m.manifest.Commit, helperpkg.ProtocolVersion)
	}
	if !sameCapabilities(actual.Capabilities, m.manifest.Capabilities) {
		return fmt.Errorf("helper capability mismatch: got %v, want %v", actual.Capabilities, m.manifest.Capabilities)
	}
	return nil
}

func sameCapabilities(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, capability := range expected {
		if !slices.Contains(actual, capability) {
			return false
		}
	}
	return true
}

func (m *helperManager) copy(ctx context.Context, containerID, remotePath string, data []byte) error {
	shellCommand := []string{"sh", "-c", `cat > "$1" && chmod +x "$1"`, "sh", remotePath}
	code, shellErr := m.streamExec(ctx, containerID, shellCommand, bytes.NewReader(data), io.Discard, io.Discard)
	if shellErr == nil && code == 0 {
		return nil
	}

	archive, err := helperTarArchive(path.Base(remotePath), data)
	if err != nil {
		return fmt.Errorf("build helper archive: %w", err)
	}
	tarCommand := []string{"tar", "-xf", "-", "-C", path.Dir(remotePath)}
	tarCode, tarErr := m.streamExec(ctx, containerID, tarCommand, bytes.NewReader(archive), io.Discard, io.Discard)
	if tarErr == nil && tarCode == 0 {
		return nil
	}
	return fmt.Errorf("inject helper failed: sh exit=%d err=%v; tar exit=%d err=%v", code, shellErr, tarCode, tarErr)
}

func helperTarArchive(name string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data))}); err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *helperManager) streamExec(ctx context.Context, containerID string, command []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	response, err := m.runtime.Exec(ctx, &runtimeapi.ExecRequest{
		ContainerId: containerID,
		Cmd:         command,
		Stdin:       stdin != nil,
		Stdout:      stdout != nil,
		Stderr:      stderr != nil,
	})
	if err != nil {
		return 1, err
	}
	u, err := parseStreamingURL(response.Url)
	if err != nil {
		return 1, err
	}
	config := &rest.Config{Host: u.Scheme + "://" + u.Host, TLSClientConfig: rest.TLSClientConfig{Insecure: u.Scheme == "https"}}
	executor, err := remotecommand.NewSPDYExecutor(config, "POST", u)
	if err != nil {
		return 1, err
	}
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdin: stdin, Stdout: stdout, Stderr: stderr})
	var exitErr interface{ ExitStatus() int }
	if errors.As(err, &exitErr) {
		return exitErr.ExitStatus(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}
