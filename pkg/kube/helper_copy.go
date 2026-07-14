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
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"xiaoshiai.cn/kube-ssh/pkg/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// copyHelperAcquirer acquires kube-ssh-helper by copying the local binary into
// the target container through Kubernetes exec. It caches prepared helpers by
// target and helper build identity; concurrent acquires for the same cache entry
// share one copy/version-probe sequence.
type copyHelperAcquirer struct {
	backend   *Backend
	localPath string
	remoteDir string

	mu      sync.Mutex
	helpers map[string]*copyHelperState
}

type copyHelperAcquirerOptions struct {
	LocalPath string
	RemoteDir string
}

func newCopyHelperAcquirer(backend *Backend, opts copyHelperAcquirerOptions) *copyHelperAcquirer {
	if opts.RemoteDir == "" {
		opts.RemoteDir = "/tmp"
	}
	return &copyHelperAcquirer{
		backend:   backend,
		localPath: opts.LocalPath,
		remoteDir: opts.RemoteDir,
		helpers:   make(map[string]*copyHelperState),
	}
}

func (a *copyHelperAcquirer) Acquire(ctx context.Context, tgt *target.Target, capability string) (helperLease, error) {
	if a.localPath == "" {
		return nil, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper path is required for %s", capability)
	}

	// TODO: Support multiple helper paths selected from the target pod's node
	// OS and architecture. The current single-path configuration assumes the
	// configured helper can execute in every target container.
	expected := helperpkg.CurrentManifest()
	key := helperCacheKey(tgt, expected)
	state, owner := a.helperState(key)
	if owner {
		var data []byte
		data, state.err = a.readHelperBinary()
		if state.err == nil {
			state.path, state.manifest, state.err = a.prepareHelper(ctx, tgt, data, expected)
		}
		a.finishHelperState(key, state)
	} else {
		select {
		case <-state.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if state.err != nil {
		return nil, state.err
	}
	if err := validateHelperManifest(state.manifest, expected, capability); err != nil {
		return nil, err
	}

	return &copyHelperLease{path: state.path}, nil
}

// Invalidate discards cached helper state for tgt. It does not remove helper
// files that were already copied into the target container.
func (a *copyHelperAcquirer) Invalidate(tgt *target.Target) {
	prefix := helperCachePrefix(tgt)
	a.mu.Lock()
	defer a.mu.Unlock()
	for key := range a.helpers {
		if strings.HasPrefix(key, prefix) {
			delete(a.helpers, key)
		}
	}
}

type copyHelperState struct {
	done     chan struct{}
	path     string
	manifest helperpkg.Manifest
	err      error
}

func (a *copyHelperAcquirer) helperState(key string) (*copyHelperState, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if state := a.helpers[key]; state != nil {
		return state, false
	}
	state := &copyHelperState{done: make(chan struct{})}
	a.helpers[key] = state
	return state, true
}

func (a *copyHelperAcquirer) finishHelperState(key string, state *copyHelperState) {
	a.mu.Lock()
	if state.err != nil && a.helpers[key] == state {
		delete(a.helpers, key)
	}
	a.mu.Unlock()
	close(state.done)
}

type copyHelperLease struct {
	path string
}

func (h *copyHelperLease) Command(args ...string) []string {
	command := make([]string, 0, len(args)+1)
	command = append(command, h.path)
	command = append(command, args...)
	return command
}

func (h *copyHelperLease) Release(ctx context.Context) error {
	return nil
}

type helperCopyMethod struct {
	name string
	copy func(context.Context, *target.Target, string, []byte) error
}

func (a *copyHelperAcquirer) readHelperBinary() ([]byte, error) {
	data, err := os.ReadFile(a.localPath)
	if err != nil {
		return nil, status.HelperUnavailable(err, "read helper binary")
	}
	return data, nil
}

func (a *copyHelperAcquirer) prepareHelper(ctx context.Context, tgt *target.Target, data []byte, expected helperpkg.Manifest) (string, helperpkg.Manifest, error) {
	remotePath, err := a.copyHelperBinary(ctx, tgt, data, expected)
	if err != nil {
		return "", helperpkg.Manifest{}, err
	}
	manifest, err := a.probeVersion(ctx, tgt, remotePath)
	if err != nil {
		return "", helperpkg.Manifest{}, err
	}
	if err := validateHelperManifest(manifest, expected, ""); err != nil {
		return "", helperpkg.Manifest{}, err
	}
	return remotePath, manifest, nil
}

func (a *copyHelperAcquirer) copyHelperBinary(ctx context.Context, tgt *target.Target, data []byte, manifest helperpkg.Manifest) (string, error) {
	remotePath := a.helperRemotePath(tgt, manifest)
	var failures []string
	for _, method := range a.copyMethods() {
		if err := method.copy(ctx, tgt, remotePath, data); err == nil {
			return remotePath, nil
		} else {
			failures = append(failures, fmt.Sprintf("%s: %v", method.name, err))
		}
	}
	return "", status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "inject helper failed: %s", strings.Join(failures, "; "))
}

func (a *copyHelperAcquirer) helperRemotePath(tgt *target.Target, manifest helperpkg.Manifest) string {
	// The digest only turns the version identity into a short, path-safe token;
	// it is not used to verify the helper binary.
	sum := sha256.Sum256([]byte(helperCacheKey(tgt, manifest)))
	return path.Join(a.remoteDir, "kube-ssh-helper-"+hex.EncodeToString(sum[:])[:32])
}

func (a *copyHelperAcquirer) copyMethods() []helperCopyMethod {
	return []helperCopyMethod{
		{name: "sh/cat/chmod", copy: a.copyHelperBinaryWithShell},
		{name: "tar", copy: a.copyHelperBinaryWithTar},
	}
}

func (a *copyHelperAcquirer) copyHelperBinaryWithShell(ctx context.Context, tgt *target.Target, remotePath string, data []byte) error {
	exitCode, err := a.backend.exec(ctx, backend.ExecRequest{
		Target: tgt,
		Command: []string{
			"sh",
			"-c",
			`cat > "$1" && chmod +x "$1"`,
			"sh",
			remotePath,
		},
		Stdin:  bytes.NewReader(data),
		Stdout: io.Discard,
		Stderr: io.Discard,
		TTY:    false,
	})
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("exited with %d", exitCode)
	}
	return nil
}

func (a *copyHelperAcquirer) copyHelperBinaryWithTar(ctx context.Context, tgt *target.Target, remotePath string, data []byte) error {
	archive, err := helperTarArchive(path.Base(remotePath), data)
	if err != nil {
		return err
	}
	exitCode, err := a.backend.exec(ctx, backend.ExecRequest{
		Target: tgt,
		Command: []string{
			"tar",
			"-xf",
			"-",
			"-C",
			path.Dir(remotePath),
		},
		Stdin:  bytes.NewReader(archive),
		Stdout: io.Discard,
		Stderr: io.Discard,
		TTY:    false,
	})
	if err != nil {
		return err
	}
	if exitCode != 0 {
		return fmt.Errorf("exited with %d", exitCode)
	}
	return nil
}

func helperTarArchive(name string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := tar.NewWriter(&buf)
	if err := writer.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(data)),
	}); err != nil {
		return nil, err
	}
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (a *copyHelperAcquirer) probeVersion(ctx context.Context, tgt *target.Target, remotePath string) (helperpkg.Manifest, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode, err := a.backend.exec(ctx, backend.ExecRequest{
		Target:  tgt,
		Command: []string{remotePath, helperpkg.CommandVersion},
		Stdout:  &stdout,
		Stderr:  &stderr,
		TTY:     false,
	})
	if err != nil {
		return helperpkg.Manifest{}, status.HelperUnavailable(err, "run helper version")
	}
	if exitCode != 0 {
		return helperpkg.Manifest{}, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper version exited with %d: %s", exitCode, bytes.TrimSpace(stderr.Bytes()))
	}

	manifest := helperpkg.Manifest{}
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		return helperpkg.Manifest{}, status.HelperUnavailable(err, "decode helper version")
	}
	return manifest, nil
}

func helperCacheKey(tgt *target.Target, manifest helperpkg.Manifest) string {
	return helperCachePrefix(tgt) + manifest.Version + "\x00" + manifest.Commit
}

func helperCachePrefix(tgt *target.Target) string {
	if tgt == nil {
		return "<nil>\x00"
	}
	return tgt.ToPath() + "\x00"
}
