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

// CopyHelperProvider acquires kube-ssh-helper by copying the local binary into
// the target container through Kubernetes exec. It caches prepared helpers by
// target and local binary checksum; concurrent acquires for the same cache entry
// share one copy/checksum/health sequence.
type CopyHelperProvider struct {
	backend   *Backend
	localPath string
	remoteDir string

	mu      sync.Mutex
	helpers map[string]*copyHelperState
}

type CopyHelperProviderOptions struct {
	LocalPath string
	RemoteDir string
}

func NewCopyHelperProvider(backend *Backend, opts CopyHelperProviderOptions) *CopyHelperProvider {
	if opts.RemoteDir == "" {
		opts.RemoteDir = "/tmp"
	}
	return &CopyHelperProvider{
		backend:   backend,
		localPath: opts.LocalPath,
		remoteDir: opts.RemoteDir,
		helpers:   make(map[string]*copyHelperState),
	}
}

func (i *CopyHelperProvider) Acquire(ctx context.Context, tgt *target.Target, capability string) (HelperHandle, error) {
	if i.localPath == "" {
		return nil, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper path is required for %s", capability)
	}

	local, err := i.readHelperBinary()
	if err != nil {
		return nil, err
	}

	key := helperCacheKey(tgt, local.checksum)
	state, owner := i.helperState(key)
	if owner {
		state.path, state.health, state.err = i.prepareHelper(ctx, tgt, local)
		i.finishHelperState(key, state)
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
	if err := ValidateHelperHealth(state.health, capability); err != nil {
		return nil, err
	}

	return &copyHelperHandle{path: state.path}, nil
}

// Invalidate discards cached helper state for tgt. It does not remove helper
// files that were already copied into the target container.
func (i *CopyHelperProvider) Invalidate(tgt *target.Target) {
	prefix := helperCachePrefix(tgt)
	i.mu.Lock()
	defer i.mu.Unlock()
	for key := range i.helpers {
		if strings.HasPrefix(key, prefix) {
			delete(i.helpers, key)
		}
	}
}

type copyHelperState struct {
	done   chan struct{}
	path   string
	health helperpkg.Health
	err    error
}

func (i *CopyHelperProvider) helperState(key string) (*copyHelperState, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if state := i.helpers[key]; state != nil {
		return state, false
	}
	state := &copyHelperState{done: make(chan struct{})}
	i.helpers[key] = state
	return state, true
}

func (i *CopyHelperProvider) finishHelperState(key string, state *copyHelperState) {
	i.mu.Lock()
	if state.err != nil && i.helpers[key] == state {
		delete(i.helpers, key)
	}
	i.mu.Unlock()
	close(state.done)
}

type copyHelperHandle struct {
	path string
}

func (h *copyHelperHandle) Command(args ...string) []string {
	command := make([]string, 0, len(args)+1)
	command = append(command, h.path)
	command = append(command, args...)
	return command
}

func (h *copyHelperHandle) Release(ctx context.Context) error {
	return nil
}

type helperBinary struct {
	data     []byte
	path     string
	checksum string
}

type helperCopyMethod struct {
	name string
	copy func(context.Context, *target.Target, string, []byte) error
}

func (i *CopyHelperProvider) readHelperBinary() (helperBinary, error) {
	data, err := os.ReadFile(i.localPath)
	if err != nil {
		return helperBinary{}, status.HelperUnavailable(err, "read helper binary")
	}
	sum := sha256.Sum256(data)
	return helperBinary{
		data:     data,
		checksum: hex.EncodeToString(sum[:]),
	}, nil
}

func (i *CopyHelperProvider) prepareHelper(ctx context.Context, tgt *target.Target, local helperBinary) (string, helperpkg.Health, error) {
	binary, err := i.copyHelperBinary(ctx, tgt, local)
	if err != nil {
		return "", helperpkg.Health{}, err
	}
	if err := i.verifyHelperHandleChecksum(ctx, tgt, binary); err != nil {
		return "", helperpkg.Health{}, err
	}
	health, err := i.checkHelperHandle(ctx, tgt, binary.path)
	if err != nil {
		return "", helperpkg.Health{}, err
	}
	return binary.path, health, nil
}

func (i *CopyHelperProvider) copyHelperBinary(ctx context.Context, tgt *target.Target, local helperBinary) (helperBinary, error) {
	remotePath := i.helperRemotePath(tgt, local.checksum)
	var failures []string
	for _, method := range i.copyMethods() {
		if err := method.copy(ctx, tgt, remotePath, local.data); err == nil {
			return helperBinary{
				data:     local.data,
				path:     remotePath,
				checksum: local.checksum,
			}, nil
		} else {
			failures = append(failures, fmt.Sprintf("%s: %v", method.name, err))
		}
	}
	return helperBinary{}, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "inject helper failed: %s", strings.Join(failures, "; "))
}

func (i *CopyHelperProvider) helperRemotePath(tgt *target.Target, checksum string) string {
	sum := sha256.Sum256([]byte(helperCacheKey(tgt, checksum)))
	return path.Join(i.remoteDir, "kube-ssh-helper-"+hex.EncodeToString(sum[:])[:32])
}

func (i *CopyHelperProvider) copyMethods() []helperCopyMethod {
	return []helperCopyMethod{
		{name: "sh/cat/chmod", copy: i.copyHelperBinaryWithShell},
		{name: "tar", copy: i.copyHelperBinaryWithTar},
	}
}

func (i *CopyHelperProvider) copyHelperBinaryWithShell(ctx context.Context, tgt *target.Target, remotePath string, data []byte) error {
	exitCode, err := i.backend.runExec(ctx, backend.ExecRequest{
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

func (i *CopyHelperProvider) copyHelperBinaryWithTar(ctx context.Context, tgt *target.Target, remotePath string, data []byte) error {
	archive, err := helperTarArchive(path.Base(remotePath), data)
	if err != nil {
		return err
	}
	exitCode, err := i.backend.runExec(ctx, backend.ExecRequest{
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

func (i *CopyHelperProvider) verifyHelperHandleChecksum(ctx context.Context, tgt *target.Target, binary helperBinary) error {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode, err := i.backend.runExec(ctx, backend.ExecRequest{
		Target:  tgt,
		Command: []string{binary.path, helperpkg.CapabilityChecksum},
		Stdout:  &stdout,
		Stderr:  &stderr,
		TTY:     false,
	})
	if err != nil {
		return status.HelperUnavailable(err, "run helper checksum")
	}
	if exitCode != 0 {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper checksum exited with %d: %s", exitCode, bytes.TrimSpace(stderr.Bytes()))
	}
	remoteChecksum := strings.TrimSpace(stdout.String())
	if remoteChecksum != binary.checksum {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper checksum mismatch: remote %s, local %s", remoteChecksum, binary.checksum)
	}
	return nil
}

func (i *CopyHelperProvider) checkHelperHandle(ctx context.Context, tgt *target.Target, remotePath string) (helperpkg.Health, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode, err := i.backend.runExec(ctx, backend.ExecRequest{
		Target:  tgt,
		Command: []string{remotePath, helperpkg.CapabilityHealth},
		Stdout:  &stdout,
		Stderr:  &stderr,
		TTY:     false,
	})
	if err != nil {
		return helperpkg.Health{}, status.HelperUnavailable(err, "run helper health")
	}
	if exitCode != 0 {
		return helperpkg.Health{}, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper health exited with %d: %s", exitCode, bytes.TrimSpace(stderr.Bytes()))
	}

	health := helperpkg.Health{}
	if err := json.Unmarshal(stdout.Bytes(), &health); err != nil {
		return helperpkg.Health{}, status.HelperUnavailable(err, "decode helper health")
	}
	if err := ValidateHelperHealth(health, ""); err != nil {
		return helperpkg.Health{}, err
	}
	return health, nil
}

func helperCacheKey(tgt *target.Target, checksum string) string {
	return helperCachePrefix(tgt) + checksum
}

func helperCachePrefix(tgt *target.Target) string {
	if tgt == nil {
		return "<nil>\x00"
	}
	return tgt.ToPath() + "\x00"
}
