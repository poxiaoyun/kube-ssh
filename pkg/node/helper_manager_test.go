package node

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
)

type helperRuntime struct {
	fakeRuntime
	execSync func(context.Context, *runtimeapi.ExecSyncRequest) (*runtimeapi.ExecSyncResponse, error)
}

func (r *helperRuntime) ExecSync(ctx context.Context, req *runtimeapi.ExecSyncRequest, _ ...grpc.CallOption) (*runtimeapi.ExecSyncResponse, error) {
	return r.execSync(ctx, req)
}

func TestHelperPrepareTreatsSuccessfulCacheEntryAsAuthoritative(t *testing.T) {
	manifest := helperpkg.CurrentManifest()
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var probes atomic.Int32
	var rejectProbe atomic.Bool
	runtime := &helperRuntime{}
	runtime.execSync = func(context.Context, *runtimeapi.ExecSyncRequest) (*runtimeapi.ExecSyncResponse, error) {
		probes.Add(1)
		if rejectProbe.Load() {
			return nil, errors.New("probe should not run for a cache hit")
		}
		return &runtimeapi.ExecSyncResponse{Stdout: manifestJSON}, nil
	}
	manager := newTestHelperManager(t, runtime)
	var injections atomic.Int32
	manager.inject = func(context.Context, string, string, []byte) error {
		injections.Add(1)
		return nil
	}

	first, err := manager.prepare(context.Background(), "container", helperpkg.CapabilitySFTP)
	if err != nil {
		t.Fatalf("first prepare() error = %v", err)
	}
	rejectProbe.Store(true)
	second, err := manager.prepare(context.Background(), "container", helperpkg.CapabilitySFTP)
	if err != nil {
		t.Fatalf("second prepare() error = %v", err)
	}
	if first != second {
		t.Fatalf("helper paths differ: %q != %q", first, second)
	}
	if got := injections.Load(); got != 1 {
		t.Fatalf("injections = %d, want 1", got)
	}
	if got := probes.Load(); got != 1 {
		t.Fatalf("probes = %d, want 1", got)
	}
}

func TestHelperPrepareCacheIsBounded(t *testing.T) {
	manifestJSON, err := json.Marshal(helperpkg.CurrentManifest())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &helperRuntime{}
	runtime.execSync = func(context.Context, *runtimeapi.ExecSyncRequest) (*runtimeapi.ExecSyncResponse, error) {
		return &runtimeapi.ExecSyncResponse{Stdout: manifestJSON}, nil
	}
	manager := newTestHelperManager(t, runtime)
	manager.ready = utilcache.NewLRUExpireCache(1)
	var injections atomic.Int32
	manager.inject = func(context.Context, string, string, []byte) error {
		injections.Add(1)
		return nil
	}

	for _, containerID := range []string{"first", "second", "first"} {
		if _, err := manager.prepare(context.Background(), containerID, helperpkg.CapabilitySFTP); err != nil {
			t.Fatalf("prepare(%q) error = %v", containerID, err)
		}
	}
	if got := injections.Load(); got != 3 {
		t.Fatalf("injections = %d, want 3 after LRU eviction", got)
	}
}

func TestHelperPrepareCoalescesInjectionAndLetsWaitersCancel(t *testing.T) {
	manifest := helperpkg.CurrentManifest()
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var installed atomic.Bool
	runtime := &helperRuntime{}
	runtime.execSync = func(context.Context, *runtimeapi.ExecSyncRequest) (*runtimeapi.ExecSyncResponse, error) {
		if installed.Load() {
			return &runtimeapi.ExecSyncResponse{Stdout: manifestJSON}, nil
		}
		return &runtimeapi.ExecSyncResponse{ExitCode: 127}, nil
	}
	manager := newTestHelperManager(t, runtime)
	injectionStarted := make(chan struct{})
	releaseInjection := make(chan struct{})
	var injections atomic.Int32
	manager.inject = func(ctx context.Context, _, _ string, _ []byte) error {
		if injections.Add(1) == 1 {
			close(injectionStarted)
		}
		select {
		case <-releaseInjection:
			installed.Store(true)
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	ownerDone := make(chan error, 1)
	go func() {
		_, err := manager.prepare(context.Background(), "container", helperpkg.CapabilitySFTP)
		ownerDone <- err
	}()
	<-injectionStarted

	const waiters = 8
	var waitersReady sync.WaitGroup
	waitersReady.Add(waiters)
	waiterDone := make(chan error, waiters)
	for range waiters {
		go func() {
			waitersReady.Done()
			_, err := manager.prepare(context.Background(), "container", helperpkg.CapabilitySFTP)
			waiterDone <- err
		}()
	}
	waitersReady.Wait()

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if _, err := manager.prepare(cancelCtx, "container", helperpkg.CapabilitySFTP); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prepare() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("canceled waiter returned after %s", elapsed)
	}

	close(releaseInjection)
	if err := <-ownerDone; err != nil {
		t.Fatalf("owner prepare() error = %v", err)
	}
	for range waiters {
		if err := <-waiterDone; err != nil {
			t.Fatalf("waiter prepare() error = %v", err)
		}
	}
	if got := injections.Load(); got != 1 {
		t.Fatalf("injections = %d, want 1", got)
	}
}

func TestHelperPrepareStopsSharedWorkWithManager(t *testing.T) {
	managerCtx, stop := context.WithCancel(context.Background())
	runtime := &helperRuntime{}
	runtime.execSync = func(context.Context, *runtimeapi.ExecSyncRequest) (*runtimeapi.ExecSyncResponse, error) {
		return &runtimeapi.ExecSyncResponse{ExitCode: 127}, nil
	}
	manager := newTestHelperManagerWithContext(t, managerCtx, runtime)
	injectionStarted := make(chan struct{})
	manager.inject = func(ctx context.Context, _, _ string, _ []byte) error {
		close(injectionStarted)
		<-ctx.Done()
		return ctx.Err()
	}
	done := make(chan error, 1)
	go func() {
		_, err := manager.prepare(context.Background(), "container", helperpkg.CapabilitySFTP)
		done <- err
	}()
	<-injectionStarted
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("prepare() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shared helper preparation did not stop with manager")
	}
}

func newTestHelperManager(t *testing.T, runtime runtimeClient) *helperManager {
	t.Helper()
	return newTestHelperManagerWithContext(t, context.Background(), runtime)
}

func newTestHelperManagerWithContext(t *testing.T, ctx context.Context, runtime runtimeClient) *helperManager {
	t.Helper()
	manager := newHelperManager(ctx, runtime, "/helper", "/tmp")
	manager.load = func() ([]byte, error) { return []byte("helper"), nil }
	manager.prepareTimeout = time.Second
	return manager
}
