package kube

import (
	"context"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	helperpkg "xiaoshiai.cn/kube-ssh/pkg/helper"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/status"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

// helperLease is an acquired helper binary that is ready to execute in the
// target container.
type helperLease interface {
	// Command returns an argv that executes the acquired helper with args.
	Command(args ...string) []string
	// Release frees resources owned by this lease. Implementations must make
	// Release idempotent; callers may invoke it from multiple cleanup paths.
	// Callers may ignore the returned error when release failure should not
	// affect the operation result.
	Release(ctx context.Context) error
}

// helperAcquirer acquires a kube-ssh-helper lease for the target container.
type helperAcquirer interface {
	Acquire(ctx context.Context, tgt *target.Target, capability string) (helperLease, error)
}

// helperCacheInvalidator is implemented by helper acquirers that keep
// target-scoped helper state and can drop it on demand.
type helperCacheInvalidator interface {
	Invalidate(tgt *target.Target)
}

func (b *Backend) acquireHelper(ctx context.Context, tgt *target.Target, capability string) (helperLease, error) {
	start := time.Now()
	result := metrics.ResultSuccess
	recorder := b.metrics
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	defer func() {
		recorder.HelperAcquireFinished(capability, result, time.Since(start))
	}()
	if b.helperAcquirer == nil {
		result = metrics.ResultError
		return nil, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper path is required for %s", capability)
	}
	handle, err := b.helperAcquirer.Acquire(ctx, tgt, capability)
	if err != nil {
		result = metrics.ResultError
		return nil, err
	}
	recorder.HelperAcquired(capability)
	return &metricsHelperLease{
		next:       handle,
		recorder:   recorder,
		capability: capability,
		acquiredAt: time.Now(),
	}, nil
}

type metricsHelperLease struct {
	next       helperLease
	recorder   metrics.Recorder
	capability string
	acquiredAt time.Time
	released   atomic.Bool
}

func (h *metricsHelperLease) Command(args ...string) []string {
	return h.next.Command(args...)
}

func (h *metricsHelperLease) Release(ctx context.Context) error {
	err := h.next.Release(ctx)
	if h.released.CompareAndSwap(false, true) {
		result := metrics.ResultSuccess
		if err != nil {
			result = metrics.ResultError
		}
		h.recorder.HelperReleased(h.capability, result, time.Since(h.acquiredAt))
	}
	return err
}

// InvalidateHelper discards cached helper state for tgt when the configured
// helper acquirer supports target-scoped invalidation.
func (b *Backend) InvalidateHelper(tgt *target.Target) {
	invalidator, ok := b.helperAcquirer.(helperCacheInvalidator)
	if !ok {
		return
	}
	invalidator.Invalidate(tgt)
}

func validateHelperManifest(manifest, expected helperpkg.Manifest, capability string) error {
	if manifest.Version != expected.Version {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper version %q does not match %q", manifest.Version, expected.Version)
	}
	if manifest.Commit != expected.Commit {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper commit %q does not match %q", manifest.Commit, expected.Commit)
	}
	if manifest.ProtocolVersion != helperpkg.ProtocolVersion {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper protocol %q is not supported; want %q", manifest.ProtocolVersion, helperpkg.ProtocolVersion)
	}
	if capability != "" && !manifestHasCapability(manifest, capability) {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper does not advertise required capability %q", capability)
	}
	return nil
}

func manifestHasCapability(manifest helperpkg.Manifest, capability string) bool {
	return slices.Contains(manifest.Capabilities, capability)
}
