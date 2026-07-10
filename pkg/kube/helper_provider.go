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

// HelperHandle is an acquired helper binary that is ready to execute in the
// target container.
type HelperHandle interface {
	// Command returns an argv that executes the acquired helper with args.
	Command(args ...string) []string
	// Release frees resources owned by this handle. Implementations must make
	// Release idempotent; callers may invoke it from multiple cleanup paths.
	// Callers may ignore the returned error when release failure should not
	// affect the operation result.
	Release(ctx context.Context) error
}

// HelperProvider acquires a kube-ssh-helper handle for the target container.
type HelperProvider interface {
	Acquire(ctx context.Context, tgt *target.Target, capability string) (HelperHandle, error)
}

// HelperCacheInvalidator is implemented by helper providers that keep
// target-scoped helper state and can drop it on demand.
type HelperCacheInvalidator interface {
	Invalidate(tgt *target.Target)
}

func (b *Backend) acquireHelper(ctx context.Context, tgt *target.Target, capability string) (HelperHandle, error) {
	start := time.Now()
	result := metrics.ResultSuccess
	recorder := b.metrics
	if recorder == nil {
		recorder = metrics.NopRecorder{}
	}
	defer func() {
		recorder.HelperAcquireFinished(capability, result, time.Since(start))
	}()
	if b.helperProvider == nil {
		result = metrics.ResultError
		return nil, status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper path is required for %s", capability)
	}
	handle, err := b.helperProvider.Acquire(ctx, tgt, capability)
	if err != nil {
		result = metrics.ResultError
		return nil, err
	}
	recorder.HelperAcquired(capability)
	return &metricsHelperHandle{
		next:       handle,
		recorder:   recorder,
		capability: capability,
		acquiredAt: time.Now(),
	}, nil
}

type metricsHelperHandle struct {
	next       HelperHandle
	recorder   metrics.Recorder
	capability string
	acquiredAt time.Time
	released   atomic.Bool
}

func (h *metricsHelperHandle) Command(args ...string) []string {
	return h.next.Command(args...)
}

func (h *metricsHelperHandle) Release(ctx context.Context) error {
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
// helper provider supports target-scoped invalidation.
func (b *Backend) InvalidateHelper(tgt *target.Target) {
	invalidator, ok := b.helperProvider.(HelperCacheInvalidator)
	if !ok {
		return
	}
	invalidator.Invalidate(tgt)
}

func ValidateHelperHealth(health helperpkg.Health, capability string) error {
	if health.Protocol != helperpkg.ProtocolVersion {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper protocol %q is not supported; want %q", health.Protocol, helperpkg.ProtocolVersion)
	}
	if !hasHelperCapability(health, helperpkg.CapabilityHealth) {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper does not advertise required capability %q", helperpkg.CapabilityHealth)
	}
	if capability != "" && !hasHelperCapability(health, capability) {
		return status.Errorf(status.ReasonHelperUnavailable, http.StatusServiceUnavailable, "helper does not advertise required capability %q", capability)
	}
	return nil
}

func hasHelperCapability(health helperpkg.Health, capability string) bool {
	return slices.Contains(health.Capabilities, capability)
}
