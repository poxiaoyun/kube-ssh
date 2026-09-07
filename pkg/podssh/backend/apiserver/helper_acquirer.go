package apiserver

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh/backend"
	helperpkg "xiaoshiai.cn/kube-ssh/pkg/podssh/backend/helper"
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

func (b *Transport) acquireHelper(ctx context.Context, tgt *target.Target, capability string) (helperLease, error) {
	start := time.Now()
	result := metrics.ResultSuccess
	defer func() {
		b.metrics.HelperAcquireFinished(capability, result, time.Since(start))
	}()
	handle, err := b.helperAcquirer.Acquire(ctx, tgt, capability)
	if err != nil {
		result = metrics.ResultError
		return nil, err
	}
	b.metrics.HelperAcquired(capability)
	return &metricsHelperLease{
		next:       handle,
		recorder:   b.metrics,
		capability: capability,
		acquiredAt: time.Now(),
	}, nil
}

// ExecHelper prepares a compatible helper and runs one helper command.
func (b *Transport) ExecHelper(ctx context.Context, req backend.HelperExecRequest) (int, error) {
	helper, err := b.acquireHelper(ctx, req.Target, req.Capability)
	if err != nil {
		return 1, err
	}
	defer func() { _ = helper.Release(context.WithoutCancel(ctx)) }()

	return b.exec(ctx, backend.ExecRequest{
		Target:  req.Target,
		Command: helper.Command(req.Command...),
		Stdin:   req.Stdin,
		Stdout:  req.Stdout,
		Stderr:  req.Stderr,
	})
}

type metricsHelperLease struct {
	next       helperLease
	recorder   metrics.HelperRecorder
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

func validateHelperManifest(manifest, expected helperpkg.Manifest, capability string) error {
	if manifest.Version != expected.Version {
		return apierrors.NewServiceUnavailable(fmt.Sprintf("helper version %q does not match %q", manifest.Version, expected.Version))
	}
	if manifest.Commit != expected.Commit {
		return apierrors.NewServiceUnavailable(fmt.Sprintf("helper commit %q does not match %q", manifest.Commit, expected.Commit))
	}
	if manifest.ProtocolVersion != helperpkg.ProtocolVersion {
		return apierrors.NewServiceUnavailable(fmt.Sprintf("helper protocol %q is not supported; want %q", manifest.ProtocolVersion, helperpkg.ProtocolVersion))
	}
	if capability != "" && !manifestHasCapability(manifest, capability) {
		return apierrors.NewServiceUnavailable(fmt.Sprintf("helper does not advertise required capability %q", capability))
	}
	return nil
}

func manifestHasCapability(manifest helperpkg.Manifest, capability string) bool {
	return slices.Contains(manifest.Capabilities, capability)
}
