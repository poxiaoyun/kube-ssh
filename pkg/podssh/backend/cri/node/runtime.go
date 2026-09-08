package node

import (
	"context"
	"fmt"
	"net/url"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// runtimeClient is the subset of CRI v1 used by the node data plane. Keeping this
// interface local makes target resolution and streaming independently testable.
type runtimeClient interface {
	// Version reports the runtime and supported CRI API versions.
	Version(ctx context.Context, request *runtimeapi.VersionRequest, options ...grpc.CallOption) (*runtimeapi.VersionResponse, error)
	// Status reports runtime and network readiness.
	Status(ctx context.Context, request *runtimeapi.StatusRequest, options ...grpc.CallOption) (*runtimeapi.StatusResponse, error)

	// ListPodSandbox returns sandboxes matching the requested filter.
	ListPodSandbox(ctx context.Context, request *runtimeapi.ListPodSandboxRequest, options ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error)
	// ListContainers returns containers matching the requested filter.
	ListContainers(ctx context.Context, request *runtimeapi.ListContainersRequest, options ...grpc.CallOption) (*runtimeapi.ListContainersResponse, error)

	// Exec prepares the streaming URL for executing a container command.
	Exec(ctx context.Context, request *runtimeapi.ExecRequest, options ...grpc.CallOption) (*runtimeapi.ExecResponse, error)
	// ExecSync runs a container command and returns its output and exit code.
	ExecSync(ctx context.Context, request *runtimeapi.ExecSyncRequest, options ...grpc.CallOption) (*runtimeapi.ExecSyncResponse, error)
	// PortForward prepares the streaming URL for ports in a Pod sandbox.
	PortForward(ctx context.Context, request *runtimeapi.PortForwardRequest, options ...grpc.CallOption) (*runtimeapi.PortForwardResponse, error)
}

type podIdentity struct {
	Namespace string
	Name      string
	UID       string
	Container string
}

type resolvedTarget struct {
	SandboxID   string
	ContainerID string
}

func resolveRuntimeTarget(ctx context.Context, runtime runtimeClient, identity podIdentity, needContainer bool) (resolvedTarget, error) {
	state := runtimeapi.PodSandboxState_SANDBOX_READY
	sandboxes, err := runtime.ListPodSandbox(ctx, &runtimeapi.ListPodSandboxRequest{
		Filter: &runtimeapi.PodSandboxFilter{State: &runtimeapi.PodSandboxStateValue{State: state}},
	})
	if err != nil {
		return resolvedTarget{}, fmt.Errorf("list CRI pod sandboxes: %w", err)
	}
	matches := make([]*runtimeapi.PodSandbox, 0, 1)
	for _, sandbox := range sandboxes.Items {
		metadata := sandbox.Metadata
		if metadata != nil && sandbox.State == runtimeapi.PodSandboxState_SANDBOX_READY && metadata.Uid == identity.UID && metadata.Namespace == identity.Namespace && metadata.Name == identity.Name {
			matches = append(matches, sandbox)
		}
	}
	if len(matches) == 0 {
		return resolvedTarget{}, fmt.Errorf("ready pod sandbox %s/%s uid %s was not found on this node", identity.Namespace, identity.Name, identity.UID)
	}
	if len(matches) > 1 {
		return resolvedTarget{}, fmt.Errorf("multiple ready pod sandboxes matched %s/%s uid %s", identity.Namespace, identity.Name, identity.UID)
	}
	result := resolvedTarget{SandboxID: matches[0].Id}
	if !needContainer {
		return result, nil
	}
	running := runtimeapi.ContainerState_CONTAINER_RUNNING
	containers, err := runtime.ListContainers(ctx, &runtimeapi.ListContainersRequest{
		Filter: &runtimeapi.ContainerFilter{
			PodSandboxId: result.SandboxID,
			State:        &runtimeapi.ContainerStateValue{State: running},
		},
	})
	if err != nil {
		return resolvedTarget{}, fmt.Errorf("list CRI containers: %w", err)
	}
	for _, container := range containers.Containers {
		if container.State == runtimeapi.ContainerState_CONTAINER_RUNNING && container.Metadata != nil && container.Metadata.Name == identity.Container {
			if result.ContainerID != "" {
				return resolvedTarget{}, fmt.Errorf("multiple running containers named %q matched pod uid %s", identity.Container, identity.UID)
			}
			result.ContainerID = container.Id
		}
	}
	if result.ContainerID == "" {
		return resolvedTarget{}, fmt.Errorf("running container %q was not found in pod uid %s", identity.Container, identity.UID)
	}
	return result, nil
}

func parseStreamingURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse CRI streaming URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("CRI streaming URL uses unsupported scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("CRI streaming URL has no host")
	}
	return u, nil
}
