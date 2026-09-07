// Package metrics defines low-cardinality observation seams for kube-ssh.
package metrics

import (
	"net/http"
	"time"
)

// AuditRecorder receives audit delivery outcomes.
type AuditRecorder interface {
	// AuditDelivery records one audit delivery outcome.
	AuditDelivery(result string)
}

// AuthenticationRecorder receives SSH authentication and connection observations.
type AuthenticationRecorder interface {
	// AuthAttempt records one credential verification outcome.
	AuthAttempt(credential, result string)
	// ConnectionOpened records one accepted SSH connection.
	ConnectionOpened(method string)
	// ConnectionClosed records one closed SSH connection.
	ConnectionClosed(method string)
}

// OperationRecorder receives protocol operation observations.
type OperationRecorder interface {
	// OperationStarted records an operation entering its lifecycle.
	OperationStarted(kind, capability string)
	// OperationFinished records an operation outcome and duration.
	OperationFinished(kind, capability, result string, duration time.Duration)
}

// BackendRecorder receives Pod backend operation observations.
type BackendRecorder interface {
	// BackendOperationFinished records a Pod backend outcome and duration.
	BackendOperationFinished(operation, result string, duration time.Duration)
}

// StreamRecorder receives proxied stream lifecycle and byte observations.
type StreamRecorder interface {
	// StreamOpened records a newly proxied stream.
	StreamOpened(kind string)
	// StreamClosed records a closed proxied stream.
	StreamClosed(kind string)
	// StreamBytes records bytes copied in one direction.
	StreamBytes(kind, direction string, n int64)
}

// HelperRecorder receives helper acquisition and release observations.
type HelperRecorder interface {
	// HelperAcquired records a helper becoming active.
	HelperAcquired(capability string)
	// HelperAcquireFinished records helper acquisition completion.
	HelperAcquireFinished(capability, result string, duration time.Duration)
	// HelperReleased records helper release completion and usage duration.
	HelperReleased(capability, result string, duration time.Duration)
}

// AccessPolicyRecorder receives Access policy runtime observations.
type AccessPolicyRecorder interface {
	// AccessPolicyCacheSyncFinished records informer cache synchronization.
	AccessPolicyCacheSyncFinished(resource, result string, duration time.Duration)
	// AccessPolicyObjects records the current informer object count.
	AccessPolicyObjects(resource string, count int)
	// AccessPolicyAuthFinished records Access credential evaluation.
	AccessPolicyAuthFinished(credential, result string, duration time.Duration)
	// AccessPolicyResolveFinished records Access target resolution.
	AccessPolicyResolveFinished(result string, duration time.Duration)
	// AccessPolicyAuthorizeFinished records Access authorization evaluation.
	AccessPolicyAuthorizeFinished(capability, decision, result string, duration time.Duration)
}

// Recorder combines every low-cardinality observation seam used by kube-ssh.
// Implementations must not use user, namespace, Pod, container, command, or
// target path as labels. Those values belong in audit events.
type Recorder interface {
	AuditRecorder
	AuthenticationRecorder
	OperationRecorder
	BackendRecorder
	StreamRecorder
	HelperRecorder
	AccessPolicyRecorder
}

type HandlerProvider interface {
	// Handler returns the HTTP metrics handler.
	Handler() http.Handler
}

// NopRecorder drops all observations.
type NopRecorder struct{}

func (NopRecorder) AuditDelivery(string)                                    {}
func (NopRecorder) AuthAttempt(string, string)                              {}
func (NopRecorder) ConnectionOpened(string)                                 {}
func (NopRecorder) ConnectionClosed(string)                                 {}
func (NopRecorder) OperationStarted(string, string)                         {}
func (NopRecorder) OperationFinished(string, string, string, time.Duration) {}
func (NopRecorder) BackendOperationFinished(string, string, time.Duration)  {}
func (NopRecorder) StreamOpened(string)                                     {}
func (NopRecorder) StreamClosed(string)                                     {}
func (NopRecorder) StreamBytes(string, string, int64)                       {}
func (NopRecorder) HelperAcquired(string)                                   {}
func (NopRecorder) HelperAcquireFinished(string, string, time.Duration)     {}
func (NopRecorder) HelperReleased(string, string, time.Duration)            {}
func (NopRecorder) AccessPolicyCacheSyncFinished(string, string, time.Duration) {
}
func (NopRecorder) AccessPolicyObjects(string, int) {}
func (NopRecorder) AccessPolicyAuthFinished(string, string, time.Duration) {
}
func (NopRecorder) AccessPolicyResolveFinished(string, time.Duration) {
}
func (NopRecorder) AccessPolicyAuthorizeFinished(string, string, string, time.Duration) {
}

const (
	ResultSuccess     = "success"
	ResultRejected    = "rejected"
	ResultDenied      = "denied"
	ResultError       = "error"
	ResultCanceled    = "canceled"
	ResultNonzeroExit = "nonzero_exit"
	ResultDuplicate   = "duplicate"
	ResultNotProvided = "not_provided"
	ResultUnknown     = "unknown"
)

const (
	CredentialPassword  = "password"
	CredentialPublicKey = "publickey"
)

const (
	StreamKindDirectTCPIP   = "direct_tcpip"
	StreamKindRemoteForward = "remote_forward"
	StreamKindAgentForward  = "agent_forward"

	StreamDirectionClientToBackend = "client_to_backend"
	StreamDirectionBackendToClient = "backend_to_client"
)

func labelValue(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
