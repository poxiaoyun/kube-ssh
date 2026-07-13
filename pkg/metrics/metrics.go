package metrics

import (
	"net/http"
	"time"
)

// Recorder receives low-cardinality observations from kube-ssh.
//
// Implementations must not use user, namespace, pod, container, command, or
// target path as metric labels. Those values belong in audit logs, not metrics.
type Recorder interface {
	AuditDelivery(result string)
	AuthAttempt(credential, result string)
	ConnectionOpened(method string)
	ConnectionClosed(method string)
	OperationStarted(kind, capability string)
	OperationFinished(kind, capability, result string, duration time.Duration)
	BackendOperationFinished(operation, result string, duration time.Duration)
	StreamOpened(kind string)
	StreamClosed(kind string)
	StreamBytes(kind, direction string, n int64)
	HelperAcquired(capability string)
	HelperAcquireFinished(capability, result string, duration time.Duration)
	HelperReleased(capability, result string, duration time.Duration)
	AccessPolicyCacheSyncFinished(resource, result string, duration time.Duration)
	AccessPolicyObjects(resource string, count int)
	AccessPolicyAuthFinished(credential, result string, duration time.Duration)
	AccessPolicyResolveFinished(result string, duration time.Duration)
	AccessPolicyAuthorizeFinished(capability, decision, result string, duration time.Duration)
}

type HandlerProvider interface {
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
