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
	AuthAttempt(credential, result string)
	ConnectionOpened(method string)
	ConnectionClosed(method string)
	OperationStarted(kind, capability string)
	OperationFinished(kind, capability, result string, duration time.Duration)
	BackendOperationFinished(operation, result string, duration time.Duration)
	HelperAcquireFinished(capability, result string, duration time.Duration)
}

type HandlerProvider interface {
	Handler() http.Handler
}

// NopRecorder drops all observations.
type NopRecorder struct{}

func (NopRecorder) AuthAttempt(string, string)                              {}
func (NopRecorder) ConnectionOpened(string)                                 {}
func (NopRecorder) ConnectionClosed(string)                                 {}
func (NopRecorder) OperationStarted(string, string)                         {}
func (NopRecorder) OperationFinished(string, string, string, time.Duration) {}
func (NopRecorder) BackendOperationFinished(string, string, time.Duration)  {}
func (NopRecorder) HelperAcquireFinished(string, string, time.Duration)     {}

const (
	ResultSuccess     = "success"
	ResultRejected    = "rejected"
	ResultDenied      = "denied"
	ResultError       = "error"
	ResultCanceled    = "canceled"
	ResultNonzeroExit = "nonzero_exit"
	ResultDuplicate   = "duplicate"
	ResultUnknown     = "unknown"
)

const (
	CredentialPassword  = "password"
	CredentialPublicKey = "publickey"
)

func labelValue(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
