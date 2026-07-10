package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Access declares how kube-ssh users may access a selected set of Pods or
// external endpoints.
//
// The resource is intentionally workload-local: application owners can ship it
// beside a Deployment, StatefulSet, Pod, or service-like manifest. Credentials
// may contain plaintext passwords; cluster RBAC around this CRD is therefore a
// security boundary.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=acc
// +kubebuilder:printcolumn:name="SelectedBackend",type=string,JSONPath=".status.selectedBackend"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type=='Ready')].status"
type Access struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AccessSpec   `json:"spec,omitempty"`
	Status AccessStatus `json:"status,omitempty"`
}

// AccessSpec is the desired access surface.
//
// +kubebuilder:validation:XValidation:rule="!has(self.type) || self.type != 'Pod' || (has(self.selector) && size(self.selector) > 0)",message="non-empty selector is required when type is Pod"
// +kubebuilder:validation:XValidation:rule="self.type != 'External' || has(self.endpoints)",message="endpoints is required when type is External"
// +kubebuilder:validation:XValidation:rule="!(has(self.selector) && has(self.endpoints))",message="selector and endpoints are mutually exclusive"
type AccessSpec struct {
	// Type determines what this Access selects. Defaults to Pod.
	//
	// +kubebuilder:default=Pod
	Type AccessType `json:"type,omitempty"`

	// Selector directly selects candidate Pods in the same namespace when Type
	// is Pod, using the same simple equality-based shape as
	// corev1.ServiceSpec.Selector.
	//
	// Example:
	//   selector:
	//     app: notebook
	//     component: api
	//
	// +mapType=atomic
	// +kubebuilder:validation:MinProperties=1
	Selector map[string]string `json:"selector,omitempty"`

	// Endpoints are explicit external endpoints used when Type is External.
	//
	// +listType=atomic
	Endpoints []AccessEndpoint `json:"endpoints,omitempty"`

	// Strategy describes how kube-ssh picks one backend when multiple Pods or
	// endpoints are available.
	Strategy *AccessStrategy `json:"strategy,omitempty"`

	// Session defines defaults used for shell and exec sessions.
	Session *SessionPolicy `json:"session,omitempty"`

	// Credentials are accepted authentication material for this access object.
	// They prove possession of a password, key, or referenced secret, but
	// only produce the local user identity declared on the same credential entry.
	//
	// +listType=map
	// +listMapKey=username
	Credentials []AccessCredential `json:"credentials,omitempty"`
}

// AccessType is the backend selection mode.
//
// +kubebuilder:validation:Enum=Pod;External
type AccessType string

const (
	AccessTypePod      AccessType = "Pod"
	AccessTypeExternal AccessType = "External"
)

// AccessEndpoint is one explicit external endpoint.
type AccessEndpoint struct {
	// Name is a stable endpoint name used for status, audit, and affinity.
	Name string `json:"name,omitempty"`

	// Address is an IP address or DNS name.
	//
	// +kubebuilder:validation:MinLength=1
	Address string `json:"address"`

	// Username is the optional backend login username for this external endpoint.
	Username string `json:"username,omitempty"`

	// Weight is the relative endpoint weight. Values less than 1 should be
	// rejected by validation. Omitted means 1.
	//
	// +kubebuilder:validation:Minimum=1
	Weight *int32 `json:"weight,omitempty"`

	// Labels are endpoint-local labels used by strategy weights, policy, or
	// audit. They do not select Kubernetes objects.
	//
	// +mapType=atomic
	Labels map[string]string `json:"labels,omitempty"`

	// Credential provides credentials needed by an external backend.
	Credential `json:",inline"`

	// Params carries backend-specific endpoint configuration. Values are strings
	// so the CRD schema remains simple and forward-compatible.
	//
	// +mapType=atomic
	Params map[string]string `json:"params,omitempty"`
}

// AccessStrategy describes how to pick one backend from selected Pods or
// endpoints.
type AccessStrategy struct {
	// Type defaults to Random.
	//
	// +kubebuilder:default=Random
	Type AccessStrategyType `json:"type,omitempty"`

	// Weights assigns relative weights to matching Pods or endpoints. Algorithms
	// that support weighting should use these values when choosing between
	// backends. Backends that match no weight entry use the default weight of 1.
	//
	// +listType=atomic
	Weights []AccessStrategyWeight `json:"weights,omitempty"`

	// SessionAffinity reuses the last selected backend for the same affinity key
	// when possible.
	SessionAffinity *AccessSessionAffinity `json:"sessionAffinity,omitempty"`
}

// AccessStrategyType is the multi-backend selection algorithm.
//
// +kubebuilder:validation:Enum=Random;RoundRobin;LeastConnections;Newest;Oldest
type AccessStrategyType string

const (
	AccessStrategyTypeRandom           AccessStrategyType = "Random"
	AccessStrategyTypeRoundRobin       AccessStrategyType = "RoundRobin"
	AccessStrategyTypeLeastConnections AccessStrategyType = "LeastConnections"
	AccessStrategyTypeNewest           AccessStrategyType = "Newest"
	AccessStrategyTypeOldest           AccessStrategyType = "Oldest"
)

// AccessStrategyWeight assigns a relative weight to matching Pods or endpoints.
type AccessStrategyWeight struct {
	// Selector matches Pods within the parent Access selector, or endpoint
	// labels in External mode.
	//
	// +mapType=atomic
	Selector map[string]string `json:"selector,omitempty"`

	// Weight is the relative weight. Values less than 1 should be rejected by
	// validation.
	//
	// +kubebuilder:validation:Minimum=1
	Weight int32 `json:"weight"`
}

// AccessSessionAffinity describes the key used to reuse a previously selected
// backend.
type AccessSessionAffinity struct {
	// Type chooses the affinity key.
	Type AccessSessionAffinityType `json:"type,omitempty"`

	// TimeoutSeconds is the maximum age of an affinity entry. Omitted means the
	// implementation default.
	//
	// +kubebuilder:validation:Minimum=1
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
}

// AccessSessionAffinityType is the key used for last-connection reuse.
//
// +kubebuilder:validation:Enum=User;Credential;SourceIP;SSHUser
type AccessSessionAffinityType string

const (
	AccessSessionAffinityTypeUser       AccessSessionAffinityType = "User"
	AccessSessionAffinityTypeCredential AccessSessionAffinityType = "Credential"
	AccessSessionAffinityTypeSourceIP   AccessSessionAffinityType = "SourceIP"
	AccessSessionAffinityTypeSSHUser    AccessSessionAffinityType = "SSHUser"
)

// SessionPolicy defines session-level defaults.
type SessionPolicy struct {
	// DefaultShell is used for shell sessions and as the shell for "sh -c" style
	// exec requests. When empty, kube-ssh should use its server default.
	DefaultShell string `json:"defaultShell,omitempty"`

	// EnvAllowlist controls SSH env requests for this access object.
	//
	// +listType=set
	EnvAllowlist []string `json:"envAllowlist,omitempty"`
}

// AccessCredential is one accepted credential rule for this access object.
//
// Credential material may be provided directly or by reference. Direct
// password tokens and keys are intentionally supported to keep workload-local
// manifests simple; cluster RBAC around this CRD is therefore a security
// boundary.
//
// A credential proves possession of authentication material and produces the
// local user identity declared on the same entry. One credential entry maps to
// exactly one user. Password tokens and public keys are expected to be unique
// across visible Access objects; duplicate material is a configuration conflict
// and should be resolved by creation-time fallback by the implementation.
type AccessCredential struct {
	// Username is the local username produced by this credential and the stable
	// identifier for this credential entry.
	//
	// +kubebuilder:validation:MinLength=1
	Username string `json:"username"`

	// UID is an optional stable external or human-readable identifier for the
	// local user.
	UID string `json:"uid,omitempty"`

	// Groups are local kube-ssh groups attached to this user.
	//
	// +listType=set
	Groups []string `json:"groups,omitempty"`

	// Extra carries provider-specific identity attributes.
	//
	// +mapType=atomic
	Extra map[string][]string `json:"extra,omitempty"`

	// Credential provides credential material directly on this access credential.
	Credential `json:",inline"`

	// Capabilities limits what this credential can do on the target.
	Capabilities CapabilityPolicy `json:"capabilities,omitempty"`
}

// Credential provides credential material directly or from referenced
// objects.
type Credential struct {
	// Passwords are opaque tokens submitted through the SSH password method, or
	// password material for an external endpoint. kube-ssh does not parse these
	// values as username/password pairs.
	//
	// +listType=set
	Passwords []string `json:"passwords,omitempty"`

	// PasswordsFrom references Secret keys containing password-token values. Each
	// key may contain one token, or multiple newline-delimited tokens.
	//
	// +listType=atomic
	PasswordsFrom []LocalSecretKeyRef `json:"passwordsFrom,omitempty"`

	// PublicKeys are OpenSSH authorized_keys lines accepted as possession proof
	// for this access object.
	//
	// +listType=set
	PublicKeys []string `json:"publicKeys,omitempty"`

	// PublicKeysFrom references Secret keys containing OpenSSH authorized_keys
	// lines. Each key may contain one key, or multiple newline-delimited keys.
	//
	// +listType=atomic
	PublicKeysFrom []LocalSecretKeyRef `json:"publicKeysFrom,omitempty"`

	// PrivateKey is optional client private key material for public-key
	// authentication to an external SSH endpoint. It is not used for
	// authenticating inbound kube-ssh users.
	PrivateKey string `json:"privateKey,omitempty"`

	// PrivateKeyFrom references a Secret key containing private key material.
	PrivateKeyFrom *LocalSecretKeyRef `json:"privateKeyFrom,omitempty"`
}

// LocalSecretKeyRef references one key in a Secret in the same namespace as the
// Access object.
type LocalSecretKeyRef struct {
	// Name is the referenced same-namespace Secret name.
	//
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Key is the key within the referenced Secret.
	//
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`
}

// CapabilityPolicy limits SSH operations for a credential.
//
// Omitted fields mean no additional restriction from this access object. The
// default is to allow every kube-ssh capability. Set Allow to switch this
// credential into whitelist mode. To restrict forwarding, set the corresponding
// forwarding policy.
type CapabilityPolicy struct {
	// Allow is the list of SSH capabilities allowed for this credential. Omitted
	// or empty means all capabilities are allowed by this access object.
	//
	// +listType=set
	Allow []Capability `json:"allow,omitempty"`

	// LocalForward restricts direct-tcpip forwarding when set. If omitted,
	// local forwarding is not additionally restricted by this access object.
	LocalForward *LocalForwardPolicy `json:"localForward,omitempty"`

	// RemoteForward restricts tcpip-forward when set. If omitted, remote
	// forwarding is not additionally restricted by this access object.
	RemoteForward *RemoteForwardPolicy `json:"remoteForward,omitempty"`
}

// Capability is an SSH operation type.
//
// +kubebuilder:validation:Enum=shell;exec;scp;sftp;local_forward;remote_forward
type Capability string

const (
	CapabilityShell         Capability = "shell"
	CapabilityExec          Capability = "exec"
	CapabilitySCP           Capability = "scp"
	CapabilitySFTP          Capability = "sftp"
	CapabilityLocalForward  Capability = "local_forward"
	CapabilityRemoteForward Capability = "remote_forward"
)

// LocalForwardPolicy restricts direct-tcpip requests.
type LocalForwardPolicy struct {
	// AllowPorts are destination ports allowed for Pod-local forwarding. Empty
	// means any Pod-local port is allowed.
	//
	// +listType=set
	// +kubebuilder:validation:items:Minimum=1
	// +kubebuilder:validation:items:Maximum=65535
	AllowPorts []int32 `json:"allowPorts,omitempty"`
}

// RemoteForwardPolicy restricts tcpip-forward requests.
type RemoteForwardPolicy struct {
	// AllowBinds are allowed bind expressions. Examples:
	//   - "127.0.0.1:10022"
	//   - "127.0.0.1:*"
	//   - "*:10022"
	//
	// Empty means any bind accepted by the backend is allowed.
	//
	// +listType=set
	AllowBinds []string `json:"allowBinds,omitempty"`
}

// AccessStatus is observed state for an Access.
type AccessStatus struct {
	// ObservedGeneration is the latest metadata.generation processed by a
	// controller or informer-backed validator.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// SelectedBackend is a compact human-readable summary of the last resolved
	// backend.
	SelectedBackend string `json:"selectedBackend,omitempty"`

	// Conditions describe validation and readiness of this access object.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AccessList contains a list of Access objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type AccessList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Access `json:"items"`
}
