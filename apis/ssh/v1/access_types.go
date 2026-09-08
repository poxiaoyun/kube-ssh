package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Access declares how kube-ssh users may access a selected set of Pods or
// external endpoints.
//
// The resource is intentionally workload-local: application owners can ship it
// beside a Deployment, StatefulSet, Pod, or service-like manifest.
// Authentication material may contain plaintext passwords; cluster RBAC around
// this CRD is therefore a security boundary.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +genclient
// +resourceName=accesses
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=acc
// +kubebuilder:printcolumn:name="Valid",type=string,JSONPath=".status.conditions[?(@.type=='Valid')].status"
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
type AccessSpec struct {
	// GatewayClassName selects the kube-ssh gateway class that owns this Access.
	// Omitted selects the default (classless) gateway. Gateways only process
	// Access objects whose class exactly matches their configured class.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	GatewayClassName *string `json:"gatewayClassName,omitempty"`

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
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	Endpoints []AccessEndpoint `json:"endpoints,omitempty"`

	// Strategy describes how kube-ssh picks one target when multiple Pods or
	// endpoints are available.
	Strategy *AccessStrategy `json:"strategy,omitempty"`

	// Session defines defaults used for shell and exec sessions.
	Session *SessionPolicy `json:"session,omitempty"`

	// Containers limits the regular Pod containers exposed by this Access.
	// Omitted or empty inherits the gateway default container policy. A
	// credential may further narrow this list, but cannot expand it. Entries are
	// exact names or patterns in which "*" matches any sequence of characters.
	//
	// +listType=set
	Containers []string `json:"containers,omitempty"`

	// Credentials are accepted authentication material for this access object.
	// They prove possession of a password, key, or referenced secret, but
	// only produce the local user identity declared on the same credential entry.
	//
	// +listType=map
	// +listMapKey=username
	Credentials []AccessCredential `json:"credentials,omitempty"`
}

// AccessType selects the SSH connection implementation.
//
// +kubebuilder:validation:Enum=Pod;External
type AccessType string

const (
	AccessTypePod      AccessType = "Pod"
	AccessTypeExternal AccessType = "External"
)

// AccessEndpoint is one explicit external endpoint.
//
// +kubebuilder:validation:XValidation:rule="((has(self.privateKeys) || has(self.privateKeysFrom)) ? 1 : 0) + ((has(self.passwords) || has(self.passwordsFrom)) ? 1 : 0) == 1",message="configure either privateKeys/privateKeysFrom or passwords/passwordsFrom"
// +kubebuilder:validation:XValidation:rule="!self.insecureSkipVerification || (!has(self.publicKeys) && !has(self.publicKeysFrom))",message="insecureSkipVerification is mutually exclusive with public keys"
// +kubebuilder:validation:XValidation:rule="self.insecureSkipVerification || has(self.publicKeys) || has(self.publicKeysFrom)",message="public keys are required unless insecureSkipVerification is true"
type AccessEndpoint struct {
	// Name is a stable endpoint name used for status, audit, and affinity.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Address is an IP address or DNS name.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Address string `json:"address"`

	// Port is the SSH server port. Omitted means 22.
	//
	// +kubebuilder:default=22
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port,omitempty"`

	// Username is the upstream SSH login username.
	//
	// +kubebuilder:validation:MinLength=1
	Username string `json:"username"`

	// Weight is the relative endpoint weight. Values less than 1 should be
	// rejected by validation. Omitted means 1.
	//
	// +kubebuilder:validation:Minimum=1
	Weight *int32 `json:"weight,omitempty"`

	// PrivateKeys are unencrypted SSH private keys tried in order.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	PrivateKeys []string `json:"privateKeys,omitempty"`

	// PrivateKeysFrom references unencrypted SSH private keys tried after inline
	// PrivateKeys.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	PrivateKeysFrom []LocalSecretKeyRef `json:"privateKeysFrom,omitempty"`

	// Passwords are exact inline passwords tried against the upstream SSH server.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Passwords []string `json:"passwords,omitempty"`

	// PasswordsFrom references exact passwords tried after inline Passwords.
	//
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	PasswordsFrom []LocalSecretKeyRef `json:"passwordsFrom,omitempty"`

	// PublicKeys are pinned OpenSSH public-key lines accepted from the upstream.
	//
	// +kubebuilder:validation:MinItems=1
	// +listType=set
	PublicKeys []string `json:"publicKeys,omitempty"`

	// PublicKeysFrom references Secret keys containing one or more newline-delimited
	// OpenSSH public-key lines.
	//
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	PublicKeysFrom []LocalSecretKeyRef `json:"publicKeysFrom,omitempty"`

	// InsecureSkipVerification accepts any upstream host key. It must be opted in
	// explicitly and cannot be combined with pinned keys.
	//
	// +kubebuilder:default=false
	InsecureSkipVerification bool `json:"insecureSkipVerification,omitempty"`
}

// AccessStrategy describes how to pick one target from selected Pods or
// endpoints.
type AccessStrategy struct {
	// Type defaults to Random.
	//
	// +kubebuilder:default=Random
	Type AccessStrategyType `json:"type,omitempty"`

	// Weights assigns relative weights to matching Pods. Algorithms that support
	// weighting should use these values when choosing between targets. Pods
	// that match no weight entry use the default weight of 1.
	//
	// +listType=atomic
	Weights []AccessStrategyWeight `json:"weights,omitempty"`

	// SessionAffinity reuses the last selected target for the same affinity key
	// when possible.
	SessionAffinity *AccessSessionAffinity `json:"sessionAffinity,omitempty"`
}

// AccessStrategyType is the multi-target selection algorithm.
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

// AccessStrategyWeight assigns a relative weight to matching Pods.
type AccessStrategyWeight struct {
	// Selector matches Pods within the parent Access selector.
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
// target.
type AccessSessionAffinity struct {
	// Type chooses the affinity key. SourceIP uses the remote address observed
	// by the kube-ssh gateway; in Kubernetes this may be a node, load balancer,
	// proxy, or NAT address instead of the real SSH client IP, so it should be
	// treated as a best-effort hint only.
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

// SessionPolicy defines session-level defaults and limits.
type SessionPolicy struct {
	// DefaultShell is used for shell sessions and as the shell for "sh -c" style
	// exec requests. When empty, kube-ssh should use its server default.
	DefaultShell string `json:"defaultShell,omitempty"`

	// EnvAllowlist controls SSH client env requests for this access object.
	// When omitted, kube-ssh uses the server-wide allowlist. When set to an
	// empty list, no client env requests are allowed. Values are exact env names,
	// prefix patterns ending in "*", or "*" for all names. This field can only
	// narrow the server-wide allowlist.
	//
	// +listType=set
	EnvAllowlist []string `json:"envAllowlist,omitempty"`

	// IdleTimeout is the maximum idle period for SSH connections using this
	// Access. Client keepalives and SSH traffic may count as activity. This
	// field is bounded by the gateway's idle-timeout limit.
	//
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=duration
	IdleTimeout *metav1.Duration `json:"idleTimeout,omitempty"`

	// MaxDuration is the maximum lifetime for SSH connections using this Access.
	// When exceeded, kube-ssh closes the whole SSH connection, including shell,
	// exec, sftp, local-forward, and remote-forward channels. This field can
	// not exceed the gateway's maximum-duration limit.
	//
	// +kubebuilder:validation:Type=string
	// +kubebuilder:validation:Format=duration
	MaxDuration *metav1.Duration `json:"maxDuration,omitempty"`
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
// exactly one user. Password tokens and public keys may be reused by different
// Access objects because the SSH target identifies the Access before credentials
// are checked. Within one Access, credential usernames must be unique and the
// same material must not map to different credential identities.
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

	// Passwords are opaque tokens submitted through the SSH password method.
	// kube-ssh does not parse these values as username/password pairs.
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

	// Containers limits this credential to named regular Pod containers. Omitted
	// or empty inherits the Access container policy. Entries are exact names or
	// patterns in which "*" matches any sequence of characters.
	//
	// +listType=set
	Containers []string `json:"containers,omitempty"`

	// Capabilities limits what this credential can do on the target.
	Capabilities CapabilityPolicy `json:"capabilities,omitempty"`
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
// Omitted or empty allowlists inherit the gateway defaults. Set Allow to
// override the default capability list for this credential, subject to the
// gateway's hard limits. Set the corresponding forwarding policy to override
// the default destinations or binds within those limits.
type CapabilityPolicy struct {
	// Allow is the list of SSH capabilities allowed for this credential. Omitted
	// or empty inherits the gateway defaults, which exclude ssh_extension unless
	// it is explicitly enabled.
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
// +kubebuilder:validation:Enum=shell;exec;scp;sftp;local_forward;remote_forward;agent_forward;ssh_extension
type Capability string

const (
	CapabilityShell         Capability = "shell"
	CapabilityExec          Capability = "exec"
	CapabilitySCP           Capability = "scp"
	CapabilitySFTP          Capability = "sftp"
	CapabilityLocalForward  Capability = "local_forward"
	CapabilityRemoteForward Capability = "remote_forward"
	CapabilityAgentForward  Capability = "agent_forward"
	CapabilitySSHExtension  Capability = "ssh_extension"
)

// LocalForwardPolicy restricts direct-tcpip requests.
type LocalForwardPolicy struct {
	// AllowDestinations are allowed host:port expressions. Examples:
	//   - "127.0.0.1:8080"
	//   - "*:8080"
	//   - "*:*"
	//
	// An asterisk matches any sequence of characters; "*" allows every value.
	//
	// Omitted or empty inherits the gateway's allowed destinations.
	//
	// +listType=set
	AllowDestinations []string `json:"allowDestinations,omitempty"`
}

// RemoteForwardPolicy restricts tcpip-forward requests.
type RemoteForwardPolicy struct {
	// AllowBinds are allowed bind expressions. Examples:
	//   - "127.0.0.1:10022"
	//   - "127.0.0.1:*"
	//   - "*:10022"
	//
	// An asterisk matches any sequence of characters; "*" allows every value.
	//
	// Omitted or empty inherits the gateway's allowed binds.
	//
	// +listType=set
	AllowBinds []string `json:"allowBinds,omitempty"`
}

// AccessStatus is observed state for an Access.
type AccessStatus struct {
	// ObservedGeneration is the latest metadata.generation processed by a
	// controller or informer-backed validator.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Endpoints are gateway-advertised SSH connection targets for this Access.
	// Address values use host:port form and Username contains the Access locator.
	//
	// +listType=map
	// +listMapKey=address
	Endpoints []AccessStatusEndpoint `json:"endpoints,omitempty"`

	// Conditions describe validation and readiness of this access object.
	// Known condition types include Valid and Ready.
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// AccessStatusEndpoint is one address advertised by the owning gateway.
type AccessStatusEndpoint struct {
	// Address is a DNS name or IP plus port, or the platform Node address
	// placeholder {NodeIP} plus port. IPv6 addresses must be bracketed.
	Address string `json:"address"`

	// Username is the SSH target locator for this Access.
	Username string `json:"username"`
}

const (
	// AccessConditionValid reports whether the Access spec and referenced local
	// credential material are usable by kube-ssh.
	AccessConditionValid = "Valid"

	// AccessConditionReady reports whether the Access currently has at least one
	// usable target.
	AccessConditionReady = "Ready"
)

// AccessList contains a list of Access objects.
//
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
type AccessList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []Access `json:"items"`
}
