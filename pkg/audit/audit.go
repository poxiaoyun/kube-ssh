package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const SchemaVersion = "1.0"

// Event is the stable, versioned audit envelope. Fields remain available for
// operation-specific attributes that do not warrant a top-level schema field.
type Event struct {
	SchemaVersion string            `json:"schema_version"`
	ID            string            `json:"id"`
	Time          time.Time         `json:"time"`
	Type          string            `json:"type"`
	Correlation   Correlation       `json:"correlation"`
	Connection    *Connection       `json:"connection,omitempty"`
	Actor         *Actor            `json:"actor,omitempty"`
	Access        *AccessBinding    `json:"access,omitempty"`
	Target        *Target           `json:"target,omitempty"`
	Operation     *Operation        `json:"operation,omitempty"`
	Authorization *Authorization    `json:"authorization,omitempty"`
	Outcome       *Outcome          `json:"outcome,omitempty"`
	Fields        map[string]string `json:"fields,omitempty"`
}

type Correlation struct {
	ConnectionID string `json:"connection_id,omitempty"`
	OperationID  string `json:"operation_id,omitempty"`
}

type Connection struct {
	SSHUsername   string `json:"ssh_username,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	LocalAddress  string `json:"local_address,omitempty"`
	ClientVersion string `json:"client_version,omitempty"`
	ServerVersion string `json:"server_version,omitempty"`
}

type Actor struct {
	ID                   string   `json:"id,omitempty"`
	Name                 string   `json:"name,omitempty"`
	Email                string   `json:"email,omitempty"`
	EmailVerified        bool     `json:"email_verified,omitempty"`
	Groups               []string `json:"groups,omitempty"`
	AuthenticationMethod string   `json:"authentication_method,omitempty"`
	PublicKeyFingerprint string   `json:"public_key_fingerprint,omitempty"`
}

type AccessBinding struct {
	Namespace          string `json:"namespace,omitempty"`
	Name               string `json:"name,omitempty"`
	CredentialUsername string `json:"credential_username,omitempty"`
	CredentialType     string `json:"credential_type,omitempty"`
}

type Target struct {
	Kind      string `json:"kind,omitempty"`
	Path      string `json:"path,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Container string `json:"container,omitempty"`
}

type Operation struct {
	Name       string `json:"name,omitempty"`
	Capability string `json:"capability,omitempty"`
	Command    string `json:"command,omitempty"`
}

type Authorization struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type Outcome struct {
	Result     string `json:"result,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Error      string `json:"error,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type Recorder interface {
	Record(ctx context.Context, event Event)
}

type NopRecorder struct{}

func (NopRecorder) Record(context.Context, Event) {}

// NewEvent initializes fields that must be present on every audit record.
func NewEvent(eventType string) Event {
	return Event{
		SchemaVersion: SchemaVersion,
		ID:            newID(),
		Time:          time.Now().UTC(),
		Type:          eventType,
	}
}

func NewID() string { return newID() }

func newID() string {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.NewString()
	}
	return id.String()
}
