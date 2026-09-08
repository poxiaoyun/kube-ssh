package audit_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
)

func TestNewIDUsesUUIDv7(t *testing.T) {
	id, err := uuid.Parse(audit.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if id.Version() != 7 || id.Variant() != uuid.RFC4122 {
		t.Fatalf("audit ID = %s, want RFC 4122 UUIDv7", id)
	}
}

func TestNewEventInitializesEnvelope(t *testing.T) {
	before := time.Now()
	event := audit.NewEvent("operation.start")
	after := time.Now()
	if event.Type != "operation.start" || event.SchemaVersion != audit.SchemaVersion {
		t.Fatalf("event = %#v", event)
	}
	if event.Time.Before(before) || event.Time.After(after) || event.Time.Location() != time.UTC {
		t.Fatalf("event time = %s, want current UTC timestamp", event.Time)
	}
	id, err := uuid.Parse(event.ID)
	if err != nil {
		t.Fatal(err)
	}
	if id.Version() != 7 {
		t.Fatalf("event ID = %s, want UUIDv7", id)
	}
}
