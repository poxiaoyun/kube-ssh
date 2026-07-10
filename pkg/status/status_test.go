package status

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStatusError(t *testing.T) {
	err := Errorf(ReasonInvalidTarget, http.StatusBadRequest, "bad target")
	if !IsReason(err, ReasonInvalidTarget) {
		t.Fatalf("IsReason() = false, want true")
	}
	if ReasonForError(errors.New("plain")) != metav1.StatusReasonUnknown {
		t.Fatalf("plain error reason is not unknown")
	}
	if !strings.Contains(err.Error(), "InvalidTarget: bad target") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestStatusWrap(t *testing.T) {
	cause := errors.New("disk missing")
	err := HelperUnavailable(cause, "read helper binary")
	if !errors.Is(err, cause) {
		t.Fatalf("wrapped error does not match cause")
	}
	if !IsReason(err, ReasonHelperUnavailable) {
		t.Fatalf("IsReason() = false, want true")
	}
	if !strings.Contains(err.Error(), "HelperUnavailable: read helper binary: disk missing") {
		t.Fatalf("error = %q", err.Error())
	}
}
