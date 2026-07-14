package status

import (
	"errors"
	"fmt"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ReasonInvalidTarget     metav1.StatusReason = "InvalidTarget"
	ReasonHelperUnavailable metav1.StatusReason = "HelperUnavailable"
	ReasonBackendFailure    metav1.StatusReason = "BackendFailure"
	ReasonInternal          metav1.StatusReason = "Internal"
)

type Error struct {
	Status metav1.Status
	Err    error
}

func Errorf(reason metav1.StatusReason, code int32, format string, args ...any) error {
	return &Error{
		Status: metav1.Status{
			Status:  metav1.StatusFailure,
			Reason:  reason,
			Code:    code,
			Message: fmt.Sprintf(format, args...),
		},
	}
}

func Wrap(reason metav1.StatusReason, code int32, err error, message string) error {
	if err == nil {
		return nil
	}
	return &Error{
		Status: metav1.Status{
			Status:  metav1.StatusFailure,
			Reason:  reason,
			Code:    code,
			Message: message,
		},
		Err: err,
	}
}

func Wrapf(reason metav1.StatusReason, code int32, err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	return Wrap(reason, code, err, fmt.Sprintf(format, args...))
}

func InvalidTarget(format string, args ...any) error {
	return Errorf(ReasonInvalidTarget, http.StatusBadRequest, format, args...)
}

func HelperUnavailable(err error, message string) error {
	return Wrap(ReasonHelperUnavailable, http.StatusServiceUnavailable, err, message)
}

func BackendFailure(err error, message string) error {
	return Wrap(ReasonBackendFailure, http.StatusBadGateway, err, message)
}

func Internal(format string, args ...any) error {
	return Errorf(ReasonInternal, http.StatusInternalServerError, format, args...)
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	message := e.Status.Message
	if e.Err != nil {
		if message == "" {
			message = e.Err.Error()
		} else {
			message = message + ": " + e.Err.Error()
		}
	}
	if message == "" {
		return string(e.Status.Reason)
	}
	return fmt.Sprintf("%s: %s", e.Status.Reason, message)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func ReasonForError(err error) metav1.StatusReason {
	if statusErr, ok := errors.AsType[*Error](err); ok {
		return statusErr.Status.Reason
	}
	return metav1.StatusReasonUnknown
}

func IsReason(err error, reason metav1.StatusReason) bool {
	return ReasonForError(err) == reason
}
