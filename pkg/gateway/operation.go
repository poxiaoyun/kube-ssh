package gateway

import (
	"context"
	"errors"
	"maps"
	"strconv"
	"sync"
	"time"

	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type operationContext struct {
	// ctx is the SSH connection context shared by channels on this connection.
	ctx *connectionState
	// info is the authenticated user identity attached during SSH authentication.
	info authn.AuthenticateInfo
	// target is the resolved target for this SSH connection.
	target *target.Target
	// audit is the mutable audit event shared by operation steps.
	audit       audit.Event
	operationID string
}

type operationSpec struct {
	// name is the operation name used for start/end/error logs.
	name string
	// capability is checked by the authorizer and recorded in audit.
	capability authz.Capability
	// attrs is the structured authorization request for this operation.
	attrs authz.Attributes
	// auditFields are extra operation-specific audit fields.
	auditFields map[string]string
}

// Operations are dispatched only after the connection publishes authentication.
func newOperationContext(ctx *connectionState) *operationContext {
	result := ctx.snapshot().authenticated
	info, tgt := result.info, result.target

	event := audit.Event{
		Fields: map[string]string{
			"user": info.User.Name,
			"kind": tgt.Kind,
		},
	}
	for _, option := range tgt.Options {
		event.Fields[option.Key] = option.Value
	}

	return &operationContext{
		ctx:    ctx,
		info:   info,
		target: tgt,
		audit:  event,
	}
}

func (s *gateway) authorizeOperation(sc *operationContext, spec operationSpec) (string, bool) {
	sc.audit.Fields["capability"] = string(spec.capability)
	maps.Copy(sc.audit.Fields, spec.auditFields)

	decision, reason, err := s.authz.Authorize(sc.ctx, authz.Request{
		User:       sc.info.User,
		AuthMethod: sc.info.Method,
		AuthExtra:  sc.info.Extra,
		Attributes: spec.attrs,
	})
	if err != nil {
		reason = err.Error()
	}
	sc.audit.Fields["decision"] = string(decision)
	sc.audit.Fields["reason"] = reason
	if decision == authz.DecisionAllow {
		return "", true
	}
	if reason == "" {
		reason = "access denied"
	}

	sc.audit.Type = spec.name + "_denied"
	sc.audit.Fields["reason"] = reason
	return reason, false
}

func (s *gateway) startOperation(sc *operationContext, spec operationSpec) func(string) {
	recorder := s.metrics
	kind := sc.target.Kind
	capability := string(spec.capability)
	start := time.Now()
	operationID := audit.NewID()
	sc.operationID = operationID
	startEvent := s.operationEvent(sc, spec, "operation.start")
	s.audit.Record(sc.ctx, startEvent)
	recorder.OperationStarted(kind, capability)
	var once sync.Once
	return func(result string) {
		once.Do(func() {
			duration := time.Since(start)
			recorder.OperationFinished(kind, capability, result, duration)
			endEvent := s.operationEvent(sc, spec, "operation.end")
			endEvent.Outcome = &audit.Outcome{Result: result, DurationMS: duration.Milliseconds(), Error: sc.audit.Fields["error"]}
			if reason := sc.audit.Fields["reason"]; reason != "" {
				endEvent.Outcome.Reason = reason
			}
			if value := sc.audit.Fields["exit_code"]; value != "" {
				setAuditExitCode(endEvent.Outcome, value)
			}
			s.audit.Record(sc.ctx, endEvent)
		})
	}
}

func (s *gateway) operationEvent(sc *operationContext, spec operationSpec, eventType string) audit.Event {
	event := s.connectionEvent(sc.ctx, eventType)
	event.Correlation.OperationID = sc.operationID
	event.Target = auditTarget(sc.target)
	event.Operation = &audit.Operation{Name: spec.name, Capability: string(spec.capability), Command: spec.auditFields["command"]}
	event.Fields = make(map[string]string, len(spec.auditFields))
	maps.Copy(event.Fields, spec.auditFields)
	for key, value := range sc.audit.Fields {
		switch key {
		case "capability", "decision", "reason", "error", "exit_code":
			continue
		}
		event.Fields[key] = value
	}
	if decision := sc.audit.Fields["decision"]; decision != "" {
		event.Authorization = &audit.Authorization{Decision: decision, Reason: sc.audit.Fields["reason"]}
	}
	return event
}

func resultFromExit(exitCode int, err error) string {
	if err != nil {
		return resultFromError(err)
	}
	if exitCode != 0 {
		return metrics.ResultNonzeroExit
	}
	return metrics.ResultSuccess
}

func resultFromError(err error) string {
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return metrics.ResultCanceled
		}
		return metrics.ResultError
	}
	return metrics.ResultSuccess
}

func setAuditExitCode(outcome *audit.Outcome, value string) {
	code, err := strconv.Atoi(value)
	if err != nil {
		return
	}
	outcome.ExitCode = &code
}
