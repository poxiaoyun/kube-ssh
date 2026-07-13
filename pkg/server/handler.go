package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	gossh "github.com/gliderlabs/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/backend"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

type sessionContext struct {
	// ctx is the SSH connection context shared by channels on this connection.
	ctx gossh.Context
	// info is the authenticated user identity attached during SSH authentication.
	info authn.AuthenticateInfo
	// target is the resolved backend target for this SSH connection.
	target *target.Target
	// policy is the effective session policy for this SSH connection.
	policy effectiveSessionPolicy
	// audit is the mutable audit event shared by operation steps.
	audit audit.Event
	// session is the underlying SSH session currently being handled.
	session gossh.Session
	// agentForward is the accepted agent forwarding socket for this session.
	agentForward backend.AgentForward
	operationID  string
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

type execOperationResolver func(ctx *sessionContext) (operationSpec, backend.ExecRequest, error)

func (s *Server) handleExecOperation(sess gossh.Session, resolve execOperationResolver) {
	sc, err := s.newSessionContext(sess)
	if err != nil {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
		return
	}

	spec, req, err := resolve(sc)
	if err != nil {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
		return
	}
	finishOperation := s.startOperation(sc, spec)

	reason, allowed := s.authorizeOperation(sc, spec)
	if !allowed {
		sc.audit.Fields["exit_code"] = "1"
		finishOperation(metrics.ResultDenied)
		_, _ = fmt.Fprintln(sess.Stderr(), reason)
		_ = sess.Exit(1)
		return
	}

	slog.InfoContext(sess.Context(), spec.name+" start", operationLogFields(sc, spec)...)

	exitCode, execErr := s.backend.Exec(sc.ctx, req)
	sc.audit.Fields["exit_code"] = fmt.Sprintf("%d", exitCode)
	if execErr != nil {
		writeSessionError(sess, req.TTY, execErr)
		sc.audit.Fields["error"] = execErr.Error()
		slog.ErrorContext(sess.Context(), spec.name+" error", append(operationLogFields(sc, spec), "err", execErr)...)
	} else {
		slog.InfoContext(sess.Context(), spec.name+" end", operationLogFields(sc, spec)...)
	}
	sc.audit.Type = spec.name + "_end"
	finishOperation(resultFromExit(exitCode, execErr))
	_ = sess.Exit(exitCode)
}

func (s *Server) handleStreamOperation(sess gossh.Session, resolve func(*sessionContext) (operationSpec, error), execute func(*sessionContext) (int, error)) {
	sc, err := s.newSessionContext(sess)
	if err != nil {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
		return
	}

	spec, err := resolve(sc)
	if err != nil {
		_, _ = fmt.Fprintln(sess.Stderr(), err)
		_ = sess.Exit(1)
		return
	}
	finishOperation := s.startOperation(sc, spec)

	reason, allowed := s.authorizeOperation(sc, spec)
	if !allowed {
		sc.audit.Fields["exit_code"] = "1"
		finishOperation(metrics.ResultDenied)
		_, _ = fmt.Fprintln(sess.Stderr(), reason)
		_ = sess.Exit(1)
		return
	}

	slog.InfoContext(sess.Context(), spec.name+" start", operationLogFields(sc, spec)...)
	exitCode, execErr := execute(sc)
	sc.audit.Fields["exit_code"] = fmt.Sprintf("%d", exitCode)
	if execErr != nil {
		writeSessionError(sess, false, execErr)
		sc.audit.Fields["error"] = execErr.Error()
		slog.ErrorContext(sess.Context(), spec.name+" error", append(operationLogFields(sc, spec), "err", execErr)...)
	} else {
		slog.InfoContext(sess.Context(), spec.name+" end", operationLogFields(sc, spec)...)
	}
	sc.audit.Type = spec.name + "_end"
	finishOperation(resultFromExit(exitCode, execErr))
	_ = sess.Exit(exitCode)
}

func (s *Server) newSessionContext(sess gossh.Session) (*sessionContext, error) {
	sc, err := s.newConnectionContext(sess.Context())
	if err != nil {
		return nil, err
	}
	sc.session = sess
	if agentSession, ok := sess.(agentForwardSession); ok {
		sc.agentForward = agentSession.AgentForward()
	}
	return sc, nil
}

func (s *Server) newConnectionContext(ctx gossh.Context) (*sessionContext, error) {
	info, ok := AuthenticateFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("internal error: missing identity")
	}
	tgt, ok := TargetFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("internal error: missing target")
	}

	event := audit.Event{
		Fields: map[string]string{
			"user": info.User.Name,
			"kind": tgt.Kind,
		},
	}
	for _, option := range tgt.Options {
		event.Fields[option.Key] = option.Value
	}

	return &sessionContext{
		ctx:    ctx,
		info:   info,
		target: tgt,
		policy: SessionPolicyFromContext(ctx),
		audit:  event,
	}, nil
}

func (s *Server) authorizeOperation(sc *sessionContext, spec operationSpec) (string, bool) {
	sc.audit.Fields["capability"] = string(spec.capability)
	for key, value := range spec.auditFields {
		sc.audit.Fields[key] = value
	}

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

func operationLogFields(sc *sessionContext, spec operationSpec) []any {
	fields := append(logFields(sc), "capability", string(spec.capability))
	for key, value := range spec.auditFields {
		fields = append(fields, key, value)
	}
	return fields
}

func logFields(sc *sessionContext) []any {
	return []any{
		"user", sc.info.User.Name,
		"kind", sc.target.Kind,
		"target", sc.target.ToPath(),
	}
}

func (s *Server) startOperation(sc *sessionContext, spec operationSpec) func(string) {
	recorder := s.metricsRecorder()
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
				if code, err := strconv.Atoi(value); err == nil {
					endEvent.Outcome.ExitCode = &code
				}
			}
			s.audit.Record(sc.ctx, endEvent)
		})
	}
}

func (s *Server) operationEvent(sc *sessionContext, spec operationSpec, eventType string) audit.Event {
	event := s.connectionEvent(sc.ctx, connectionAuditFromContext(sc.ctx), eventType)
	event.Correlation.OperationID = sc.operationID
	if event.Actor == nil {
		event.Actor = auditActor(sc.info, "")
	}
	event.Target = auditTarget(sc.target)
	event.Operation = &audit.Operation{Name: spec.name, Capability: string(spec.capability), Command: spec.auditFields["command"]}
	event.Fields = make(map[string]string, len(spec.auditFields))
	for key, value := range spec.auditFields {
		event.Fields[key] = value
	}
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
	if err == nil {
		return metrics.ResultSuccess
	}
	if errors.Is(err, context.Canceled) {
		return metrics.ResultCanceled
	}
	return metrics.ResultError
}
