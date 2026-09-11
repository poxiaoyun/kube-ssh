package gateway

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/anmitsu/go-shlex"
	"xiaoshiai.cn/kube-ssh/pkg/authz"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
	"xiaoshiai.cn/kube-ssh/pkg/podssh"
	"xiaoshiai.cn/kube-ssh/pkg/sshprotocol"
	"xiaoshiai.cn/kube-ssh/pkg/sshproxy"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func (s *gateway) selectConnectionProtocol(ctx *connectionState, tgt *target.Target, policy effectiveSessionPolicy) (sshprotocol.ConnectionProtocol, error) {
	switch tgt.Kind {
	case target.KindPod:
		if s.podBackend == nil {
			return nil, fmt.Errorf("pod SSH backend is not configured")
		}
		return podssh.NewProtocol(
			ctx,
			tgt,
			s.podBackend,
			func(operation sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
				return s.beginConnectionOperation(ctx, operation)
			},
			s.metrics,
			policy.DefaultShell,
			policy.envAllowed,
		), nil
	case target.KindExternalSSH:
		if s.sshProxy == nil {
			return nil, fmt.Errorf("upstream SSH connector is not configured")
		}
		return sshproxy.NewProtocol(
			ctx,
			tgt,
			s.sshProxy,
			func(operation sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
				return s.beginConnectionOperation(ctx, operation)
			},
			policy.envAllowed,
		), nil
	default:
		return nil, fmt.Errorf("target kind %q has no SSH protocol implementation", tgt.Kind)
	}
}

func (s *gateway) beginConnectionOperation(ctx *connectionState, operation sshprotocol.Operation) (sshprotocol.FinishOperation, error) {
	sc := newOperationContext(ctx)
	spec := connectionOperationSpec(sc, operation)
	finish := s.startOperation(sc, spec)
	reason, allowed := s.authorizeOperation(sc, spec)
	complete := func(result sshprotocol.OperationResult) {
		if result.Err != nil {
			sc.audit.Fields["error"] = result.Err.Error()
		}
		if result.ExitCode != nil {
			sc.audit.Fields["exit_code"] = strconv.Itoa(*result.ExitCode)
			if !allowed {
				finish(metrics.ResultDenied)
				return
			}
			finish(resultFromExit(*result.ExitCode, result.Err))
			return
		}
		if result.ActualBindPort != nil {
			sc.audit.Fields["actual_port"] = strconv.FormatUint(uint64(*result.ActualBindPort), 10)
		}
		if !allowed {
			finish(metrics.ResultDenied)
			return
		}
		finish(resultFromError(result.Err))
	}
	if !allowed {
		return complete, fmt.Errorf("%s", reason)
	}
	return complete, nil
}

func connectionOperationSpec(sc *operationContext, operation sshprotocol.Operation) operationSpec {
	switch {
	case operation.ChannelType == sshprotocol.ChannelDirectTCPIP:
		return localForwardOperationSpec(sc, operation)
	case operation.RequestType == sshprotocol.RequestTCPIPForward:
		return connectionRemoteForwardOperationSpec(sc, operation)
	case operation.RequestType == sshprotocol.RequestAgentForward:
		return connectionAgentForwardOperationSpec(sc)
	case operation.ChannelType == sshprotocol.ChannelSession && (operation.RequestType == sshprotocol.RequestShell || operation.RequestType == sshprotocol.RequestExec):
		argv, _ := shlex.Split(operation.Command, true)
		return connectionSessionOperationSpec(*sc.target, operation.RequestType, argv, operation.Command)
	case operation.ChannelType == sshprotocol.ChannelSession && operation.RequestType == sshprotocol.RequestSubsystem && operation.Subsystem == sshprotocol.SubsystemSFTP:
		return connectionSFTPOperationSpec(*sc.target)
	default:
		return connectionExtensionOperationSpec(sc, operation)
	}
}

func localForwardOperationSpec(sc *operationContext, operation sshprotocol.Operation) operationSpec {
	destinationPort := strconv.FormatUint(uint64(operation.DestinationPort), 10)
	originPort := strconv.FormatUint(uint64(operation.OriginPort), 10)
	return operationSpec{
		name:       "portforward",
		capability: authz.CapabilityLocalForward,
		attrs: authz.Attributes{
			Action: string(authz.CapabilityLocalForward),
			Resources: append(targetResources(*sc.target),
				authz.AttributeResource{Resource: "hosts", Name: operation.DestinationHost},
				authz.AttributeResource{Resource: "ports", Name: destinationPort},
			),
			Path: sc.target.String() + "/hosts/" + operation.DestinationHost + "/ports/" + destinationPort,
			Extra: map[string][]string{
				"destination_host": {operation.DestinationHost},
				"destination_port": {destinationPort},
				"origin_host":      {operation.OriginHost},
				"origin_port":      {originPort},
			},
		},
		auditFields: map[string]string{
			"destination_host": operation.DestinationHost,
			"destination_port": destinationPort,
			"origin_host":      operation.OriginHost,
			"origin_port":      originPort,
		},
	}
}

func connectionRemoteForwardOperationSpec(sc *operationContext, operation sshprotocol.Operation) operationSpec {
	port := strconv.FormatUint(uint64(operation.BindPort), 10)
	return operationSpec{
		name:       "remote_forward",
		capability: authz.CapabilityRemoteForward,
		attrs: authz.Attributes{
			Action: string(authz.CapabilityRemoteForward),
			Resources: append(targetResources(*sc.target),
				authz.AttributeResource{Resource: "bind_hosts", Name: operation.BindHost},
				authz.AttributeResource{Resource: "bind_ports", Name: port},
			),
			Path: sc.target.String() + "/remote-forwards/" + operation.BindHost + "/" + port,
			Extra: map[string][]string{
				"bind_host": {operation.BindHost},
				"bind_port": {port},
			},
		},
		auditFields: map[string]string{"bind_host": operation.BindHost, "bind_port": port},
	}
}

func connectionAgentForwardOperationSpec(sc *operationContext) operationSpec {
	return operationSpec{
		name:       "agent_forward",
		capability: authz.CapabilityAgentForward,
		attrs: authz.Attributes{
			Action:    string(authz.CapabilityAgentForward),
			Resources: targetResources(*sc.target),
			Path:      sc.target.String() + "/agent-forward",
		},
	}
}

func connectionSessionOperationSpec(tgt target.Target, requestType string, argv []string, command string) operationSpec {
	capability := authz.CapabilityExec
	switch requestType {
	case sshprotocol.RequestShell:
		capability = authz.CapabilityShell
	case sshprotocol.RequestExec:
		if isSCPCommand(argv) {
			capability = authz.CapabilitySCP
		}
	}
	name := "session"
	if capability == authz.CapabilitySCP {
		name = "scp"
	}
	extra := map[string][]string{}
	if command != "" {
		extra["command"] = []string{command}
	}
	return operationSpec{
		name:       name,
		capability: capability,
		attrs: authz.Attributes{
			Action:    string(capability),
			Resources: targetResources(tgt),
			Path:      tgt.String(),
			Extra:     extra,
		},
		auditFields: map[string]string{"command": command},
	}
}

func connectionSFTPOperationSpec(tgt target.Target) operationSpec {
	return operationSpec{
		name:       "sftp",
		capability: authz.CapabilitySFTP,
		attrs: authz.Attributes{
			Action:    string(authz.CapabilitySFTP),
			Resources: targetResources(tgt),
			Path:      tgt.String(),
		},
	}
}

func targetResources(tgt target.Target) []authz.AttributeResource {
	resources := []authz.AttributeResource{{Resource: "targets", Name: tgt.Kind}}
	for _, option := range tgt.Options {
		resources = append(resources, authz.AttributeResource{Resource: option.Key, Name: option.Value})
	}
	return resources
}

func isSCPCommand(argv []string) bool {
	if len(argv) == 0 || path.Base(argv[0]) != "scp" {
		return false
	}
	for _, arg := range argv[1:] {
		if arg == "-t" || arg == "-f" || strings.HasPrefix(arg, "-t") || strings.HasPrefix(arg, "-f") {
			return true
		}
	}
	return false
}

func connectionExtensionOperationSpec(sc *operationContext, operation sshprotocol.Operation) operationSpec {
	extra := map[string][]string{}
	auditFields := map[string]string{}
	path := sc.target.String()
	add := func(key, value string) {
		if value == "" {
			return
		}
		extra[key] = []string{value}
		auditFields[key] = value
	}
	add("channel_type", operation.ChannelType)
	add("request_type", operation.RequestType)
	add("subsystem", operation.Subsystem)
	if operation.ChannelType != "" {
		path += "/channels/" + operation.ChannelType
	}
	if operation.RequestType != "" {
		path += "/requests/" + operation.RequestType
	}
	return operationSpec{
		name:       "ssh_extension",
		capability: authz.CapabilitySSHExtension,
		attrs: authz.Attributes{
			Action:    string(authz.CapabilitySSHExtension),
			Resources: targetResources(*sc.target),
			Path:      path,
			Extra:     extra,
		},
		auditFields: auditFields,
	}
}
