// Package sshproxy establishes upstream SSH transports for External Access
// targets.
package sshproxy

import (
	"fmt"
	"strconv"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

const (
	optionNamespaces = "namespaces"
	optionAccesses   = "accesses"
	optionEndpoints  = "endpoints"

	runtimeAccessUID        = "ssh.accessUID"
	runtimeAccessGeneration = "ssh.accessGeneration"
)

type boundTarget struct {
	Namespace  string
	Access     string
	Endpoint   string
	AccessUID  string
	Generation int64
}

// NewTarget binds an endpoint to the current Access identity and generation.
func NewTarget(access *sshv1.Access, endpoint string) *target.Target {
	return &target.Target{
		Kind: target.KindExternalSSH,
		Options: []target.Option{
			{Key: optionNamespaces, Value: access.Namespace},
			{Key: optionAccesses, Value: access.Name},
			{Key: optionEndpoints, Value: endpoint},
		},
		Runtime: map[string]string{
			runtimeAccessUID:        string(access.UID),
			runtimeAccessGeneration: strconv.FormatInt(access.Generation, 10),
		},
	}
}

func parseTarget(tgt *target.Target) (boundTarget, error) {
	if tgt == nil {
		return boundTarget{}, apierrors.NewBadRequest("target is not specified")
	}
	if tgt.Kind != target.KindExternalSSH {
		return boundTarget{}, apierrors.NewBadRequest(fmt.Sprintf("unsupported target kind %q", tgt.Kind))
	}
	parsed := boundTarget{
		Namespace: tgt.Option(optionNamespaces),
		Access:    tgt.Option(optionAccesses),
		Endpoint:  tgt.Option(optionEndpoints),
		AccessUID: tgt.Runtime[runtimeAccessUID],
	}
	if parsed.Namespace == "" || parsed.Access == "" || parsed.Endpoint == "" || parsed.AccessUID == "" {
		return boundTarget{}, apierrors.NewBadRequest("ssh target requires a bound Access and endpoint")
	}
	generation, err := strconv.ParseInt(tgt.Runtime[runtimeAccessGeneration], 10, 64)
	if err != nil {
		return boundTarget{}, apierrors.NewBadRequest("ssh target has invalid Access generation")
	}
	parsed.Generation = generation
	return parsed, nil
}
