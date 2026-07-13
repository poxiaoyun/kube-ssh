package server

import (
	"strings"

	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/audit"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/target"
)

func auditActor(info authn.AuthenticateInfo, fingerprint string) *audit.Actor {
	return &audit.Actor{
		ID:                   info.User.ID,
		Name:                 info.User.Name,
		Email:                info.User.Email,
		EmailVerified:        info.User.EmailVerified,
		Groups:               append([]string(nil), info.User.Groups...),
		AuthenticationMethod: info.Method,
		PublicKeyFingerprint: fingerprint,
	}
}

func auditTarget(tgt *target.Target) *audit.Target {
	if tgt == nil {
		return nil
	}
	return &audit.Target{
		Kind:      tgt.Kind,
		Path:      tgt.ToPath(),
		Namespace: firstTargetOption(tgt, "namespace", "namespaces"),
		Name:      firstTargetOption(tgt, "name", "pod", "pods"),
		Container: firstTargetOption(tgt, "container", "containers"),
	}
}

func auditAccess(info authn.AuthenticateInfo) *audit.AccessBinding {
	namespace := firstExtraValue(info.Extra, accesspolicy.ExtraAccessNamespace)
	name := firstExtraValue(info.Extra, accesspolicy.ExtraAccessName)
	if namespace == "" && name == "" {
		values := info.Extra["access"]
		if len(values) > 0 {
			namespace, name, _ = strings.Cut(values[0], "/")
		}
	}
	if namespace == "" || name == "" {
		return nil
	}
	credentialUsername := firstExtraValue(info.Extra, accesspolicy.ExtraCredentialUser)
	if credentialUsername == "" {
		credentialUsername = info.User.Name
	}
	credentialType := firstExtraValue(info.Extra, accesspolicy.ExtraCredentialType)
	if credentialType == "" {
		credentialType = info.Method
	}
	return &audit.AccessBinding{
		Namespace:          namespace,
		Name:               name,
		CredentialUsername: credentialUsername,
		CredentialType:     credentialType,
	}
}

func firstTargetOption(tgt *target.Target, keys ...string) string {
	for _, key := range keys {
		if value := tgt.Option(key); value != "" {
			return value
		}
	}
	return ""
}
