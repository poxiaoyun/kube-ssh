package accesspolicy

import "xiaoshiai.cn/kube-ssh/pkg/authn"

const (
	ExtraAccessNamespace = "kube-ssh/access.namespace"
	ExtraAccessName      = "kube-ssh/access.name"
	ExtraCredentialUser  = "kube-ssh/access.credential.username"
	ExtraCredentialType  = "kube-ssh/access.credential.type"
)

const (
	CredentialTypePassword  = "password"
	CredentialTypePublicKey = "publickey"
)

func authExtra(match *CredentialMatch, credentialType string) map[string][]string {
	return map[string][]string{
		ExtraAccessNamespace: {match.Access.Namespace},
		ExtraAccessName:      {match.Access.Name},
		ExtraCredentialUser:  {match.Credential.Username},
		ExtraCredentialType:  {credentialType},
	}
}

func matchUser(match *CredentialMatch) authn.UserInfo {
	return authn.UserInfo{
		ID:     match.Credential.UID,
		Name:   match.Credential.Username,
		Groups: append([]string(nil), match.Credential.Groups...),
		Extra:  copyStringSliceMap(match.Credential.Extra),
	}
}
