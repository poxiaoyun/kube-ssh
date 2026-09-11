package accesspolicy

import "context"

// AuthenticationMethods derives SSH methods from the selected Access's inbound
// credentials. found distinguishes an Access without credentials from a direct
// Pod locator. Secret references declare a method; the matcher validates their
// contents when the client supplies credentials.
func AuthenticationMethods(ctx context.Context, store AccessGetter, sshUser string) (methods []string, found bool, err error) {
	_, access, found, err := resolveAccessLocator(ctx, store, sshUser)
	if err != nil || !found {
		return nil, found, err
	}
	var publicKey, password bool
	for _, credential := range access.Spec.Credentials {
		publicKey = publicKey || len(credential.PublicKeysFrom) > 0
		password = password || len(credential.PasswordsFrom) > 0
		for _, value := range credential.PublicKeys {
			publicKey = publicKey || value != ""
		}
		for _, value := range credential.Passwords {
			password = password || value != ""
		}
	}
	if publicKey {
		methods = append(methods, CredentialTypePublicKey)
	}
	if password {
		methods = append(methods, CredentialTypePassword)
	}
	return methods, true, nil
}
