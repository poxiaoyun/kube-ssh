package gateway

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"

	cryptossh "golang.org/x/crypto/ssh"
	"xiaoshiai.cn/kube-ssh/pkg/accesspolicy"
	"xiaoshiai.cn/kube-ssh/pkg/authn"
	"xiaoshiai.cn/kube-ssh/pkg/metrics"
)

var errAuthenticationRejected = errors.New("permission denied")

type authenticationResultKey struct{}

// authenticationResult travels with the candidate's Permissions through
// x/crypto's public-key cache. A key probe never publishes connection identity.
type authenticationResult struct {
	info        *authn.AuthenticateInfo
	fingerprint string
	credential  string
}

func (s *gateway) authenticationConfig(ctx *connectionState, enabled []string) *cryptossh.ServerConfig {
	var fingerprint string
	var reported bool
	finish := func(result *authenticationResult) (*cryptossh.Permissions, error) {
		s.recordAuthentication(ctx, result.credential, result.fingerprint, metrics.ResultSuccess, result.info, nil)
		reported = true
		if !s.acceptAuthenticated(ctx, result.info, result.fingerprint, result.credential) {
			return nil, errAuthenticationRejected
		}
		return &cryptossh.Permissions{ExtraData: map[any]any{authenticationResultKey{}: result}}, nil
	}
	publicKey := func(conn cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
		fingerprint, reported = cryptossh.FingerprintSHA256(key), false
		info, err := s.authn.AuthenticatePublicKey(ctx, conn.User(), key)
		if err != nil {
			return nil, err
		}
		return &cryptossh.Permissions{ExtraData: map[any]any{
			authenticationResultKey{}: &authenticationResult{info: info, fingerprint: fingerprint, credential: metrics.CredentialPublicKey},
		}}, nil
	}
	password := func(conn cryptossh.ConnMetadata, value []byte) (*cryptossh.Permissions, error) {
		reported = false
		info, err := s.authn.AuthenticateBasic(ctx, conn.User(), string(value))
		if err != nil {
			return nil, err
		}
		return finish(&authenticationResult{info: info, credential: metrics.CredentialPassword})
	}
	return &cryptossh.ServerConfig{
		// This only enables the guarded none callback. It must never return nil
		// error: the client still needs to complete one of the selected methods.
		NoClientAuth: true,
		NoClientAuthCallback: func(conn cryptossh.ConnMetadata) (*cryptossh.Permissions, error) {
			ctx.setMetadata(conn)
			methods := enabled
			if s.accessPolicy != nil {
				accessMethods, found, err := accesspolicy.AuthenticationMethods(ctx, s.accessPolicy, conn.User())
				if err != nil {
					slog.WarnContext(ctx, "authentication method selection failed", "user", conn.User(), "err", err)
					return nil, errAuthenticationRejected
				}
				if found {
					methods = accessMethods
				}
			}
			next := cryptossh.ServerAuthCallbacks{}
			if slices.Contains(enabled, "publickey") && slices.Contains(methods, "publickey") {
				next.PublicKeyCallback = publicKey
			}
			if slices.Contains(enabled, "password") && slices.Contains(methods, "password") {
				next.PasswordCallback = password
			}
			if next.PublicKeyCallback == nil && next.PasswordCallback == nil {
				return nil, errAuthenticationRejected
			}
			return nil, &cryptossh.PartialSuccessError{Next: next}
		},
		VerifiedPublicKeyCallback: func(_ cryptossh.ConnMetadata, _ cryptossh.PublicKey, permissions *cryptossh.Permissions, _ string) (*cryptossh.Permissions, error) {
			result := permissions.ExtraData[authenticationResultKey{}].(*authenticationResult)
			return finish(result)
		},
		AuthLogCallback: func(conn cryptossh.ConnMetadata, method string, err error) {
			defer func() { reported = false }()
			if method == "none" || err == nil || reported {
				return
			}
			attemptFingerprint := ""
			if method == "publickey" {
				attemptFingerprint = fingerprint
			}
			s.recordAuthentication(ctx, method, attemptFingerprint, metrics.ResultRejected, nil, err)
			s.metrics.AuthAttempt(method, metrics.ResultRejected)
			slog.WarnContext(ctx, "authentication rejected", "method", method, "user", conn.User(), "fingerprint", attemptFingerprint, "err", err)
		},
	}
}

func enabledAuthenticationMethods(methods []string) ([]string, error) {
	if methods == nil {
		methods = []string{"publickey", "password"}
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("authentication methods must contain at least one of publickey or password")
	}
	seen := make(map[string]bool, len(methods))
	for _, method := range methods {
		switch method {
		case "publickey", "password":
		default:
			return nil, fmt.Errorf("unsupported authentication method %q; use publickey or password", method)
		}
		if seen[method] {
			return nil, fmt.Errorf("duplicate authentication method %q", method)
		}
		seen[method] = true
	}
	return methods, nil
}
