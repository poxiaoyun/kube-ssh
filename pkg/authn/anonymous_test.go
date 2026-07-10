package authn

import (
	"context"
	"testing"
)

func TestAnonymousAuthenticateBasic(t *testing.T) {
	info, err := (Anonymous{}).AuthenticateBasic(context.Background(), "default.nginx.app", "password")
	if err != nil {
		t.Fatalf("AuthenticateBasic() error = %v", err)
	}
	if info.User.Name != AnonymousUserName {
		t.Fatalf("user name = %q, want %q", info.User.Name, AnonymousUserName)
	}
	if info.Method != "anonymous" {
		t.Fatalf("method = %q, want anonymous", info.Method)
	}
}
