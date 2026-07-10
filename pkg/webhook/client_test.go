package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientPostUsesBearerToken(t *testing.T) {
	var gotAuth string
	var gotBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer server.Close()

	client, err := NewClient(Options{Server: server.URL, Token: "secret"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	out := map[string]string{}
	if err := client.Post(context.Background(), map[string]string{"hello": "world"}, &out); err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("Authorization = %q, want bearer token", gotAuth)
	}
	if gotBody["hello"] != "world" {
		t.Fatalf("body = %#v", gotBody)
	}
	if out["ok"] != "true" {
		t.Fatalf("out = %#v", out)
	}
}

func TestClientPostReturnsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer server.Close()

	client, err := NewClient(Options{Server: server.URL})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if err := client.Post(context.Background(), map[string]string{"hello": "world"}, nil); err == nil {
		t.Fatal("Post() error = nil, want error")
	}
}
