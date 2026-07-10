package target

import "testing"

func TestTargetOptionsKeepOrder(t *testing.T) {
	tgt := Target{
		Kind: "example",
		Options: []KeyValue{
			{Key: "zones", Value: "z1"},
			{Key: "units", Value: "app"},
			{Key: "names", Value: "nginx"},
			{Key: "scopes", Value: "default"},
		},
	}
	if got, want := tgt.ToPath(), "example/zones/z1/units/app/names/nginx/scopes/default"; got != want {
		t.Fatalf("ToPath() = %q, want %q", got, want)
	}
	if got, want := tgt.Option("names"), "nginx"; got != want {
		t.Fatalf("Option(%q) = %q, want %q", "names", got, want)
	}
}
