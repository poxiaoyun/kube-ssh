package pattern

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{name: "exact", pattern: "mysql-0", value: "mysql-0", want: true},
		{name: "different", pattern: "mysql-0", value: "mysql-1", want: false},
		{name: "all", pattern: "*", value: "mysql-0", want: true},
		{name: "prefix", pattern: "mysql-*", value: "mysql-0", want: true},
		{name: "suffix", pattern: "*.internal", value: "db.internal", want: true},
		{name: "middle", pattern: "db-*-primary", value: "db-eu-primary", want: true},
		{name: "host port", pattern: "*:8080", value: "127.0.0.1:8080", want: true},
		{name: "host port mismatch", pattern: "*:8080", value: "127.0.0.1:9090", want: false},
		{name: "multiple stars", pattern: "a**c", value: "abc", want: true},
		{name: "ordered", pattern: "*ab*cd*", value: "xxabyycdzz", want: true},
		{name: "out of order", pattern: "*ab*cd*", value: "xxcdyyabzz", want: false},
		{name: "empty exact", pattern: "", value: "", want: true},
		{name: "empty mismatch", pattern: "", value: "value", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.pattern, tt.value); got != tt.want {
				t.Fatalf("Match(%q, %q) = %t, want %t", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	if MatchAny(nil, "mysql-0") {
		t.Fatal("MatchAny(nil) = true, want false")
	}
	if !MatchAny([]string{"postgres-*", "mysql-*"}, "mysql-0") {
		t.Fatal("MatchAny() = false, want true")
	}
}
