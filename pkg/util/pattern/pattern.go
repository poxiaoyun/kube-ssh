// Package pattern provides small, policy-neutral wildcard matching helpers.
package pattern

import "strings"

// Match reports whether value matches pattern. An asterisk matches any
// sequence of characters, including an empty sequence.
func Match(pattern, value string) bool {
	if pattern == value || pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return false
	}

	parts := strings.Split(pattern, "*")
	rest := value
	if parts[0] != "" {
		if !strings.HasPrefix(rest, parts[0]) {
			return false
		}
		rest = rest[len(parts[0]):]
	}
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		idx := strings.Index(rest, part)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(part):]
	}
	last := parts[len(parts)-1]
	return last == "" || strings.HasSuffix(rest, last)
}

// MatchAny reports whether value matches at least one pattern. An empty
// pattern list does not match; callers retain ownership of empty-list policy.
func MatchAny(patterns []string, value string) bool {
	for _, candidate := range patterns {
		if Match(candidate, value) {
			return true
		}
	}
	return false
}
