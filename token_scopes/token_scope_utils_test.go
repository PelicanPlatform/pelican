package token_scopes

import (
	"strconv"
	"testing"
)

func TestGetScopeString(t *testing.T) {
	tests := []struct {
		name   string
		scopes []TokenScope
		want   string
	}{
		{"no-scope", []TokenScope{}, ""},
		{"single-scope", []TokenScope{"read"}, "read"},
		{"multiple-scopes", []TokenScope{"read", "write", "delete"}, "read write delete"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetScopeString(tt.scopes)
			if got != tt.want {
				t.Errorf("GetScopeString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func largeInputSet() []string {
	var scopes []string
	for i := 0; i < 1000; i++ {
		scopes = append(scopes, "scope"+strconv.Itoa(i))
	}
	return scopes
}

func TestScopeContains(t *testing.T) {
	tests := []struct {
		name           string
		tokenScopes    []string
		expectedScopes []string
		all            bool
		want           bool
	}{
		{"empty-scopes", []string{}, []string{}, false, false},
		{"single-match", []string{"read"}, []string{"read"}, false, true},
		{"no-match", []string{"read"}, []string{"write"}, false, false},
		{"multiple-matches", []string{"read", "write"}, []string{"read", "write"}, false, true},
		{"partial-match-all-false", []string{"read", "write"}, []string{"read"}, false, true},
		{"partial-match-all-true", []string{"read", "write"}, []string{"read"}, true, false},
		{"case-insensitivity", []string{"Read"}, []string{"read"}, false, true},
		{"different-lengths-all-true", []string{"read", "write"}, []string{"read"}, true, false},
		{"exact-match-all-true", []string{"read", "write"}, []string{"write", "read"}, true, true},
		{"large-input-sets", largeInputSet(), largeInputSet(), false, true},
		{"nil-inputs", nil, nil, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopeContains(tt.tokenScopes, tt.expectedScopes, tt.all); got != tt.want {
				t.Errorf("ScopeContains() = %v, want %v", got, tt.want)
			}
		})
	}
}
