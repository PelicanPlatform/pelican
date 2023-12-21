package utils

import "testing"

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
