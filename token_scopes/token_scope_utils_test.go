/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package token_scopes

import (
	"strconv"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func largeInputSetScopes() []TokenScope {
	var scopes []TokenScope
	for i := 0; i < 1000; i++ {
		scopes = append(scopes, TokenScope("scope"+strconv.Itoa(i)))
	}
	return scopes
}

func TestScopeContains(t *testing.T) {
	tests := []struct {
		name           string
		tokenScopes    []string
		expectedScopes []TokenScope
		all            bool
		want           bool
	}{
		{"empty-scopes", []string{}, []TokenScope{}, false, false},
		{"single-match", []string{"read"}, []TokenScope{"read"}, false, true},
		{"no-match", []string{"read"}, []TokenScope{"write"}, false, false},
		{"multiple-matches", []string{"read", "write"}, []TokenScope{"read", "write"}, false, true},
		{"partial-match-all-false", []string{"read", "write"}, []TokenScope{"read"}, false, true},
		{"partial-match-all-true", []string{"read", "write"}, []TokenScope{"read"}, true, false},
		{"case-insensitivity", []string{"Read"}, []TokenScope{"read"}, false, true},
		{"different-lengths-all-true", []string{"read", "write"}, []TokenScope{"read"}, true, false},
		{"exact-match-all-true", []string{"read", "write"}, []TokenScope{"write", "read"}, true, true},
		{"large-input-sets", largeInputSet(), largeInputSetScopes(), false, true},
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

func TestResourceScopes(t *testing.T) {
	tests := []struct {
		name       string
		myScope    ResourceScope
		otherScope ResourceScope
		expected   bool
	}{
		{"diffScope", NewResourceScope(Wlcg_Storage_Create, "/"), NewResourceScope(Wlcg_Storage_Modify, "/"), false},
		{"same", NewResourceScope(Wlcg_Storage_Create, ""), NewResourceScope(Wlcg_Storage_Create, ""), true},
		{"default", NewResourceScope(Wlcg_Storage_Create, ""), NewResourceScope(Wlcg_Storage_Create, "/"), true},
		{"sub", NewResourceScope(Wlcg_Storage_Create, ""), NewResourceScope(Wlcg_Storage_Create, "/foo"), true},
		{"subDeep", NewResourceScope(Wlcg_Storage_Create, "/foo"), NewResourceScope(Wlcg_Storage_Create, "/foo/bar"), true},
		{"subClean", NewResourceScope(Wlcg_Storage_Create, "/foo"), NewResourceScope(Wlcg_Storage_Create, "/foo/"), true},
		{"noPath", NewResourceScope(Wlcg_Storage_Create, "/foo"), NewResourceScope(Wlcg_Storage_Create, "/foobar"), false},
		{"sameDeep", NewResourceScope(Wlcg_Storage_Create, "/foo/bar"), NewResourceScope(Wlcg_Storage_Create, "/foo/bar"), true},
		{"sameDeep", NewResourceScope(Wlcg_Storage_Create, "/foo/bar"), NewResourceScope(Wlcg_Storage_Create, "/foo/barbaz"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.myScope.Contains(tt.otherScope))
		})
	}
}

func TestParseResources(t *testing.T) {
	tok := jwt.New()

	require.NoError(t, tok.Set("scope", "blah"))
	assert.Equal(t, []ResourceScope{{Authorization: TokenScope("blah"), Resource: "/"}}, ParseResourceScopeString(tok))

	require.NoError(t, tok.Set("scope", 5))
	assert.Equal(t, []ResourceScope{}, ParseResourceScopeString(tok))

	require.NoError(t, tok.Set("scope", "foo bar"))
	assert.Equal(t, []ResourceScope{{Authorization: TokenScope("foo"), Resource: "/"}, {Authorization: TokenScope("bar"), Resource: "/"}}, ParseResourceScopeString(tok))

	require.NoError(t, tok.Set("scope", "storage.create:/foo"))
	assert.Equal(t, []ResourceScope{{Authorization: Wlcg_Storage_Create, Resource: "/foo"}}, ParseResourceScopeString(tok))
}
