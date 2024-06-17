//go:build !windows

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

package local_cache

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestCalcResources(t *testing.T) {
	tests := []struct {
		scopes          token_scopes.ResourceScope
		basePaths       []string
		restrictedPaths []string
		result          []token_scopes.ResourceScope
	}{
		{
			scopes:    token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"),
			basePaths: []string{"/foo", "/bar"},
			result: []token_scopes.ResourceScope{
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/foo"),
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/bar"),
			},
		},
		{
			scopes:          token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"),
			basePaths:       []string{"/foo", "/bar"},
			restrictedPaths: []string{"/baz"},
			result: []token_scopes.ResourceScope{
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/foo/baz"),
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/bar/baz"),
			},
		},
		{
			scopes:          token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"),
			basePaths:       []string{"/"},
			restrictedPaths: []string{"/foo", "/bar"},
			result: []token_scopes.ResourceScope{
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/foo"),
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/bar"),
			},
		},
		{
			scopes:          token_scopes.NewResourceScope(token_scopes.Storage_Read, "/baz"),
			basePaths:       []string{"/foo"},
			restrictedPaths: []string{"/bar"},
			result:          []token_scopes.ResourceScope{},
		},
		{
			scopes:          token_scopes.NewResourceScope(token_scopes.Storage_Read, "/bar/baz"),
			basePaths:       []string{"/foo"},
			restrictedPaths: []string{"/bar"},
			result: []token_scopes.ResourceScope{
				token_scopes.NewResourceScope(token_scopes.Storage_Read, "/foo/bar/baz"),
			},
		},
	}
	for _, test := range tests {
		result := calcResourceScopes(test.scopes, test.basePaths, test.restrictedPaths)
		assert.Equal(t, test.result, result)
	}
}
