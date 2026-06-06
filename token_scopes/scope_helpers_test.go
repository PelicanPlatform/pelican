/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrimScopePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		maxDepth int
		expected string
	}{
		{"negative depth returns root", "/a/b/c", -1, "/"},
		{"zero depth returns root", "/a/b/c", 0, "/"},
		{"depth 1 keeps first component", "/a/b/c", 1, "/a"},
		{"depth 2 keeps two components", "/a/b/c", 2, "/a/b"},
		{"depth exceeds path length", "/a/b", 5, "/a/b"},
		{"root path unaffected", "/", 2, "/"},
		{"double slashes cleaned", "/a//b/c", 1, "/a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, TrimScopePath(tt.path, tt.maxDepth))
		})
	}
}

func TestExtractObjectPath(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		expected string
	}{
		{"pelican URL", "pelican://host.example.com/foo/bar/baz.dat", "/foo/bar/baz.dat"},
		{"osdf URL", "osdf://host/some/path/file.txt", "/some/path/file.txt"},
		{"https URL", "https://example.com/data/file.dat", "/data/file.dat"},
		{"no scheme returns cleaned path", "/foo/bar/baz.dat", "/foo/bar/baz.dat"},
		{"relative path cleaned", "foo/bar/baz.dat", "foo/bar/baz.dat"},
		{"URL with no path after host", "pelican://host", "/"},
		{"URL trailing slash", "pelican://host/", "/"},
		{"double slashes cleaned", "pelican://host//foo//bar", "/foo/bar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, ExtractObjectPath(tt.rawURL))
		})
	}
}

func TestNamespaceInfo_ScopePath(t *testing.T) {
	tests := []struct {
		name     string
		ns       NamespaceInfo
		rawPath  string
		expected string
	}{
		{
			name:     "strips namespace prefix and takes parent dir",
			ns:       NamespaceInfo{Namespace: "/chtc/PROTECTED"},
			rawPath:  "/chtc/PROTECTED/data/file.dat",
			expected: "/data",
		},
		{
			name:     "strips base path when set",
			ns:       NamespaceInfo{Namespace: "/chtc/PROTECTED", BasePath: "/chtc"},
			rawPath:  "/chtc/PROTECTED/data/file.dat",
			expected: "/PROTECTED/data",
		},
		{
			name:     "path exactly at namespace returns root",
			ns:       NamespaceInfo{Namespace: "/chtc"},
			rawPath:  "/chtc/file.dat",
			expected: "/",
		},
		{
			name:     "max scope depth trims result",
			ns:       NamespaceInfo{Namespace: "/ns", MaxScopeDepth: 1},
			rawPath:  "/ns/a/b/c/file.dat",
			expected: "/a",
		},
		{
			name:     "max scope depth larger than path",
			ns:       NamespaceInfo{Namespace: "/ns", MaxScopeDepth: 10},
			rawPath:  "/ns/a/file.dat",
			expected: "/a",
		},
		{
			name:     "max scope depth 0 does not trim",
			ns:       NamespaceInfo{Namespace: "/ns", MaxScopeDepth: 0},
			rawPath:  "/ns/a/b/c/file.dat",
			expected: "/a/b/c",
		},
		{
			name:     "neither namespace nor basePath set",
			ns:       NamespaceInfo{},
			rawPath:  "/foo/bar/baz.dat",
			expected: "/foo/bar",
		},
		{
			name:     "base path does not match falls through to namespace",
			ns:       NamespaceInfo{Namespace: "/chtc", BasePath: "/other"},
			rawPath:  "/chtc/data/file.dat",
			expected: "/data",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.ns.ScopePath(tt.rawPath))
		})
	}
}

func TestNamespaceInfo_ComputeReadScopes(t *testing.T) {
	ns := NamespaceInfo{Namespace: "/chtc/PROTECTED"}
	scopes := ns.ComputeReadScopes("/chtc/PROTECTED/data/file.dat")
	assert.Equal(t, []string{"storage.read:/data"}, scopes)
}

func TestNamespaceInfo_ComputeWriteScopes(t *testing.T) {
	ns := NamespaceInfo{Namespace: "/chtc/PROTECTED"}
	scopes := ns.ComputeWriteScopes("/chtc/PROTECTED/data/file.dat")
	assert.Equal(t, []string{
		"storage.read:/data",
		"storage.modify:/data",
		"storage.create:/data",
	}, scopes)
}

func TestNamespaceInfo_ScopesWithDepthLimit(t *testing.T) {
	ns := NamespaceInfo{
		Namespace:     "/ns",
		BasePath:      "/ns",
		MaxScopeDepth: 2,
	}
	// Path /ns/a/b/c/d/file.dat → relative is /a/b/c/d/file.dat,
	// parent dir is /a/b/c/d, trimmed to depth 2 → /a/b
	readScopes := ns.ComputeReadScopes("/ns/a/b/c/d/file.dat")
	assert.Equal(t, []string{"storage.read:/a/b"}, readScopes)

	writeScopes := ns.ComputeWriteScopes("/ns/a/b/c/d/file.dat")
	assert.Equal(t, []string{
		"storage.read:/a/b",
		"storage.modify:/a/b",
		"storage.create:/a/b",
	}, writeScopes)
}
