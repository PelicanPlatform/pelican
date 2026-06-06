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
	"path"
	"strings"
)

// NamespaceInfo holds the director-provided metadata for a namespace,
// used to compute properly-scoped storage scopes for credential
// bootstrap requests.
type NamespaceInfo struct {
	IssuerURL     string
	BasePath      string // from XPelTokGenHdr.BasePaths[0]
	Namespace     string // from XPelNsHdr.Namespace
	MaxScopeDepth uint   // from XPelTokGenHdr.MaxScopeDepth
}

// ScopePath computes the path component for a storage scope, stripping
// the namespace base path and applying MaxScopeDepth trimming.  rawPath
// is the full object path (e.g. /foo/bar/baz.dat).
func (n *NamespaceInfo) ScopePath(rawPath string) string {
	cleaned := path.Clean(rawPath)
	// Strip the base path (or namespace) to get the path relative to the issuer.
	relative := cleaned
	if n.BasePath != "" && strings.HasPrefix(cleaned, n.BasePath) {
		relative = cleaned[len(n.BasePath):]
	} else if n.Namespace != "" && strings.HasPrefix(cleaned, n.Namespace) {
		relative = cleaned[len(n.Namespace):]
	}
	if relative == "" {
		relative = "/"
	}
	// Use the parent directory so the scope covers sibling files.
	relative = path.Dir(relative)
	// Apply MaxScopeDepth if set.
	if n.MaxScopeDepth > 0 {
		relative = TrimScopePath(relative, int(n.MaxScopeDepth))
	}
	return path.Clean("/" + relative)
}

// ComputeReadScopes returns the storage scopes needed for reading
// from the given path within this namespace.
func (n *NamespaceInfo) ComputeReadScopes(rawPath string) []string {
	p := n.ScopePath(rawPath)
	return []string{"storage.read:" + p}
}

// ComputeWriteScopes returns the storage scopes needed for writing
// to the given path within this namespace.
func (n *NamespaceInfo) ComputeWriteScopes(rawPath string) []string {
	p := n.ScopePath(rawPath)
	return []string{"storage.read:" + p, "storage.modify:" + p, "storage.create:" + p}
}

// TrimScopePath reduces a directory path to at most maxDepth components.
func TrimScopePath(pathName string, maxDepth int) string {
	if maxDepth < 0 {
		return "/"
	}
	pathName = path.Clean(pathName)
	components := strings.Split(pathName, "/")
	maxLen := maxDepth + 1
	if maxLen > len(components) {
		maxLen = len(components)
	}
	return "/" + path.Join(components[0:maxLen]...)
}

// ExtractObjectPath extracts the object path from a raw URL.
// For URLs like "pelican://host/foo/bar/baz.dat" it returns "/foo/bar/baz.dat".
// For non-URL strings it returns the input cleaned as a path.
func ExtractObjectPath(rawURL string) string {
	idx := strings.Index(rawURL, "://")
	if idx >= 0 {
		// Has a scheme — extract just the path portion.
		rest := rawURL[idx+3:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx >= 0 {
			return path.Clean(rest[slashIdx:])
		}
		return "/"
	}
	return path.Clean(rawURL)
}
