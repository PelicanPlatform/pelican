/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package issuer

import (
	"net/url"
	"strings"

	"github.com/ory/fosite"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/oa4mp"
)

// sciTokensScopeStrategy is a fosite ScopeStrategy that understands SciTokens/WLCG
// hierarchical scopes (e.g., storage.read:/ covers storage.read:/data/analysis).
//
// For WLCG-style scopes (containing ":"), only exact match and hierarchical
// path matching are used.  fosite's WildcardScopeStrategy is NOT applied to
// these scopes because it splits on "." and treats "*" as a wildcard segment,
// which could cause a matcher like "storage.*" to incorrectly grant access
// to any storage action at any path.
//
// For plain OIDC scopes (openid, offline_access, etc.) the standard
// WildcardScopeStrategy is used as a fallback.
func sciTokensScopeStrategy(matchers []string, needle string) bool {
	if strings.Contains(needle, ":") {
		// WLCG-style scope — use only exact + hierarchical matching.
		for _, m := range matchers {
			if m == needle {
				return true
			}
		}
		return matchHierarchical(needle, matchers)
	}
	// Plain OIDC scope — fosite's standard strategy is safe here.
	return fosite.WildcardScopeStrategy(matchers, needle)
}

// CalculateUserScopes computes the set of scopes a user should be granted
// based on the configured Issuer.AuthorizationTemplates and the user's groups.
//
// It delegates to oa4mp.CalculateAllowedScopes which processes the compiled
// authorization rules.
//
// Returns the allowed scopes and the set of groups that matched rules.
func CalculateUserScopes(user, userID string, groups []string) (scopes []string, matchedGroups []string) {
	return oa4mp.CalculateAllowedScopes(user, userID, groups)
}

// MapGroupsToScopes converts a user's group memberships into WLCG-style
// storage scopes using the prefix and action rules from Issuer.AuthorizationTemplates.
//
// This is a convenience wrapper that returns only the scopes (not the matched groups).
func MapGroupsToScopes(user, userID string, groups []string) []string {
	scopes, _ := CalculateUserScopes(user, userID, groups)
	return scopes
}

// FilterRequestedScopes filters requested scopes against what the user is allowed.
// It returns only the scopes that are both requested and permitted by authorization rules.
// Standard OIDC scopes (openid, offline_access, wlcg) are always allowed.
//
// When a requested scope is broader than any single allowed scope (e.g. the user
// requests storage.read:/ but is only permitted storage.read:/foo and
// storage.read:/bar), the broad scope is replaced with all narrower allowed
// scopes that fall under it.
func FilterRequestedScopes(requestedScopes []string, user, userID string, groups []string) []string {
	allowedScopes := MapGroupsToScopes(user, userID, groups)

	// Build a set of allowed scopes
	allowedSet := make(map[string]struct{}, len(allowedScopes))
	for _, s := range allowedScopes {
		allowedSet[s] = struct{}{}
	}

	// These OIDC/WLCG meta-scopes are always allowed for authenticated users
	alwaysAllowed := map[string]struct{}{
		"openid":         {},
		"offline_access": {},
		"wlcg":           {},
		"profile":        {},
		"email":          {},
	}

	seen := make(map[string]struct{}) // dedup
	result := make([]string, 0, len(requestedScopes))
	addUnique := func(s string) {
		if _, dup := seen[s]; !dup {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}

	for _, scope := range requestedScopes {
		if _, ok := alwaysAllowed[scope]; ok {
			addUnique(scope)
			continue
		}
		// Check if the requested scope is in the allowed set
		if _, ok := allowedSet[scope]; ok {
			addUnique(scope)
			continue
		}
		// Check hierarchical matching: user might request storage.read:/foo
		// and the allowed scope is storage.read:/ (which is a parent)
		if matchHierarchical(scope, allowedScopes) {
			addUnique(scope)
			continue
		}
		// Reverse hierarchical: the requested scope is broader than what's
		// allowed (e.g. storage.read:/ requested but only storage.read:/foo
		// and storage.read:/bar are permitted). Substitute in all narrower
		// allowed scopes that fall under the requested one.
		narrower := collectNarrowerScopes(scope, allowedScopes)
		if len(narrower) > 0 {
			for _, ns := range narrower {
				addUnique(ns)
			}
			continue
		}
		log.Debugf("FilterRequestedScopes: scope %q not allowed for user %s", scope, user)
	}
	return result
}

// matchHierarchical checks whether requestedScope is covered by any scope in allowed.
// For example, storage.read:/foo is covered by storage.read:/ because / is a prefix of /foo.
func matchHierarchical(requestedScope string, allowed []string) bool {
	reqParts := strings.SplitN(requestedScope, ":", 2)
	if len(reqParts) != 2 {
		return false
	}
	reqAction := reqParts[0]
	reqPath := reqParts[1]

	// Decode URL-encoded paths for proper comparison
	reqPathDecoded, err := url.PathUnescape(reqPath)
	if err != nil {
		reqPathDecoded = reqPath
	}

	for _, scope := range allowed {
		parts := strings.SplitN(scope, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != reqAction {
			continue
		}
		allowedPath, err := url.PathUnescape(parts[1])
		if err != nil {
			allowedPath = parts[1]
		}
		if isHierarchicalChild(reqPathDecoded, allowedPath) {
			return true
		}
	}
	return false
}

// collectNarrowerScopes returns all allowed scopes whose action matches the
// requested scope and whose path is a child of (narrower than) the requested
// scope's path. For example, if requestedScope is "storage.read:/" and allowed
// contains ["storage.read:/foo", "storage.read:/bar", "storage.modify:/baz"],
// it returns ["storage.read:/foo", "storage.read:/bar"].
func collectNarrowerScopes(requestedScope string, allowed []string) []string {
	reqParts := strings.SplitN(requestedScope, ":", 2)
	if len(reqParts) != 2 {
		return nil
	}
	reqAction := reqParts[0]
	reqPath, err := url.PathUnescape(reqParts[1])
	if err != nil {
		reqPath = reqParts[1]
	}

	var result []string
	for _, scope := range allowed {
		parts := strings.SplitN(scope, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] != reqAction {
			continue
		}
		allowedPath, err := url.PathUnescape(parts[1])
		if err != nil {
			allowedPath = parts[1]
		}
		// Check if the allowed scope's path is a child of the requested path
		// (i.e. the requested scope is broader)
		if isHierarchicalChild(allowedPath, reqPath) {
			result = append(result, scope)
		}
	}
	return result
}

// isHierarchicalChild checks whether childPath is covered by parentPath.
// parentPath must be an ancestor (prefix at a path-component boundary) of childPath,
// or they must be equal.
func isHierarchicalChild(childPath, parentPath string) bool {
	if !strings.HasPrefix(childPath, parentPath) {
		return false
	}
	if len(childPath) == len(parentPath) {
		return true // exact match
	}
	if strings.HasSuffix(parentPath, "/") {
		return true // parent ends in /, e.g. /data/ covers /data/foo
	}
	if childPath[len(parentPath)] == '/' {
		return true // path-component boundary, e.g. /data covers /data/foo
	}
	return false
}
