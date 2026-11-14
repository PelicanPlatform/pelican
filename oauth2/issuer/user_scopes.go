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
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oa4mp"
)

// userAllowedScopes computes every scope this issuer may grant the user: the
// authorization templates (this namespace's own rules when it has them, the
// global ones otherwise) plus the scopes derived from collection ACLs. Every
// path that mints tokens for a user goes through it, whether browser
// authorization, device approval or external token exchange, so none of them
// can grant more than the others.
//
// It also returns the groups that contributed, for the wlcg.groups claim, and
// the database it consulted, which grantRequestedScopes needs for the
// pelican.transfer gate.
func (p *OIDCProvider) userAllowedScopes(user, userID string, groups []string) (allowed, matchedGroups []string, serverDB *gorm.DB) {
	if len(p.AuthzRules) > 0 {
		allowed, matchedGroups = oa4mp.CalculateAllowedScopesWithRules(p.AuthzRules, user, userID, groups)
	} else {
		allowed, matchedGroups = oa4mp.CalculateAllowedScopes(user, userID, groups)
	}
	serverDB = database.ServerDatabase
	if serverDB == nil {
		serverDB = p.storage.db
	}
	collectionScopes, collectionGroups, err := oa4mp.GetUserCollectionScopes(serverDB, user, userID, groups, p.Namespace)
	if err != nil {
		log.WithError(err).Warn("Embedded issuer: failed to get collection scopes")
	} else {
		allowed = append(allowed, collectionScopes...)
		matchedGroups = oa4mp.MergeGroups(matchedGroups, collectionGroups)
	}
	return allowed, matchedGroups, serverDB
}

// grantRequestedScopes decides which of the requested scopes to grant.
//
// A requested scope the user's authorization covers is granted as is; one
// broader than what is permitted is replaced by every narrower allowed scope
// beneath it. Standard OIDC scopes (openid, offline_access, wlcg, profile,
// email) are protocol-level and bypass the user-authorization check, while
// pelican.transfer is granted only to users permitted to use the transfer
// API. Every candidate must also be within the client's configured scopes, so
// operators can restrict what each client receives.
func grantRequestedScopes(requested, allowed, clientScopes []string, serverDB *gorm.DB, userID string, groups []string) []string {
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		scope = cleanScopePath(scope)
		var candidates []string
		switch {
		case scope == "pelican.transfer":
			if transferAccessAllowed(serverDB, userID, groups) {
				candidates = []string{scope}
			}
		case isStandardScope(scope) || scopeAllowed(scope, allowed):
			candidates = []string{scope}
		default:
			candidates = collectNarrowerScopes(scope, allowed)
		}
		for _, candidate := range candidates {
			if scopeAllowed(candidate, clientScopes) {
				granted = append(granted, candidate)
			}
		}
	}
	return granted
}
