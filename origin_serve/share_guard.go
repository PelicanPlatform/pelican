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

package origin_serve

// Multi-user backend guard for share access. The collection-share
// design (docs/collections-design.md) explicitly excludes XRootD
// POSIX / multi-user backends:
//
//   "When the multiuser backend interacts with a token generated for
//    the share, it must interact as the owner of the share, not the
//    owner of the token. ...Not supported for XRootD-based POSIX /
//    multi-user backends."
//
// Phase 3 of the share rollout (origin/collections.go's
// handleCreateCollectionShare) refuses share creation up front when
// `Origin.Multiuser` is true, so a multi-user origin should never
// see a `share.access:/$ID` token in the first place. This file is
// the defense-in-depth layer: if an operator flips multi-user on
// AFTER shares already exist, any leftover share tokens — already
// minted by oa4mp before the flip — must not be allowed to
// successfully bypass the per-user identity remapping the multi-user
// backend is supposed to enforce.
//
// The check happens at the bearer-token-to-user mapping seam
// (MapTokenToUser): when a token carrying share.access reaches a
// multiuser-mode origin, we deny the request rather than silently
// fall back to the token bearer's identity (which, for a share, is
// NOT the user the data should be served as).

import (
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// tokenCarriesShareAccess reports whether the JWT carries any
// `share.access:/...` scope. Parses without verification; the caller
// is expected to have verified the signature elsewhere — we're only
// inspecting the claim set to make a routing decision.
//
// Scope claims follow the WLCG profile: a single space-separated
// string in the `scope` claim. Any matching token returns true
// regardless of which share ID the scope is bound to.
func tokenCarriesShareAccess(tokenStr string) bool {
	if tokenStr == "" {
		return false
	}
	tok, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		// Malformed; let the upstream verifier reject. We refuse to
		// guess at a partial parse here.
		return false
	}
	raw, ok := tok.Get("scope")
	if !ok {
		return false
	}
	scopeStr, ok := raw.(string)
	if !ok {
		return false
	}
	prefix := token_scopes.Share_Access.String() + ":"
	for _, s := range strings.Fields(scopeStr) {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// shareTokenForbiddenInMultiuser returns true when the supplied
// token MUST be refused at this origin: i.e. the origin is in
// multi-user mode AND the token carries a share.access scope. The
// caller (MapTokenToUser) drops the request with no fallback when
// this returns true — silently using the bearer's identity would
// violate the design contract that share data be served as the
// share OWNER, not the recipient.
func shareTokenForbiddenInMultiuser(tokenStr string) bool {
	if !param.Origin_Multiuser.GetBool() {
		return false
	}
	if !tokenCarriesShareAccess(tokenStr) {
		return false
	}
	log.Warn("Refusing request: share.access token presented at a multi-user origin (shares are unsupported on multi-user backends per docs/collections-design.md)")
	return true
}
