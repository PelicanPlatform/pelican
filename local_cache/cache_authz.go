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
	"context"
	"fmt"
	"path"
	"slices"
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	authConfig struct {
		ns      atomic.Pointer[[]server_structs.NamespaceAd]
		issuers atomic.Pointer[map[string]bool]
		// ctx bounds key fetches.  They are shared between requests, so they
		// must not be tied to whichever request happened to trigger one.
		ctx        context.Context
		issuerKeys *token.JwksCache
		tokenAuthz *ttlcache.Cache[string, authzResult]
	}

	acls []token_scopes.ResourceScope

	// authzResult is the cached authorization result for a given token.
	// It contains the computed access-control list (scopes) and an
	// optional string describing why the token was not fully trusted
	// (e.g. "token validation failed: token issuer X is not one of the
	// trusted issuers").
	// When tokenError is non-empty the scopes only contain public
	// namespace grants.  The full underlying error is included to
	// provide actionable deny reasons while avoiding direct exposure
	// of sensitive token details.
	authzResult struct {
		scopes     acls
		tokenError string // human-readable reason the token was rejected (empty when OK)
	}
)

// tokenAuthzTTL is the maximum lifetime of a cached token-authorization
// result.  Individual entries may be given a shorter TTL when the token
// itself expires sooner.
const tokenAuthzTTL = 5 * time.Minute

func newAuthConfig(ctx context.Context, egrp *errgroup.Group) (ac *authConfig) {
	ac = &authConfig{}

	// Issuer keys are fetched and aged by the shared cache, which serves the
	// last keys it retrieved through an issuer outage and stops trusting them
	// once they are too old to confirm.  The key space here comes from the
	// namespaces the director advertises rather than from a request, so no
	// capacity bound is needed.
	ac.ctx = ctx
	ac.issuerKeys = token.NewJwksCache(ctx, egrp)

	// Touch-on-hit must stay disabled: the token's exp is only checked in the
	// loader, so letting a Get refresh the entry would keep an actively-used
	// token authorized indefinitely past its expiry.
	ac.tokenAuthz = ttlcache.New[string, authzResult](
		ttlcache.WithTTL[string, authzResult](tokenAuthzTTL),
		ttlcache.WithDisableTouchOnHit[string, authzResult](),
		ttlcache.WithLoader[string, authzResult](ttlcache.LoaderFunc[string, authzResult](ac.loader)),
	)

	egrp.Go(func() error {
		ac.tokenAuthz.Start()
		return nil
	})
	egrp.Go(func() error {
		<-ctx.Done()
		ac.tokenAuthz.Stop()
		ac.tokenAuthz.DeleteAll()
		return nil
	})

	return
}

// issuerJwksResolver locates an issuer's JWKS through OIDC discovery.
func issuerJwksResolver(issuerUrl string) token.JwksUrlResolver {
	return func(ctx context.Context) (string, error) {
		jwksUrl, err := token.LookupIssuerJwksUrl(ctx, issuerUrl)
		if err != nil {
			return "", errors.Wrapf(err, "failed to look up the JWKS URL for issuer %s", issuerUrl)
		}
		return jwksUrl.String(), nil
	}
}

func (ac *authConfig) updateConfig(nsAds []server_structs.NamespaceAd) error {
	issuers := make(map[string]bool)
	for _, nsAd := range nsAds {
		for _, issuer := range nsAd.Issuer {
			issuers[issuer.IssuerUrl.String()] = true
		}
	}

	// Only invalidate the cached token ACLs when the namespace list
	// actually changed.  The periodic poll runs every minute and
	// almost always returns the same list; invalidating every time
	// would flush the cache needlessly.
	oldNs := ac.ns.Load()
	changed := oldNs == nil || !nsAdsAuthzEqual(*oldNs, nsAds)

	ac.issuers.Store(&issuers)
	ac.ns.Store(&nsAds)

	if changed && ac.tokenAuthz != nil {
		ac.tokenAuthz.DeleteAll()
	}
	return nil
}

// nsAdsAuthzEqual reports whether two namespace-ad slices are semantically
// identical for authorization purposes (paths, capabilities, and issuer
// configuration).
func nsAdsAuthzEqual(old, new []server_structs.NamespaceAd) bool {
	if len(old) != len(new) {
		return false
	}
	// Build map keyed by path for O(n) comparison.
	oldByPath := make(map[string]int, len(old))
	for i := range old {
		oldByPath[old[i].Path] = i
	}
	for i := range new {
		oi, ok := oldByPath[new[i].Path]
		if !ok {
			return false
		}
		o := &old[oi]
		n := &new[i]
		if o.Caps.PublicReads != n.Caps.PublicReads ||
			o.Caps.Reads != n.Caps.Reads ||
			o.Caps.Writes != n.Caps.Writes {
			return false
		}
		if len(o.Issuer) != len(n.Issuer) {
			return false
		}
		for j := range o.Issuer {
			if o.Issuer[j].IssuerUrl.String() != n.Issuer[j].IssuerUrl.String() {
				return false
			}
			if !slices.Equal(o.Issuer[j].BasePaths, n.Issuer[j].BasePaths) {
				return false
			}
			if !slices.Equal(o.Issuer[j].RestrictedPaths, n.Issuer[j].RestrictedPaths) {
				return false
			}
		}
	}
	return true
}

func (ac *authConfig) getResourceScopes(tokenStr string) (scopes []token_scopes.ResourceScope, issuer string, err error) {
	if tokenStr == "" {
		return
	}

	tok, err := token.UnsafeParseClaims(tokenStr)
	if err != nil {
		err = errors.Wrap(err, "failed to parse incoming JWT when authorizing request")
		return
	}
	issuer = tok.Issuer()

	issuers := ac.issuers.Load()
	if !(*issuers)[issuer] {
		err = errors.Errorf("token issuer %s is not one of the trusted issuers", issuer)
		return
	}

	if ac.issuerKeys == nil {
		err = errors.New("issuer key cache is not initialized")
		return
	}
	keyset, err := ac.issuerKeys.Keys(ac.ctx, issuer, issuerJwksResolver(issuer))
	if err != nil {
		err = errors.Wrapf(err, "unable to determine keys for issuer %s", issuer)
		return
	}

	tok, err = token.VerifyWithKeyset(tokenStr, keyset)
	if err != nil {
		err = errors.Wrap(err, "unable to get resource scopes because verification failed")
		return
	}

	scopes = token_scopes.ParseResourceScopeString(tok)

	return
}

func calcResourceScopes(rs token_scopes.ResourceScope, basePaths []string, restrictedPaths []string) (results []token_scopes.ResourceScope) {
	results = make([]token_scopes.ResourceScope, 0)
	for _, basePath := range basePaths {
		if len(restrictedPaths) == 0 {
			results = append(results, token_scopes.NewResourceScope(rs.Authorization, path.Join(basePath, rs.Resource)))
		} else {
			for _, restrictedPath := range restrictedPaths {
				tmpResource := token_scopes.NewResourceScope(rs.Authorization, restrictedPath)
				if tmpResource.Contains(rs) {
					// E.g., restricted_path=/foo, token scope is storage.read:/foo/bar; generate ACL of storage.read:/foo/bar
					results = append(results, token_scopes.NewResourceScope(rs.Authorization, path.Join(basePath, rs.Resource)))
				} else if rs.Contains(tmpResource) {
					// E.g., restricted_path=/foo, token scope is storage.read:/; generate ACL of storage.read:/foo
					results = append(results, token_scopes.NewResourceScope(rs.Authorization, path.Join(basePath, tmpResource.Resource)))
				}
			}
		}
	}
	return
}

// Given a token, calculate the corresponding access control list
//
// The returned ACLs indicate what the bearer of the token is authorized (read, write)
// to do with respect to the root of the cache.  For example, if /foo is
// labeled as a public prefix by the director, then one ACL returned will
// be read:/foo.
//
// Public namespaces always grant read ACLs regardless of the token's
// validity.  An invalid or untrusted token only prevents private-namespace
// ACLs from being generated; it is not an error.
func (ac *authConfig) getAcls(token string) (newAcls acls, tokenTrusted bool, err error) {
	namespaces := ac.ns.Load()
	if namespaces == nil {
		return
	}
	resources, issuer, tokenErr := ac.getResourceScopes(token)
	tokenTrusted = (tokenErr == nil)
	if tokenErr != nil && token != "" {
		log.Debugln("Token validation failed (public ACLs still granted):", tokenErr)
	}

	newAcls = make(acls, 0)
	for _, conf := range *namespaces {
		if conf.Caps.PublicReads {
			newAcls = append(newAcls, token_scopes.ResourceScope{Authorization: token_scopes.Wlcg_Storage_Read, Resource: conf.Path})
		}
		// Check token-based permissions for non-public namespaces, or
		// for public-reads namespaces that also support writes (the
		// public-reads grant above only covers reads).
		if tokenTrusted && conf.Issuer != nil && (!conf.Caps.PublicReads || conf.Caps.Writes) {
			for _, resource := range resources {
				if (resource.Authorization == token_scopes.Wlcg_Storage_Create || resource.Authorization == token_scopes.Wlcg_Storage_Modify) && !conf.Caps.Writes {
					continue
				}
				if resource.Authorization == token_scopes.Wlcg_Storage_Read && !conf.Caps.Reads && !conf.Caps.PublicReads {
					continue
				}
				// For public-reads namespaces, skip adding redundant read ACLs from the token
				if conf.Caps.PublicReads && resource.Authorization == token_scopes.Wlcg_Storage_Read {
					continue
				}
				for _, issuerConfig := range conf.Issuer {
					if issuerConfig.IssuerUrl.String() != issuer {
						continue
					}
					newAcls = append(newAcls, calcResourceScopes(resource, issuerConfig.BasePaths, issuerConfig.RestrictedPaths)...)
				}
			}
		}
	}
	return
}

func (ac *authConfig) loader(cache *ttlcache.Cache[string, authzResult], tokenStr string) *ttlcache.Item[string, authzResult] {
	newAcls, tokenTrusted, tokenValidationErr := ac.getAcls(tokenStr)
	if tokenValidationErr != nil && tokenStr == "" {
		// Non-token-related error (e.g., namespace config issue) should
		// be logged and result in a nil return.
		log.Warningln("Failed to compute ACLs:", tokenValidationErr)
		return nil
	}

	var tokenError string
	if !tokenTrusted && tokenStr != "" {
		// Include a human-readable reason so authorize() can return actionable
		// deny reasons.  The underlying error is not exposed in full to avoid
		// sensitive data leakage, but we include enough detail to be useful.
		if tokenValidationErr != nil {
			tokenError = fmt.Sprintf("token validation failed: %v", tokenValidationErr)
		} else {
			tokenError = "token validation failed"
		}
	} else if tokenStr == "" {
		// No token provided — public ACLs only.
		tokenError = "no token provided"
	}

	// Use a shorter TTL for unrecognized tokens to bound memory usage
	// from attackers sending many junk tokens (DoS mitigation).
	ttl := ttlcache.DefaultTTL
	if !tokenTrusted && tokenStr != "" {
		ttl = 30 * time.Second
	} else if tokenTrusted {
		// Cap the cache entry's lifetime at the token's own expiry (plus the
		// clock-skew leeway the verifier grants) so the cached authorization
		// never outlives the token itself.  getAcls has already verified the
		// token's signature, so the claims can be trusted despite the unsafe
		// parse.
		if tok, err := token.UnsafeParseClaims(tokenStr); err == nil {
			if exp := tok.Expiration(); !exp.IsZero() {
				remaining := time.Until(exp) + token.ClockSkewLeeway
				if remaining <= 0 {
					log.Warningln("Rejecting expired token")
					return nil
				}
				if remaining < tokenAuthzTTL {
					ttl = remaining
				}
			}
		}
	}

	item := cache.Set(tokenStr, authzResult{scopes: newAcls, tokenError: tokenError}, ttl)
	return item
}

// authorize checks whether the given token grants the requested action on
// the resource.  It returns whether access is granted and a human-readable
// reason when it is denied.
func (ac *authConfig) authorize(action token_scopes.TokenScope, resource, token string) (bool, string) {
	aclsItem := ac.tokenAuthz.Get(token)
	if aclsItem == nil {
		if token == "" {
			return false, "no token provided and namespace requires authorization"
		}
		return false, "failed to compute authorization for token"
	}
	result := aclsItem.Value()
	rsScope := token_scopes.NewResourceScope(action, resource)
	if slices.ContainsFunc(result.scopes, func(rs token_scopes.ResourceScope) bool { return rs.Contains(rsScope) }) {
		return true, ""
	}
	// Access denied — build a reason.
	if result.tokenError != "" {
		return false, result.tokenError
	}
	return false, fmt.Sprintf("token scopes insufficient for %s on %s", action, resource)
}
