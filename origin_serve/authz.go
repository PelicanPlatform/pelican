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

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	authConfig struct {
		exports atomic.Pointer[[]server_utils.OriginExport]
		// nsAds is exports rendered as namespace ads, derived once per config
		// change rather than per request: SetTokenHintHeaders runs on every
		// request a standalone origin serves, and rebuilding the ads there costs
		// a url.Parse per issuer per request.  Swapped together with exports.
		nsAds     atomic.Pointer[[]server_structs.NamespaceAd]
		issuers   atomic.Pointer[map[string]bool]
		audiences []string // accepted audience values (origin URL + wildcards)
		// ctx bounds key fetches.  They are shared between requests, so they
		// must not be tied to whichever request happened to trigger one.
		ctx        context.Context
		issuerKeys *token.JwksCache
		tokenAuthz *ttlcache.Cache[string, cachedTokenInfo]
		userMapper *UserMapper // Maps JWT claims to local users/groups
	}

	// cachedTokenInfo stores authorization scopes, user info, and issuer for a token
	cachedTokenInfo struct {
		Scopes   []token_scopes.ResourceScope
		UserInfo *userInfo
		Issuer   string
	}

	acls []token_scopes.ResourceScope

	// issuerContextKey is the typed key for storing token issuer in context
	issuerContextKey struct{}
)

var globalAuthConfig *authConfig

// tokenAuthzTTL is the maximum lifetime of a cached token-authorization
// result.  Individual entries may be given a shorter TTL when the token
// itself expires sooner.
const tokenAuthzTTL = 5 * time.Minute

// hasPathPrefix checks if the request path is under the authorized prefix.
// Unlike strings.HasPrefix, this checks path boundaries to prevent
// access to /foo/bar2 when only /foo/bar is authorized.
func hasPathPrefix(requestPath, authorizedPrefix string) bool {
	// Clean both paths to normalize them
	requestPath = path.Clean(requestPath)
	authorizedPrefix = path.Clean(authorizedPrefix)

	// Exact match is always allowed
	if requestPath == authorizedPrefix {
		return true
	}

	// Ensure authorizedPrefix ends with / for comparison
	if !strings.HasSuffix(authorizedPrefix, "/") {
		authorizedPrefix += "/"
	}

	// Check if requestPath starts with authorizedPrefix
	return strings.HasPrefix(requestPath, authorizedPrefix)
}

func newAuthConfig(ctx context.Context, egrp *errgroup.Group) (ac *authConfig) {
	ac = &authConfig{}

	// Build the set of accepted audience values.
	// The WLCG Common JWT Profile and SciTokens specs each define a
	// wildcard audience ("https://wlcg.cern.ch/jwt/v1/any" and "ANY"
	// respectively) that must always be accepted.  In addition, the
	// origin's own URL (Origin.TokenAudience, which defaults to
	// Origin.Url) is accepted so that tokens scoped to this specific
	// origin are honored.
	ac.audiences = []string{
		"https://wlcg.cern.ch/jwt/v1/any", // WLCG wildcard
		"ANY",                             // SciTokens wildcard
	}
	if tokenAud := param.Origin_TokenAudience.GetString(); tokenAud != "" {
		ac.audiences = append(ac.audiences, tokenAud)
	}

	// Initialize UserMapper for mapping JWT claims to local users/groups
	// Read configuration from parameters
	usernameClaim := param.Origin_ScitokensUsernameClaim.GetString()
	if usernameClaim == "" {
		usernameClaim = "sub" // fallback to default
	}

	groupsClaim := param.Origin_ScitokensGroupsClaim.GetString()
	if groupsClaim == "" {
		groupsClaim = "wlcg.groups" // fallback to default
	}

	mapfilePath := param.Origin_ScitokensNameMapFile.GetString()

	defaultUser := param.Origin_ScitokensDefaultUser.GetString()
	unauthenticatedUser := param.Origin_ScitokensUnauthenticatedUser.GetString()

	ac.userMapper = NewUserMapper(usernameClaim, groupsClaim, mapfilePath, defaultUser, unauthenticatedUser)

	// Start periodic mapfile refresh if configured
	refreshInterval := param.Origin_UserMapfileRefreshInterval.GetDuration()
	ac.userMapper.StartPeriodicRefresh(refreshInterval)

	// Issuer keys are fetched and aged by the shared cache, which serves the
	// last keys it retrieved through an issuer outage and stops trusting them
	// once they are too old to confirm.  The key space here comes from the
	// export configuration rather than from a request, so no capacity bound is
	// needed.
	ac.ctx = ctx
	ac.issuerKeys = token.NewJwksCache(ctx, egrp)

	// Touch-on-hit must stay disabled: the token's exp is only checked in the
	// loader, so letting a Get refresh the entry would keep an actively-used
	// token authorized indefinitely past its expiry.
	ac.tokenAuthz = ttlcache.New[string, cachedTokenInfo](
		ttlcache.WithTTL[string, cachedTokenInfo](tokenAuthzTTL),
		ttlcache.WithDisableTouchOnHit[string, cachedTokenInfo](),
		ttlcache.WithLoader[string, cachedTokenInfo](ttlcache.LoaderFunc[string, cachedTokenInfo](ac.loader)),
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

func (ac *authConfig) updateConfig(exports []server_utils.OriginExport) error {
	issuers := make(map[string]bool)
	for _, export := range exports {
		for _, issuer := range export.IssuerUrls {
			issuers[issuer] = true
		}
	}
	// An export whose issuer URL will not parse cannot produce token hints, but
	// it can still be authorized against; keep the rest of the config current and
	// leave the ads empty rather than refusing to serve.
	nsAds, err := server_utils.NamespaceAdsFromExports(exports)
	if err != nil {
		log.Warningf("Unable to derive namespace ads from the origin's exports; token hint headers will be omitted: %v", err)
		nsAds = nil
	}
	ac.issuers.Store(&issuers)
	ac.nsAds.Store(&nsAds)
	ac.exports.Store(&exports)
	return nil
}

func (ac *authConfig) getResourceScopes(tokenStr string) (scopes []token_scopes.ResourceScope, issuer string, err error) {
	if tokenStr == "" {
		return
	}

	tok, err := token.UnsafeParseClaims(tokenStr)
	if err != nil {
		// Failed to parse token — mark as unverified since we couldn't verify it
		tokenErr := NewTokenValidationError("failed to parse incoming JWT when authorizing request").
			WithVerified(false).
			WithDetails(err.Error())
		err = tokenErr
		return
	}
	issuer = tok.Issuer()

	issuers := ac.issuers.Load()
	trusted := (*issuers)[issuer]

	// The federation's discovery endpoint is also a trusted issuer.
	// We check it dynamically here rather than storing it in ac.issuers
	// because the discovery URL may not yet be known when updateConfig
	// runs at startup (the discovery server may start after the origin),
	// particularly in unit tests.
	//
	// We also accept DirectorEndpoint because the director may create
	// federation tokens before the canonical discovery URL has been
	// established.  This is safe because the origin's own issuer URL
	// is now a distinct sub-path when co-located with the director.
	if !trusted {
		if fedInfo, fedErr := config.GetFederation(context.Background()); fedErr == nil {
			if fedInfo.DiscoveryEndpoint != "" && issuer == fedInfo.DiscoveryEndpoint {
				trusted = true
			} else if fedInfo.DirectorEndpoint != "" && issuer == fedInfo.DirectorEndpoint {
				trusted = true
			}
		}
	}

	if !trusted {
		// The issuer was read from an unverified token, so it is unverified at this point
		trustedList := slices.Sorted(maps.Keys(*issuers))
		tokenErr := NewTokenValidationError("token issuer is not one of the trusted issuers").
			WithIssuer(issuer).
			WithVerified(false).
			WithDetails(fmt.Sprintf("trusted issuers: %s", strings.Join(trustedList, ", ")))
		log.Warningln(tokenErr.String())
		err = tokenErr
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
		// Token signature or claims validation failed — mark as unverified
		tokenErr := NewTokenValidationError("failed to verify token signature or claims").
			WithVerified(false).
			WithIssuer(issuer).
			WithDetails(err.Error())
		err = tokenErr
		return
	}

	// Validate the audience claim.  The WLCG Common JWT Profile and
	// SciTokens specifications require that the resource server check
	// the "aud" claim against its own identity (Origin.TokenAudience)
	// or the recognized wildcard values.
	tokenAuds := tok.Audience()
	if len(tokenAuds) > 0 && len(ac.audiences) > 0 {
		audOK := false
		for _, ta := range tokenAuds {
			for _, aa := range ac.audiences {
				if ta == aa {
					audOK = true
					break
				}
			}
			if audOK {
				break
			}
		}
		if !audOK {
			tokenErr := NewTokenValidationError("token audience does not match this origin").
				WithVerified(true).
				WithIssuer(issuer).
				WithSubject(tok.Subject()).
				WithDetails(fmt.Sprintf("token audiences %v, accepted audiences %v", tokenAuds, ac.audiences))
			log.Warningln(tokenErr.String())
			err = tokenErr
			return
		}
	}

	scopes = token_scopes.ParseResourceScopeString(tok)

	return
}

// SetTokenHintHeaders writes the director's X-Pelican-{Namespace,Authorization,
// Token-Generation} headers describing how a caller could obtain a token for
// resource, or does nothing if no export covers it.
//
// A federated origin never needs this: the director already told the client
// which token to get before redirecting it here.  A standalone origin has no
// director, so a client asking it for an object directly would otherwise get a
// bare rejection with no way to discover the issuer.  Emitting the same headers
// the director would lets the client (see the token-hint retry in
// client/handle_http.go) acquire the right token and try again, and lets a human
// with curl see where to authenticate.
//
// The hint is advisory: it names the credential this origin recommends, not the
// only one it will accept.  LongestNSMatch reports the single most specific
// export covering resource, while getAcls below grants access from every export
// whose issuer matches the presented token.  With exports nested one inside
// another under different issuers, a token from the outer export's issuer whose
// scope reaches the inner path is still honored even though the hint pointed at
// the inner issuer.  Narrowing that is an authorization change affecting
// federated origins equally, so it does not belong to standalone mode; until
// then, do not read these headers as a statement of what will be refused.
func (ac *authConfig) SetTokenHintHeaders(hdr http.Header, resource string) {
	nsAds := ac.nsAds.Load()
	if nsAds == nil {
		return
	}
	nsAd := server_structs.LongestNSMatch(resource, *nsAds)
	if nsAd == nil {
		return
	}
	// This origin serves its own listings, so it is its own collections URL.
	server_structs.SetXNamespaceHeaderWithCollections(hdr, param.Origin_Url.GetString(), *nsAd)
	server_structs.SetXAuthHeader(hdr, *nsAd)
	server_structs.SetXTokenGenHeader(hdr, *nsAd)
}

// Given a token, calculate the corresponding access control list
func (ac *authConfig) getAcls(token string) (newAcls acls, err error) {
	exports := ac.exports.Load()
	if exports == nil {
		return
	}
	resources, issuer, err := ac.getResourceScopes(token)
	if err != nil {
		return
	}

	newAcls = make(acls, 0)
	for _, export := range *exports {
		if export.Capabilities.PublicReads {
			newAcls = append(newAcls, token_scopes.ResourceScope{Authorization: token_scopes.Wlcg_Storage_Read, Resource: export.FederationPrefix})
		}

		// Always check token-based authorization for write operations (even if PublicReads is true)
		for _, resource := range resources {
			if (resource.Authorization == token_scopes.Wlcg_Storage_Create || resource.Authorization == token_scopes.Wlcg_Storage_Modify) && !export.Capabilities.Writes {
				continue
			}
			if resource.Authorization == token_scopes.Wlcg_Storage_Read && !export.Capabilities.Reads {
				continue
			}

			// Check if issuer is authorized for this export
			authorized := false
			for _, exportIssuer := range export.IssuerUrls {
				if exportIssuer == issuer {
					authorized = true
					break
				}
			}
			if !authorized {
				log.Debugf("Token issuer %s not authorized for export %s (export issuers: %v)", issuer, export.FederationPrefix, export.IssuerUrls)
				continue
			}

			// Token scopes are relative to the namespace (federation prefix)
			// So we need to prepend the federation prefix to the token's resource to get the full path
			fullResourcePath := path.Join(export.FederationPrefix, resource.Resource)

			// Add the scope with the full path (including federation prefix)
			fullScope := token_scopes.ResourceScope{
				Authorization: resource.Authorization,
				Resource:      fullResourcePath,
			}
			newAcls = append(newAcls, fullScope)
		}
	}
	return
}

func (ac *authConfig) loader(cache *ttlcache.Cache[string, cachedTokenInfo], tokenStr string) *ttlcache.Item[string, cachedTokenInfo] {
	acls, err := ac.getAcls(tokenStr)
	if err != nil {
		// If the token is not a valid one signed by a known issuer, do not keep it in memory (avoids a DoS)
		log.Warningln("Rejecting invalid token:", err)
		return nil
	}

	// Re-parse the claims to pick up the issuer (for logging) and the expiry.
	// getAcls has already verified the token's signature and validity, so the
	// claims can be trusted despite the unsafe parse.
	issuer := ""
	ttl := ttlcache.DefaultTTL
	if tok, err := token.UnsafeParseClaims(tokenStr); err == nil {
		issuer = tok.Issuer()
		// Cap the cache entry's lifetime at the token's own expiry (plus the
		// clock-skew leeway the verifier grants) so the cached authorization
		// never outlives the token itself.
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

	// Extract user information from the token at cache time (only once)
	// Use the UserMapper to map JWT claims to local users/groups
	userInfo := ac.userMapper.MapTokenToUser(tokenStr)
	if userInfo == nil {
		// No mapfile rule matched and no default user configured; reject the token.
		log.Warningln("Rejecting token: no mapfile rule matched and no default user configured")
		return nil
	}

	info := cachedTokenInfo{
		Scopes:   acls,
		UserInfo: userInfo,
		Issuer:   issuer,
	}
	item := cache.Set(tokenStr, info, ttl)
	return item
}

func (ac *authConfig) authorize(action token_scopes.TokenScope, resource, token string) bool {
	tokenItem := ac.tokenAuthz.Get(token)
	if tokenItem == nil {
		return false
	}
	info := tokenItem.Value()
	rsScope := token_scopes.NewResourceScope(action, resource)
	for _, acl := range info.Scopes {
		if acl.Contains(rsScope) {
			return true
		}
	}
	return false
}

// authorizeWithContext checks authorization and extracts user/group info from token
func (ac *authConfig) authorizeWithContext(ctx context.Context, action token_scopes.TokenScope, resource, token string) (context.Context, bool) {
	tokenItem := ac.tokenAuthz.Get(token)
	if tokenItem == nil {
		return ctx, false
	}

	info := tokenItem.Value()
	rsScope := token_scopes.NewResourceScope(action, resource)
	authorized := false
	for _, acl := range info.Scopes {
		if acl.Contains(rsScope) {
			authorized = true
			break
		}
	}

	if !authorized {
		return ctx, false
	}

	// User info is already extracted during cache load, just attach it to context
	ctx = setUserInfo(ctx, info.UserInfo)
	// Add issuer to context for tracking token source
	ctx = context.WithValue(ctx, issuerContextKey{}, info.Issuer)
	return ctx, true
}

// InitAuthConfig initializes the global auth config
func InitAuthConfig(ctx context.Context, egrp *errgroup.Group, exports []server_utils.OriginExport) error {
	globalAuthConfig = newAuthConfig(ctx, egrp)
	return globalAuthConfig.updateConfig(exports)
}

// GetAuthConfig returns the global auth config
func GetAuthConfig() *authConfig {
	return globalAuthConfig
}

// ShutdownAuthConfig stops the auth config's background processes
func ShutdownAuthConfig() {
	if globalAuthConfig != nil && globalAuthConfig.userMapper != nil {
		globalAuthConfig.userMapper.Shutdown()
	}
}
