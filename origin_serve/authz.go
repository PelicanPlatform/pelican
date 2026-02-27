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
	"net/http"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	authConfig struct {
		exports    atomic.Pointer[[]server_utils.OriginExport]
		issuers    atomic.Pointer[map[string]bool]
		audiences  []string // accepted audience values (origin URL + wildcards)
		issuerKeys *ttlcache.Cache[string, authConfigItem]
		tokenAuthz *ttlcache.Cache[string, cachedTokenInfo]
		userMapper *UserMapper // Maps JWT claims to local users/groups
	}

	authConfigItem struct {
		set jwk.Set
		err error
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
	// origin are honoured.
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

	ac.userMapper = NewUserMapper(usernameClaim, groupsClaim, mapfilePath)

	// Start periodic mapfile refresh if configured
	refreshInterval := param.Origin_UserMapfileRefreshInterval.GetDuration()
	ac.userMapper.StartPeriodicRefresh(refreshInterval)

	loader := ttlcache.LoaderFunc[string, authConfigItem](
		func(cache *ttlcache.Cache[string, authConfigItem], issuerUrl string) *ttlcache.Item[string, authConfigItem] {
			var ar *jwk.Cache
			jwksUrl, err := token.LookupIssuerJwksUrl(ctx, issuerUrl)
			if err != nil {
				log.Errorln("Failed to lookup JWKS URL:", err)
			} else {
				ar = jwk.NewCache(ctx)
				client := &http.Client{Transport: config.GetBasicTransport()}
				if err = ar.Register(jwksUrl.String(), jwk.WithMinRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
					log.Errorln("Failed to register JWKS URL with cache: ", err)
				} else {
					log.Debugln("Setting public key cache for issuer", issuerUrl)
				}
			}

			ttl := ttlcache.DefaultTTL
			var item *ttlcache.Item[string, authConfigItem]
			if ar != nil {
				item = cache.Set(issuerUrl, authConfigItem{set: jwk.NewCachedSet(ar, jwksUrl.String()), err: nil}, ttl)
			} else {
				ttl = time.Duration(5 * time.Minute)
				item = cache.Set(issuerUrl, authConfigItem{set: nil, err: err}, ttl)
			}
			return item
		},
	)
	ac.issuerKeys = ttlcache.New[string, authConfigItem](
		ttlcache.WithTTL[string, authConfigItem](15*time.Minute),
		ttlcache.WithLoader[string, authConfigItem](ttlcache.NewSuppressedLoader[string, authConfigItem](loader, nil)),
	)

	ac.tokenAuthz = ttlcache.New[string, cachedTokenInfo](
		ttlcache.WithTTL[string, cachedTokenInfo](5*time.Minute),
		ttlcache.WithLoader[string, cachedTokenInfo](ttlcache.LoaderFunc[string, cachedTokenInfo](ac.loader)),
	)

	egrp.Go(func() error {
		ac.issuerKeys.Start()
		return nil
	})
	egrp.Go(func() error {
		ac.tokenAuthz.Start()
		return nil
	})
	egrp.Go(func() error {
		<-ctx.Done()
		ac.issuerKeys.Stop()
		ac.issuerKeys.DeleteAll()
		ac.tokenAuthz.Stop()
		ac.tokenAuthz.DeleteAll()
		return nil
	})

	return
}

func (ac *authConfig) updateConfig(exports []server_utils.OriginExport) error {
	issuers := make(map[string]bool)
	for _, export := range exports {
		for _, issuer := range export.IssuerUrls {
			issuers[issuer] = true
		}
	}
	ac.issuers.Store(&issuers)
	ac.exports.Store(&exports)
	return nil
}

func (ac *authConfig) getResourceScopes(token string) (scopes []token_scopes.ResourceScope, issuer string, err error) {
	if token == "" {
		return
	}

	tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false))
	if err != nil {
		// Failed to parse token - mark as unverified since we couldn't verify it
		tokenErr := NewTokenValidationError("failed to parse incoming JWT when authorizing request").
			WithVerified(false).
			WithDetails(err.Error())
		err = tokenErr
		return
	}
	issuer = tok.Issuer()

	issuers := ac.issuers.Load()
	if !(*issuers)[issuer] {
		// Token was parsed without verification (jwt.WithVerify(false)), so issuer is unverified
		tokenErr := NewTokenValidationError("token issuer is not one of the trusted issuers").
			WithIssuer(issuer).
			WithVerified(false).
			WithDetails(fmt.Sprintf("trusted issuers: %v", *issuers))
		log.Warningln(tokenErr.String())
		err = tokenErr
		return
	}

	issuerConfItem := ac.issuerKeys.Get(issuer)
	if issuerConfItem == nil {
		err = errors.Errorf("unable to determine keys for issuer %s", issuer)
		return
	}

	issuerConf := issuerConfItem.Value()
	if issuerConf.err != nil {
		err = issuerConf.err
		return
	}

	item := issuerConfItem.Value()
	if item.set == nil {
		if item.err != nil {
			err = item.err
		} else {
			err = errors.Errorf("failed to fetch public key set")
		}
		return
	}
	tok, err = jwt.Parse([]byte(token), jwt.WithKeySet(item.set))
	if err != nil {
		// Token signature verification failed - mark as unverified
		tokenErr := NewTokenValidationError("failed to verify token signature").
			WithVerified(false).
			WithDetails(err.Error())
		err = tokenErr
		return
	}

	err = jwt.Validate(tok)
	if err != nil {
		// Token was cryptographically verified but validation (exp, nbf, etc) failed
		// Mark as verified since we successfully checked the signature
		tokenErr := NewTokenValidationError("unable to get resource scopes because validation failed").
			WithVerified(true).
			WithIssuer(issuer).
			WithSubject(tok.Subject()).
			WithDetails(err.Error())
		err = tokenErr
		return
	}

	// Validate the audience claim.  The WLCG Common JWT Profile and
	// SciTokens specifications require that the resource server check
	// the "aud" claim against its own identity (Origin.TokenAudience)
	// or the recognised wildcard values.
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

func (ac *authConfig) loader(cache *ttlcache.Cache[string, cachedTokenInfo], token string) *ttlcache.Item[string, cachedTokenInfo] {
	acls, err := ac.getAcls(token)
	if err != nil {
		// If the token is not a valid one signed by a known issuer, do not keep it in memory (avoids a DoS)
		log.Warningln("Rejecting invalid token:", err)
		return nil
	}

	// Extract issuer from the token
	issuer := ""
	if tok, err := jwt.Parse([]byte(token), jwt.WithVerify(false)); err == nil {
		issuer = tok.Issuer()
	}

	// Extract user information from the token at cache time (only once)
	// Use the UserMapper to map JWT claims to local users/groups
	userInfo := ac.userMapper.MapTokenToUser(token)

	info := cachedTokenInfo{
		Scopes:   acls,
		UserInfo: userInfo,
		Issuer:   issuer,
	}
	item := cache.Set(token, info, ttlcache.DefaultTTL)
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
