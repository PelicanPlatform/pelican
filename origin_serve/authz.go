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

package origin_serve

import (
	"context"
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
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	authConfig struct {
		exports    atomic.Pointer[[]server_utils.OriginExport]
		issuers    atomic.Pointer[map[string]bool]
		issuerKeys *ttlcache.Cache[string, authConfigItem]
		tokenAuthz *ttlcache.Cache[string, acls]
	}

	authConfigItem struct {
		set jwk.Set
		err error
	}

	acls []token_scopes.ResourceScope
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

	ac.tokenAuthz = ttlcache.New[string, acls](
		ttlcache.WithTTL[string, acls](5*time.Minute),
		ttlcache.WithLoader[string, acls](ttlcache.LoaderFunc[string, acls](ac.loader)),
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
		err = errors.Wrap(err, "failed to parse incoming JWT when authorizing request")
		return
	}
	issuer = tok.Issuer()

	issuers := ac.issuers.Load()
	if !(*issuers)[issuer] {
		err = errors.Errorf("token issuer %s is not one of the trusted issuers", issuer)
		log.Warningf("%s; trusted issuers: %v", err, *issuers)
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
		return
	}

	err = jwt.Validate(tok)
	if err != nil {
		err = errors.Wrap(err, "unable to get resource scopes because validation failed")
		return
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

			// Use path-aware prefix matching:
			// Token resource /foo/bar authorizes paths under export /foo
			// Export /foo/bar can be authorized by token resource /foo or /foo/bar
			if hasPathPrefix(export.FederationPrefix, resource.Resource) || hasPathPrefix(resource.Resource, export.FederationPrefix) {
				newAcls = append(newAcls, resource)
			}
		}
	}
	return
}

func (ac *authConfig) loader(cache *ttlcache.Cache[string, acls], token string) *ttlcache.Item[string, acls] {
	acls, err := ac.getAcls(token)
	if err != nil {
		// If the token is not a valid one signed by a known issuer, do not keep it in memory (avoids a DoS)
		log.Warningln("Rejecting invalid token:", err)
		return nil
	}

	item := cache.Set(token, acls, ttlcache.DefaultTTL)
	return item
}

func (ac *authConfig) authorize(action token_scopes.TokenScope, resource, token string) bool {
	aclsItem := ac.tokenAuthz.Get(token)
	if aclsItem == nil {
		return false
	}
	rsScope := token_scopes.NewResourceScope(action, resource)
	for _, acl := range aclsItem.Value() {
		if acl.Contains(rsScope) {
			return true
		}
	}
	return false
}

// authorizeWithContext checks authorization and extracts user/group info from token
func (ac *authConfig) authorizeWithContext(ctx context.Context, action token_scopes.TokenScope, resource, token string) (context.Context, bool) {
	aclsItem := ac.tokenAuthz.Get(token)
	if aclsItem == nil {
		return ctx, false
	}

	rsScope := token_scopes.NewResourceScope(action, resource)
	authorized := false
	for _, acl := range aclsItem.Value() {
		if acl.Contains(rsScope) {
			authorized = true
			break
		}
	}

	if !authorized {
		return ctx, false
	}

	// Extract user and group information from the token
	ui := extractUserInfoFromToken(token)
	ctx = setUserInfo(ctx, ui)

	return ctx, true
}

// extractUserInfoFromToken extracts user and group information from a JWT token
func extractUserInfoFromToken(tokenStr string) *userInfo {
	ui := &userInfo{
		User:   "nobody",
		Groups: []string{},
	}

	tok, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		log.Debugf("Failed to parse token for user info extraction: %v", err)
		return ui
	}

	// Extract subject (user)
	if sub := tok.Subject(); sub != "" {
		ui.User = sub
	}

	// Extract groups from various possible claim names
	// Try "wlcg.groups" first (WLCG tokens)
	if groups, ok := tok.Get("wlcg.groups"); ok {
		if groupList, ok := groups.([]interface{}); ok {
			for _, g := range groupList {
				if groupStr, ok := g.(string); ok {
					ui.Groups = append(ui.Groups, groupStr)
				}
			}
		}
	}

	// Try "groups" (generic claim)
	if len(ui.Groups) == 0 {
		if groups, ok := tok.Get("groups"); ok {
			if groupList, ok := groups.([]interface{}); ok {
				for _, g := range groupList {
					if groupStr, ok := g.(string); ok {
						ui.Groups = append(ui.Groups, groupStr)
					}
				}
			}
		}
	}

	return ui
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
