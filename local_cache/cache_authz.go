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
	"net/http"
	"path"
	"slices"
	"sync/atomic"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	authConfig struct {
		ns         atomic.Pointer[[]server_structs.NamespaceAdV2]
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
				client := &http.Client{Transport: config.GetTransport()}
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

func (ac *authConfig) updateConfig(nsAds []server_structs.NamespaceAdV2) error {
	issuers := make(map[string]bool)
	for _, nsAd := range nsAds {
		for _, issuer := range nsAd.Issuer {
			issuers[issuer.IssuerUrl.String()] = true
		}
	}
	ac.issuers.Store(&issuers)
	ac.ns.Store(&nsAds)
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
		if item.err == nil {
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
// If the token verification fails then an error will be returned; no authorization
// should be given.
func (ac *authConfig) getAcls(token string) (newAcls acls, err error) {
	namespaces := ac.ns.Load()
	if namespaces == nil {
		return
	}
	resources, issuer, err := ac.getResourceScopes(token)
	if err != nil {
		return
	}

	newAcls = make(acls, 0)
	for _, conf := range *namespaces {
		if conf.Caps.PublicReads {
			newAcls = append(newAcls, token_scopes.ResourceScope{Authorization: token_scopes.Storage_Read, Resource: conf.Path})
		} else if conf.Issuer != nil {
			for _, resource := range resources {
				if (resource.Authorization == token_scopes.Storage_Create || resource.Authorization == token_scopes.Storage_Modify) && !conf.Caps.Writes {
					continue
				}
				if resource.Authorization == token_scopes.Storage_Read && !conf.Caps.Reads {
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
	return slices.ContainsFunc(aclsItem.Value(), func(rs token_scopes.ResourceScope) bool { return rs.Contains(rsScope) })
}
