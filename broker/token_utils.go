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

package broker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
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

var (
	// A thread-safe cache for the namespace public keys
	namespaceKeys *ttlcache.Cache[string, *jwk.Cache]
)

// Launches a background goroutine that periodically expires
// the namespace key cache
func LaunchNamespaceKeyMaintenance(ctx context.Context, egrp *errgroup.Group) {
	loader := ttlcache.LoaderFunc[string, *jwk.Cache](
		func(cache *ttlcache.Cache[string, *jwk.Cache], prefix string) *ttlcache.Item[string, *jwk.Cache] {
			iss, err := getRegistryIssValue(prefix)
			if err != nil {
				return nil
			}
			// The actual location of the JWKS at the registry
			jwksUrl := iss + "/.well-known/issuer.jwks"

			ar := jwk.NewCache(ctx)
			client := &http.Client{Transport: config.GetTransport()}
			if err = ar.Register(jwksUrl, jwk.WithMinRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
				return nil
			}
			log.Debugln("Setting public key cache for issuer", iss)
			item := cache.Set(prefix, ar, ttlcache.DefaultTTL)
			return item
		},
	)
	namespaceKeys = ttlcache.New[string, *jwk.Cache](
		ttlcache.WithTTL[string, *jwk.Cache](15*time.Minute),
		ttlcache.WithLoader[string, *jwk.Cache](loader),
	)

	go namespaceKeys.Start()
	egrp.Go(func() error {
		<-ctx.Done()
		namespaceKeys.Stop()
		namespaceKeys.DeleteAll()
		return nil
	})
}

// Given a namespace prefix, return the value that should be used
// by the `iss` claim in a token for this federation's registry.
func getRegistryIssValue(prefix string) (iss string, err error) {
	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return
	}
	namespaceUrlStr := fedInfo.NamespaceRegistrationEndpoint
	if namespaceUrlStr == "" {
		err = errors.New("namespace URL is not set")
		return
	}
	namespaceUrl, err := url.Parse(namespaceUrlStr)
	if err != nil {
		return
	}
	namespaceUrl.Path, err = url.JoinPath(namespaceUrl.Path, "api", "v1.0", "registry", prefix)
	if err != nil {
		return
	}
	iss = namespaceUrl.String()
	return
}

// Given a namespace prefix, return the value for the `iss` claim and
// the public keyset to use
func getRegistryIssuerInfo(ctx context.Context, prefix string) (iss string, keyset jwk.Set, err error) {
	if iss, err = getRegistryIssValue(prefix); err != nil {
		return
	}

	// The actual location of the JWKS at the registry
	jwksUrl := iss + "/.well-known/issuer.jwks"

	item := namespaceKeys.Get(prefix)
	if item.Value() != nil {
		keyset, err = item.Value().Get(ctx, jwksUrl)
	}
	return
}

// Create a signed JWT appropriate for retrieving requests from the connection broker
func createToken(namespace, subject, audience string, desiredScope token_scopes.TokenScope) (tokenStr string, err error) {
	issuerUrl, err := getRegistryIssValue(namespace)
	if err != nil {
		return
	}

	tokenCfg := token.NewWLCGToken()
	tokenCfg.Lifetime = time.Minute
	tokenCfg.Issuer = issuerUrl
	tokenCfg.Subject = subject
	tokenCfg.AddAudiences(audience)
	tokenCfg.AddScopes(desiredScope)
	tokenStr, err = tokenCfg.CreateToken()

	return
}

func getCacheHostnameFromToken(token []byte) (hostname string, err error) {
	tok, err := jwt.Parse(token, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return
	}
	iss := tok.Issuer()
	expectedPrefix, err := getRegistryIssValue(server_structs.CachePrefix.String())
	if err != nil {
		return
	}
	hostname, hasPrefix := strings.CutPrefix(iss, expectedPrefix)
	if !hasPrefix {
		err = errors.Errorf("Token issuer %s doesn't start with expected registry issuer %s", iss, expectedPrefix)
		return
	}
	return
}

// Given a token and a namespace prefix, determine if it has the desired scope
// and audience.
func verifyToken(ctx context.Context, token, namespace, audience string, requiredScope token_scopes.TokenScope) (ok bool, err error) {
	issuerUrl, keyset, err := getRegistryIssuerInfo(ctx, namespace)
	if err != nil {
		return
	}

	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(keyset), jwt.WithValidate(true))
	if err != nil {
		return
	}

	scopeValidator := token_scopes.CreateScopeValidator([]token_scopes.TokenScope{requiredScope}, false)
	err = jwt.Validate(tok,
		jwt.WithAudience(audience),
		jwt.WithValidator(scopeValidator),
		jwt.WithClaimValue("iss", issuerUrl),
	)
	if err == nil {
		ok = true
	}
	return
}
