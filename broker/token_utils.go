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
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	namespaceKeys      = ttlcache.New[string, *jwk.Cache](ttlcache.WithTTL[string, *jwk.Cache](15 * time.Minute))
	namespaceKeysMutex = sync.RWMutex{}
)

// Given a namespace prefix, return the value that should be used
// by the `iss` claim in a token for this federation's registry.
func getRegistryIssValue(prefix string) (iss string, err error) {
	// Calculate the correct `iss` field as part of the registry service
	namespaceUrlStr := param.Federation_RegistryUrl.GetString()
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

	var ar *jwk.Cache
	namespaceKeysMutex.RLock()
	item := namespaceKeys.Get(prefix)
	if item != nil {
		if !item.IsExpired() {
			ar = item.Value()
		}
	}
	namespaceKeysMutex.RUnlock()
	if ar == nil {
		ar = jwk.NewCache(ctx)
		client := &http.Client{Transport: config.GetTransport()}
		if err = ar.Register(jwksUrl, jwk.WithMinRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
			return
		}
		namespaceKeysMutex.Lock()
		namespaceKeys.Set(prefix, ar, ttlcache.DefaultTTL)
		namespaceKeysMutex.Unlock()
	}
	log.Debugln("Attempting to fetch public key for issuer", iss)
	keyset, err = ar.Get(ctx, jwksUrl)
	return
}

func validateScope(desiredScope token_scopes.TokenScope) func(context.Context, jwt.Token) jwt.ValidationError {
	return func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		scopeAny, ok := tok.Get("scope")
		if !ok {
			return jwt.NewValidationError(errors.New("no scope is present; required to advertise to director"))
		}
		scope, ok := scopeAny.(string)
		if !ok {
			return jwt.NewValidationError(errors.New("scope claim in token is not string-valued"))
		}

		for _, scope := range strings.Split(scope, " ") {
			if scope == desiredScope.String() {
				return nil
			}
		}
		return jwt.NewValidationError(errors.Errorf("token scope claim is missing value %s", desiredScope.String()))
	}
}

// Create a signed JWT appropriate for retrieving requests from the connection broker
func createToken(namespace, audience string, desiredScope token_scopes.TokenScope) (token string, err error) {
	issuerUrl, err := getRegistryIssValue(namespace)
	if err != nil {
		return
	}

	tok, err := jwt.NewBuilder().
		Claim("scope", desiredScope.String()).
		Issuer(issuerUrl).
		Audience([]string{audience}).
		Subject(param.Server_Hostname.GetString()).
		Expiration(time.Now().Add(time.Minute)).
		Build()
	if err != nil {
		return
	}

	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		err = errors.Wrap(err, "failed to load the origin's JWK")
		return
	}

	err = jwk.AssignKeyID(key)
	if err != nil {
		err = errors.Wrap(err, "Failed to assign kid to the token")
		return
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		return
	}
	token = string(signed)
	return
}

func getCacheHostnameFromToken(token []byte) (hostname string, err error) {
	tok, err := jwt.Parse(token, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return
	}
	iss := tok.Issuer()
	expectedPrefix, err := getRegistryIssValue("/cache")
	if err != nil {
		return
	}
	hostname, hasPrefix := strings.CutPrefix(iss, expectedPrefix)
	if !hasPrefix {
		err = errors.Errorf("Token issuer %s doesnt start with expected registry issuer %s", iss, expectedPrefix)
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

	validator := jwt.ValidatorFunc(validateScope(requiredScope))
	err = jwt.Validate(tok,
		jwt.WithAudience(param.Server_ExternalWebUrl.GetString()),
		jwt.WithValidator(validator),
		jwt.WithClaimValue("iss", issuerUrl),
	)
	if err == nil {
		ok = true
	}
	return
}
