/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
package web_ui

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	pelican_config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// Creates a validator that checks if a token's scope matches the given scope: matchScope
func createScopeValidator(matchScope string) jwt.ValidatorFunc {
	return jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		scope_any, present := tok.Get("scope")
		if !present {
			return jwt.NewValidationError(errors.New("No scope is present; required for authorization"))
		}
		scope, ok := scope_any.(string)
		if !ok {
			return jwt.NewValidationError(errors.New("scope claim in token is not string-valued"))
		}

		for _, scope := range strings.Split(scope, " ") {
			if scope == matchScope {
				return nil
			}
		}
		return jwt.NewValidationError(errors.New("Token does not contain the scope: " + matchScope))
	})
}

// Checks that the given token was signed by the federation jwk and also checks that the token has the expected scope
func FederationCheck(c *gin.Context, strToken string, expectedScope string) {
	var bKey *jwk.Key

	fedURL := param.Federation_DiscoveryUrl.GetString()
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))

	if err != nil {
		return
	}

	if fedURL == token.Issuer() {
		err := pelican_config.DiscoverFederation()
		if err != nil {
			return
		}
		fedURIFile := param.Federation_JwkUrl.GetString()
		response, err := http.Get(fedURIFile)
		if err != nil {
			return
		}
		defer response.Body.Close()
		contents, err := io.ReadAll(response.Body)
		if err != nil {
			return
		}
		keys, err := jwk.Parse(contents)
		if err != nil {
			return
		}
		key, ok := keys.Key(0)
		if !ok {
			return
		}
		bKey = &key
		var raw ecdsa.PrivateKey
		if err = (*bKey).Raw(&raw); err != nil {
			return
		}

		parsed, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, raw.PublicKey))

		if err != nil {
			return
		}

		scopeValidator := createScopeValidator(expectedScope)
		if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
			return
		}

		c.Set("User", "Federation")
	}
}

// Checks that the given token was signed by the origin jwk and also checks that the token has the expected scope
func OriginCheck(c *gin.Context, strToken string, expectedScope string) {
	bKey, err := pelican_config.GetOriginJWK()
	if err != nil {
		return
	}

	var raw ecdsa.PrivateKey
	if err = bKey.Raw(&raw); err != nil {
		return
	}

	parsed, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, raw.PublicKey))

	if err != nil {
		return
	}

	scopeValidator := createScopeValidator(expectedScope)
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		return
	}

	c.Set("User", "Origin")
}
