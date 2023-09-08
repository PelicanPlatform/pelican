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

package director

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type (
	OriginAdvertise struct {
		Name       string        `json:"name"`
		URL        string        `json:"url"`
		Namespaces []NamespaceAd `json:"namespaces"`
	}
)

var (
	namespaceKeys      = ttlcache.New[string, *jwk.Cache](ttlcache.WithTTL[string, *jwk.Cache](15 * time.Minute))
	namespaceKeysMutex = sync.RWMutex{}
)

func CreateAdvertiseToken(namespace string) (string, error) {
	// TODO: Need to come back and carefully consider a few naming practices.
	//       Here, issuerUrl is actually the registry database url, and not
	//       the token issuer url for this namespace
	issuerUrl, err := GetIssuerURL(namespace)
	if err != nil {
		return "", err
	}
	director := viper.GetString("DirectorURL")
	if director == "" {
		return "", errors.New("Director URL is not known; cannot create advertise token")
	}

	tok, err := jwt.NewBuilder().
		Claim("scope", "pelican.advertise").
		Issuer(issuerUrl).
		Audience([]string{director}).
		Subject("origin").
		Expiration(time.Now().Add(time.Minute)).
		Build()
	if err != nil {
		return "", err
	}

	key, err := config.GetOriginJWK()
	if err != nil {
		return "", errors.Wrap(err, "failed to load the origin's JWK")
	}

	// Get/assign the kid, needed for verification of the token by the director
	// TODO: Create more generic "tokenCreate" functions so we don't have to do
	//       this by hand all the time
	err = jwk.AssignKeyID(*key)
	if err != nil {
		return "", errors.Wrap(err, "Failed to assign kid to the token")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, *key))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// Given a token and a location in the namespace to advertise in,
// see if the entity is authorized to advertise an origin for the
// namespace
func VerifyAdvertiseToken(token, namespace string) (bool, error) {
	issuerUrl, err := GetIssuerURL(namespace)
	if err != nil {
		return false, err
	}
	var ar *jwk.Cache

	// defer statements are scoped to function, not lexical enclosure,
	// which is why we wrap these defer statements in anon funcs
	func () {
		namespaceKeysMutex.RLock()
		defer namespaceKeysMutex.RUnlock()
		item := namespaceKeys.Get(namespace)
		if item != nil {
			if !item.IsExpired() {
				ar = item.Value()
			}
		}
	}()
	ctx := context.Background()
	if ar == nil {
		ar = jwk.NewCache(ctx)
		// This should be switched to use the common transport, but that must first be exported
		client := &http.Client{}
		if viper.GetBool("TLSSkipVerify") {
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client = &http.Client{Transport: tr}
		}
		if err = ar.Register(issuerUrl, jwk.WithMinRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
			return false, err
		}
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()
		namespaceKeys.Set(namespace, ar, ttlcache.DefaultTTL)
	}
	log.Debugln("Attempting to fetch keys from ", issuerUrl)
	keyset, err := ar.Get(ctx, issuerUrl)

	if log.IsLevelEnabled(log.DebugLevel) {
		// Let's check that we can convert to JSON and get the right thing...
		jsonbuf, err := json.Marshal(keyset)
		if err != nil {
			return false, errors.Wrap(err, "failed to marshal the public keyset into JWKS JSON")
		}
		log.Debugln("Constructed JWKS from fetching jwks:", string(jsonbuf))
	}

	if err != nil {
		return false, err
	}

	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(keyset), jwt.WithValidate(true))
	if err != nil {
		return false, err
	}

	scope_any, present := tok.Get("scope")
	if !present {
		return false, errors.New("No scope is present; required to advertise to director")
	}
	scope, ok := scope_any.(string)
	if !ok {
		return false, errors.New("scope claim in token is not string-valued")
	}

	scopes := strings.Split(scope, " ")

	for _, scope := range scopes {
		if scope == "pelican.advertise" {
			return true, nil
		}
	}
	return false, nil
}

func GetIssuerURL(prefix string) (string, error) {
	namespace_url_string := viper.GetString("NamespaceURL")
	if namespace_url_string == "" {
		return "", errors.New("Namespace URL is not set")
	}
	namespace_url, err := url.Parse(namespace_url_string)
	if err != nil {
		return "", err
	}
	namespace_url.Path = path.Join(namespace_url.Path, "api", "v1.0", "registry", prefix, ".well-known", "issuer.jwks")
	return namespace_url.String(), nil
}
