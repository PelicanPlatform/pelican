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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	OriginAdvertiseV2 struct {
		Name       string          `json:"name"`
		DataURL    string          `json:"data-url" binding:"required"`
		WebURL     string          `json:"web-url,omitempty"`
		BrokerURL  string          `json:"broker-url,omitempty"`
		Caps       Capabilities    `json:"capabilities"`
		Namespaces []NamespaceAdV2 `json:"namespaces"`
		Issuer     []TokenIssuer   `json:"token-issuer"`
	}

	OriginAdvertiseV1 struct {
		Name               string          `json:"name"`
		URL                string          `json:"url" binding:"required"` // This is the url for origin's XRootD service and file transfer
		WebURL             string          `json:"web_url,omitempty"`      // This is the url for origin's web engine and APIs
		Namespaces         []NamespaceAdV1 `json:"namespaces"`
		EnableWrite        bool            `json:"enablewrite"`
		EnableFallbackRead bool            `json:"enable-fallback-read"` // True if the origin will allow direct client reads when no caches are available
	}

	checkStatusReq struct {
		Prefix string `json:"prefix"`
	}

	checkStatusRes struct {
		Approved bool `json:"approved"`
	}
)

// Create interface
// Add it to namespacekeys in place of jwk.cache
type NamespaceCache interface {
	Register(u string, options ...jwk.RegisterOption) error
	Get(ctx context.Context, u string) (jwk.Set, error)
}

var (
	namespaceKeys      = ttlcache.New[string, NamespaceCache](ttlcache.WithTTL[string, NamespaceCache](15 * time.Minute))
	namespaceKeysMutex = sync.RWMutex{}

	adminApprovalErr error
)

func checkNamespaceStatus(prefix string, registryWebUrlStr string) (bool, error) {
	registryUrl, err := url.Parse(registryWebUrlStr)
	if err != nil {
		return false, err
	}
	reqUrl := registryUrl.JoinPath("/api/v1.0/registry/checkNamespaceStatus")

	reqBody := checkStatusReq{Prefix: prefix}
	reqByte, err := json.Marshal(reqBody)
	if err != nil {
		return false, err
	}
	client := http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequest("POST", reqUrl.String(), bytes.NewBuffer(reqByte))
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return false, err
	}

	res, err := client.Do(req)
	if err != nil {
		return false, err
	}

	if res.StatusCode != 200 {
		if res.StatusCode == 404 {
			// This is when we hit a legacy OSDF registry (or Pelican registry <= 7.4.0) which doesn't have such endpoint
			log.Warningf("Request %q hit 404, either it's an OSDF registry or Pelican registry <= 7.4.0. Fallback to return true for approval status check", reqUrl.String())
			return true, nil
		} else {
			return false, errors.New(fmt.Sprintf("Server error with status code %d", res.StatusCode))
		}
	}

	resBody := checkStatusRes{}
	bodyByte, err := io.ReadAll(res.Body)
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(bodyByte, &resBody); err != nil {
		return false, err
	}

	return resBody.Approved, nil
}

// Given a token and a location in the namespace to advertise in,
// see if the entity is authorized to advertise an origin for the
// namespace
func VerifyAdvertiseToken(ctx context.Context, token, namespace string) (bool, error) {
	issuerUrl, err := GetNSIssuerURL(namespace)
	if err != nil {
		return false, err
	}

	keyLoc, err := GetJWKSURLFromIssuerURL(issuerUrl)
	if err != nil {
		return false, err
	}

	var ar NamespaceCache

	// defer statements are scoped to function, not lexical enclosure,
	// which is why we wrap these defer statements in anon funcs
	func() {
		namespaceKeysMutex.RLock()
		defer namespaceKeysMutex.RUnlock()
		item := namespaceKeys.Get(namespace)
		if item != nil {
			if !item.IsExpired() {
				ar = item.Value()
			}
		}
	}()
	regUrlStr := param.Federation_RegistryUrl.GetString()
	approved, err := checkNamespaceStatus(namespace, regUrlStr)
	if err != nil {
		return false, errors.Wrap(err, "Failed to check namespace approval status")
	}
	if !approved {
		adminApprovalErr = errors.New(namespace + " has not been approved by an administrator.")
		return false, adminApprovalErr
	}
	if ar == nil {
		ar = jwk.NewCache(ctx)
		client := &http.Client{Transport: config.GetTransport()}
		if err = ar.Register(keyLoc, jwk.WithMinRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
			return false, err
		}
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()

		customTTL := param.Director_AdvertisementTTL.GetDuration()
		if customTTL == 0 {
			namespaceKeys.Set(namespace, ar, ttlcache.DefaultTTL)
		} else {
			namespaceKeys.Set(namespace, ar, customTTL)
		}

	}
	log.Debugln("Attempting to fetch keys from ", keyLoc)
	keyset, err := ar.Get(ctx, keyLoc)

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
		if scope == token_scopes.Pelican_Advertise.String() {
			return true, nil
		}
	}
	return false, nil
}

// Verify that a token received is a valid token from director
func VerifyDirectorTestReportToken(strToken string) (bool, error) {
	directorURL := param.Federation_DirectorUrl.GetString()
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))
	if err != nil {
		return false, err
	}

	if directorURL != token.Issuer() {
		return false, errors.Errorf("Token issuer is not a director")
	}

	key, err := utils.LoadDirectorPublicKey()
	if err != nil {
		return false, err
	}

	tok, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, key), jwt.WithValidate(true))
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
		if scope == token_scopes.Pelican_DirectorTestReport.String() {
			return true, nil
		}
	}
	return false, nil
}

// For a given prefix, get the prefix's issuer URL, where we consider that the openid endpoint
// we use to look up a key location. Note that this is NOT the same as the issuer key -- to
// find that, follow openid-style discovery using the issuer URL as a base.
func GetNSIssuerURL(prefix string) (string, error) {
	if prefix == "" || !strings.HasPrefix(prefix, "/") {
		return "", errors.New(fmt.Sprintf("the prefix \"%s\" is invalid", prefix))
	}
	registryUrlStr := param.Federation_RegistryUrl.GetString()
	if registryUrlStr == "" {
		return "", errors.New("federation registry URL is not set and was not discovered")
	}
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		return "", err
	}

	registryUrl.Path, err = url.JoinPath(registryUrl.Path, "api", "v1.0", "registry", prefix)

	if err != nil {
		return "", errors.Wrapf(err, "failed to construct openid-configuration lookup URL for prefix %s", prefix)
	}
	return registryUrl.String(), nil
}

// Given an issuer url, lookup the JWKS URL from the openid-configuration
// For example, if the issuer URL is https://registry.com:8446/api/v1.0/registry/test-namespace,
// this function will return the key indicated by the openid-configuration JSON hosted at
// https://registry.com:8446/api/v1.0/registry/test-namespace/.well-known/openid-configuration.
func GetJWKSURLFromIssuerURL(issuerUrl string) (string, error) {
	// Get/parse the openid-configuration JSON to lookup key location
	issOpenIDUrl, err := url.Parse(issuerUrl)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse issuer URL")
	}
	issOpenIDUrl.Path, _ = url.JoinPath(issOpenIDUrl.Path, ".well-known", "openid-configuration")

	client := &http.Client{Transport: config.GetTransport()}
	openIDCfg, err := client.Get(issOpenIDUrl.String())
	if err != nil {
		return "", errors.Wrapf(err, "failed to lookup openid-configuration for issuer %s", issuerUrl)
	}
	defer openIDCfg.Body.Close()

	// If we hit an old registry, it may not have the openid-configuration. In that case, we fallback to the old
	// behavior of looking for the key directly at the issuer URL.
	if openIDCfg.StatusCode == http.StatusNotFound {
		oldKeyLoc, err := url.JoinPath(issuerUrl, ".well-known", "issuer.jwks")
		if err != nil {
			return "", errors.Wrapf(err, "failed to construct key lookup URL for issuer %s", issuerUrl)
		}
		return oldKeyLoc, nil
	}

	body, err := io.ReadAll(openIDCfg.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read response body from %s", issuerUrl)
	}

	var openIDCfgMap map[string]string
	err = json.Unmarshal(body, &openIDCfgMap)
	if err != nil {
		return "", errors.Wrapf(err, "failed to unmarshal openid-configuration for issuer %s", issuerUrl)
	}

	if keyLoc, ok := openIDCfgMap["jwks_uri"]; ok {
		return keyLoc, nil
	} else {
		return "", errors.New(fmt.Sprintf("no key found in openid-configuration for issuer %s", issuerUrl))
	}
}
