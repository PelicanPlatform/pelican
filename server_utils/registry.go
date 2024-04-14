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

package server_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
)

// For a given prefix, get the prefix's issuer URL, where we consider that the openid endpoint
// we use to look up a key location. Note that this is NOT the same as the issuer key -- to
// find that, follow openid-style discovery using the issuer URL as a base.
func GetNSIssuerURL(prefix string) (string, error) {
	if prefix == "" || !strings.HasPrefix(prefix, "/") {
		return "", errors.New(fmt.Sprintf("the prefix \"%s\" is invalid", prefix))
	}
	fedInfo, err := config.GetFederation(context.Background())
	registryUrlStr := fedInfo.NamespaceRegistrationEndpoint
	if registryUrlStr == "" {
		if err != nil {
			return "", err
		}
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

// Given an issuer URL, get the JWKS from the issuer's JWKS URL
func GetJWKSFromIssUrl(issuer string) (*jwk.Set, error) {
	// Make sure our URL is solid
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Invalid issuer URL: ", issuerUrl))
	}

	// Discover the JWKS URL from the issuer
	pubkeyUrlStr, err := GetJWKSURLFromIssuerURL(issuerUrl.String())
	if err != nil {
		return nil, errors.Wrap(err, "Error getting JWKS URL from issuer URL")
	}

	// Query the JWKS URL for the public keys
	httpClient := &http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequest("GET", pubkeyUrlStr, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating request to issuer's JWKS URL")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Error querying issuer's key endpoint (%s)", pubkeyUrlStr)
	}
	defer resp.Body.Close()
	// Check the response code, make sure it's not in the error ranges (400-500)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.Errorf("The issuer's JWKS endpoint returned an unexpected status: %s", resp.Status)
	}

	// Read the response body and parse the JWKs from it
	jwksStr, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading response body from %s", pubkeyUrlStr)
	}
	kSet, err := jwk.ParseString(string(jwksStr))
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing JWKs from %s", pubkeyUrlStr)
	}

	return &kSet, nil
}
