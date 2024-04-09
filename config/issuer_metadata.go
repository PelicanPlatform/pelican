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

package config

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
)

type OauthIssuer struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	DeviceAuthURL   string   `json:"device_authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	RegistrationURL string   `json:"registration_endpoint"`
	UserInfoURL     string   `json:"userinfo_endpoint"`
	GrantTypes      []string `json:"grant_types_supported"`
	ScopesSupported []string `json:"scopes_supported"`
}

// Get OIDC issuer metadata from an OIDC issuer URL.
// The URL should not contain the path to /.well-known/openid-configuration
func GetIssuerMetadata(issuer_url string) (*OauthIssuer, error) {
	wellKnownUrl := strings.TrimSuffix(issuer_url, "/") + "/.well-known/openid-configuration"

	client := http.Client{Transport: GetTransport()}
	req, err := http.NewRequest(http.MethodGet, wellKnownUrl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.Errorf("Failed to retrieve issuer metadata at %s with status code %d", wellKnownUrl, resp.StatusCode)
	}

	issuer := &OauthIssuer{}
	err = json.Unmarshal(body, issuer)
	return issuer, err
}
