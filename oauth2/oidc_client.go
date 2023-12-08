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

package oauth2

import (
	"net/url"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
)

// ServerOIDCClient loads the OIDC client configuration for
// the pelican server
func ServerOIDCClient() (result Config, err error) {
	// Load OIDC.ClientID
	if result.ClientID, err = config.GetOIDCClientID(); err != nil {
		return
	}

	if result.ClientID == "" {
		err = errors.New("OIDC.ClientID is empty")
		return
	}

	// load OIDC.ClientSecret
	if result.ClientSecret, err = config.GetOIDCClientSecret(); err != nil {
		return
	}

	if result.ClientSecret == "" {
		err = errors.New("OIDC.ClientSecret is empty")
		return
	}

	// Load OIDC.AuthorizationEndpoint
	authorizationEndpoint, err := config.GetOIDCAuthorizationEndpoint()
	if err != nil {
		err = errors.Wrap(err, "Unable to get authorization endpoint for OIDC issuer")
		return
	}
	if authorizationEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.DeviceAuthEndpoint")
		return
	}
	authorizationEndpointURL, err := url.Parse(authorizationEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.DeviceAuthEndpoint")
		return
	}
	result.Endpoint.AuthURL = authorizationEndpointURL.String()

	// Load OIDC.DeviceAuthEndpoint
	deviceAuthEndpoint, err := config.GetOIDCDeviceAuthEndpoint()
	if err != nil {
		err = errors.Wrap(err, "Unable to get device authentication endpoint for OIDC issuer")
		return
	}
	if deviceAuthEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.DeviceAuthEndpoint")
		return
	}
	deviceAuthEndpointURL, err := url.Parse(deviceAuthEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.DeviceAuthEndpoint")
		return
	}
	result.Endpoint.DeviceAuthURL = deviceAuthEndpointURL.String()

	// Load OIDC.TokenEndpoint
	tokenEndpoint, err := config.GetOIDCTokenEndpoint()
	if err != nil {
		err = errors.Wrap(err, "Unable to get token endpoint for OIDC issuer")
		return
	}
	if tokenEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.TokenEndpoint")
		return
	}
	tokenAuthEndpointURL, err := url.Parse(tokenEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.TokenEndpoint")
		return
	}
	result.Endpoint.TokenURL = tokenAuthEndpointURL.String()

	// Load OIDC.UserInfoEndpoint
	userInfoEndpoint, err := config.GetOIDCUserInfoEndpoint()
	if err != nil {
		err = errors.Wrap(err, "Unable to get user info endpoint for OIDC issuer")
		return
	}
	if userInfoEndpoint == "" {
		err = errors.New("Nothing set for config parameter OIDC.UserInfoEndpoint")
		return
	}
	userInfoEndpointURL, err := url.Parse(userInfoEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.UserInfoEndpoint")
		return
	}
	result.Endpoint.UserInfoURL = userInfoEndpointURL.String()

	// Set the scope
	result.Scopes = []string{"openid", "profile", "email", "org.cilogon.userinfo"}

	return
}
