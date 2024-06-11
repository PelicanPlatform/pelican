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

package oauth2

import (
	"fmt"
	"net"
	"net/url"

	"github.com/pkg/errors"
	upstream_oauth "golang.org/x/oauth2"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// ServerOIDCClient loads the OIDC client configuration for
// the pelican server
func ServerOIDCClient() (result Config, provider config.OIDCProvider, err error) {
	provider = config.UnknownProvider
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
		err = errors.New("Nothing set for config parameter OIDC.AuthorizationEndpoint")
		return
	}
	authorizationEndpointURL, err := url.Parse(authorizationEndpoint)
	if err != nil {
		err = errors.New("Failed to parse URL for parameter OIDC.AuthorizationEndpoint")
		return
	}
	result.Endpoint.AuthURL = authorizationEndpointURL.String()

	// We get the provider based on the hostname of the authorization endpoint
	if authorizationEndpointURL.Hostname() == "auth.globus.org" {
		provider = config.Globus
	} else if authorizationEndpointURL.Hostname() == "cilogon.org" {
		provider = config.CILogon
	}

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
	result.Scopes = []string{"openid", "profile", "email"}
	// Add extra scope only for CILogon user info endpoint
	if provider == config.CILogon {
		result.Scopes = append(result.Scopes, "org.cilogon.userinfo")
	}
	return
}

// Generate a redirect URL for OAuth2 code authentication flow, given the callback path
// It will use OIDC.ClientRedirectHostname as the hostname if set. This is useful for local
// testing in a container environment.
func GetRedirectURL(callback string) (redirURL string, err error) {
	redirectUrlStr := param.Server_ExternalWebUrl.GetString()
	redirectUrl, err := url.Parse(redirectUrlStr)
	if err != nil {
		err = errors.Wrap(err, "failed to parse Server.ExternalWebUrl")
		return
	}
	redirectUrl.Path = callback
	redirectHostname := param.OIDC_ClientRedirectHostname.GetString()
	if redirectHostname != "" {
		_, _, err := net.SplitHostPort(redirectHostname)
		if err != nil {
			// Port not present
			redirectUrl.Host = fmt.Sprint(redirectHostname, ":", param.Server_WebPort.GetInt())
		} else {
			// Port present
			redirectUrl.Host = redirectHostname
		}
	}
	redirURL = redirectUrl.String()
	return
}

// Parse pelican/oAuth2 config to golang/x/oauth2 Config
func ParsePelicanOAuth(pCfg Config, callback string) (oCfg upstream_oauth.Config, err error) {
	redUrl, err := GetRedirectURL(callback)
	if err != nil {
		return
	}

	oCfg = upstream_oauth.Config{
		RedirectURL:  redUrl,
		ClientID:     pCfg.ClientID,
		ClientSecret: pCfg.ClientSecret,
		Scopes:       pCfg.Scopes,
		Endpoint: upstream_oauth.Endpoint{
			AuthURL:       pCfg.Endpoint.AuthURL,
			DeviceAuthURL: pCfg.Endpoint.DeviceAuthURL,
			TokenURL:      pCfg.Endpoint.TokenURL,
		},
	}
	return
}
