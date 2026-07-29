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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestGetRedirectURL(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	t.Run("no-redirect-host-no-cb-path-set", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://localhost:8888"))
		get, err := GetRedirectURL("")
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8888", get)
	})

	t.Run("no-redirect-host-cp-path-set", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://localhost:8888"))
		get, err := GetRedirectURL("/new/url")
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8888/new/url", get)
	})

	t.Run("redirect-host-cp-path-set", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://ea123fsac:8888"))
		require.NoError(t, param.Server_WebPort.Set(8888))
		require.NoError(t, param.OIDC_ClientRedirectHostname.Set("localhost"))
		get, err := GetRedirectURL("/new/url")
		require.NoError(t, err)
		assert.Equal(t, "https://localhost:8888/new/url", get)
	})

	// WS5: a delegating (firewalled) origin can't receive the IdP callback itself;
	// the redirect_uri host is auto-derived to the federation director (which
	// proxies the origin's login) without the admin setting anything.
	t.Run("delegating-origin-auto-derives-director-host", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(server_utils.ResetTestState)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.hidden:8443"))
		require.NoError(t, param.Origin_DelegateIssuerToDirector.Set(true))
		config.SetFederation(pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.example:9999"})
		get, err := GetRedirectURL("/api/v1.0/auth/oauth/callback")
		require.NoError(t, err)
		assert.Equal(t, "https://director.example:9999/api/v1.0/auth/oauth/callback", get)
	})

	// An explicit OIDC.ClientRedirectHostname always wins over the auto-derive.
	t.Run("explicit-redirect-host-overrides-delegation", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(server_utils.ResetTestState)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.hidden:8443"))
		require.NoError(t, param.Server_WebPort.Set(8443))
		require.NoError(t, param.Origin_DelegateIssuerToDirector.Set(true))
		require.NoError(t, param.OIDC_ClientRedirectHostname.Set("manual.example"))
		config.SetFederation(pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.example:9999"})
		get, err := GetRedirectURL("/cb")
		require.NoError(t, err)
		assert.Equal(t, "https://manual.example:8443/cb", get)
	})
}
