/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package issuer

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
)

// TestDeviceViewURL verifies the device verification page URL carries the correct
// same-origin issuer base so the page's fetches land on the right route whether
// it is served by the origin itself or by the director proxy (WS4/WS5).
func TestDeviceViewURL(t *testing.T) {
	origExt := param.Server_ExternalWebUrl.GetString()
	origDelegate := param.Origin_DelegateIssuerToDirector.GetBool()
	t.Cleanup(func() {
		_ = param.Server_ExternalWebUrl.Set(origExt)
		_ = param.Origin_DelegateIssuerToDirector.Set(origDelegate)
		config.SetFederation(pelican_url.FederationDiscovery{})
	})

	require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example:8443"))

	// Non-delegating origin: the page calls the origin's own issuer route.
	require.NoError(t, param.Origin_DelegateIssuerToDirector.Set(false))
	got, err := url.Parse(deviceViewURL("/foo", "WXYZ-1234"))
	require.NoError(t, err)
	q := got.Query()
	assert.Equal(t, "/view/issuer/device", got.Path)
	assert.Equal(t, "/foo", q.Get("namespace"))
	assert.Equal(t, "WXYZ-1234", q.Get("user_code"))
	assert.Equal(t, "/api/v1.0/issuer/ns/foo", q.Get("issuer_base"))

	// Delegating origin: the page must call the director proxy's issuer route,
	// since a firewalled origin's own route is unreachable.
	require.NoError(t, param.Origin_DelegateIssuerToDirector.Set(true))
	config.SetFederation(pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.example:9999"})
	got, err = url.Parse(deviceViewURL("/foo", ""))
	require.NoError(t, err)
	q = got.Query()
	assert.Equal(t, "/api/v1.0/issuer-proxy/ns/foo", q.Get("issuer_base"))
	assert.Empty(t, q.Get("user_code"))
}
