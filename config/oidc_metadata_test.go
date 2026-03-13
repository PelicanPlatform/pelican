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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestGetOIDCProvider(t *testing.T) {
	t.Cleanup(func() {
		ResetConfig()
	})
	t.Run("empty-endpoints-gives-error", func(t *testing.T) {
		ResetConfig()
		get, err := GetOIDCProvider()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nothing set for config parameter OIDC.IssuerUrl or OIDC.AuthorizationEndpoint")
		assert.Empty(t, get)
	})

	t.Run("auth-endpoint-gives-correct-result", func(t *testing.T) {
		ResetConfig()
		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://example.com/authorization"))
		get, err := GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, UnknownProvider, get)

		// CILogon
		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://cilogon.org/api/v1.0/authorization"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// Globus
		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://auth.globus.org/api/v1.0/authorization"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, Globus, get)
	})

	t.Run("issuer-endpoint-gives-correct-result", func(t *testing.T) {
		ResetConfig()
		require.NoError(t, param.Set(param.OIDC_Issuer.GetName(), "https://example.com"))
		get, err := GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, UnknownProvider, get)

		// CILogon
		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), "https://cilogon.org"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// CILogon no protocol
		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), "cilogon.org"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// Globus no protocol
		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), "auth.globus.org"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, Globus, get)
	})
}

func TestGetMetadataRespectsExplicitEndpoints(t *testing.T) {
	t.Cleanup(func() {
		ResetConfig()
		// Note: Resetting sync.Once in tests is generally not recommended due to potential race conditions.
		// However, in this case, we run tests sequentially and need to re-trigger metadata discovery.
		// In production code, sync.Once ensures getMetadata() is only called once per process lifetime.
		onceMetadata = sync.Once{}
		metadataError = nil
		oidcMetadata = nil
	})

	t.Run("explicit-endpoints-not-overridden-by-issuer", func(t *testing.T) {
		ResetConfig()
		// Reset the sync.Once so we can test getMetadata again in this isolated test
		onceMetadata = sync.Once{}
		metadataError = nil
		oidcMetadata = nil

		// Set explicit endpoints (e.g., for GitHub OAuth2)
		explicitAuthEndpoint := "https://github.com/login/oauth/authorize"
		explicitTokenEndpoint := "https://github.com/login/oauth/access_token"
		explicitUserInfoEndpoint := "https://api.github.com/user"
		explicitDeviceAuthEndpoint := "https://github.com/login/device/code"

		require.NoError(t, param.Set(param.OIDC_AuthorizationEndpoint.GetName(), explicitAuthEndpoint))
		require.NoError(t, param.Set(param.OIDC_TokenEndpoint.GetName(), explicitTokenEndpoint))
		require.NoError(t, param.Set(param.OIDC_UserInfoEndpoint.GetName(), explicitUserInfoEndpoint))
		require.NoError(t, param.Set(param.OIDC_DeviceAuthEndpoint.GetName(), explicitDeviceAuthEndpoint))

		// Set OIDC.Issuer to CILogon (which has OIDC discovery)
		// This should NOT override the explicitly set endpoints
		require.NoError(t, param.Set(param.OIDC_Issuer.GetName(), "https://cilogon.org"))

		// Call the metadata discovery - it will try to fetch from CILogon but should not override
		onceMetadata.Do(getMetadata)

		// Verify the endpoints are still what we set explicitly, not CILogon's
		authEndpoint, err := GetOIDCAuthorizationEndpoint()
		require.NoError(t, err)
		assert.Equal(t, explicitAuthEndpoint, authEndpoint, "Authorization endpoint should not be overridden")

		tokenEndpoint, err := GetOIDCTokenEndpoint()
		require.NoError(t, err)
		assert.Equal(t, explicitTokenEndpoint, tokenEndpoint, "Token endpoint should not be overridden")

		userInfoEndpoint, err := GetOIDCUserInfoEndpoint()
		require.NoError(t, err)
		assert.Equal(t, explicitUserInfoEndpoint, userInfoEndpoint, "UserInfo endpoint should not be overridden")

		deviceAuthEndpoint, err := GetOIDCDeviceAuthEndpoint()
		require.NoError(t, err)
		assert.Equal(t, explicitDeviceAuthEndpoint, deviceAuthEndpoint, "DeviceAuth endpoint should not be overridden")
	})
}
