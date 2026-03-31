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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestApplyGitHubOAuthDefaults(t *testing.T) {
	t.Cleanup(ResetConfig)

	t.Run("no-op-when-group-source-not-github", func(t *testing.T) {
		ResetConfig()
		SetBaseDefaultsInConfig(viper.GetViper())
		require.NoError(t, applyGitHubOAuthDefaults())
		assert.Equal(t, cilogonOIDCDefaults.issuer, param.OIDC_Issuer.GetString())
	})

	t.Run("fills-all-github-values-from-cilogon-defaults", func(t *testing.T) {
		ResetConfig()
		// Load defaults.yaml so all OIDC params are "IsSet" with CILogon values
		SetBaseDefaultsInConfig(viper.GetViper())
		require.NoError(t, param.Issuer_GroupSource.Set("github"))
		require.NoError(t, applyGitHubOAuthDefaults())

		assert.Equal(t, "https://github.com", param.OIDC_Issuer.GetString())
		assert.Equal(t, "https://github.com/login/oauth/authorize", param.OIDC_AuthorizationEndpoint.GetString())
		assert.Equal(t, "https://github.com/login/oauth/access_token", param.OIDC_TokenEndpoint.GetString())
		assert.Equal(t, "https://api.github.com/user", param.OIDC_UserInfoEndpoint.GetString())
		assert.Equal(t, "https://github.com/login/device/code", param.OIDC_DeviceAuthEndpoint.GetString())
		assert.Equal(t, []string{"user", "read:org"}, param.OIDC_Scopes.GetStringSlice())
		assert.Equal(t, "login", param.Issuer_OIDCAuthenticationUserClaim.GetString())
		assert.Equal(t, "id", param.Issuer_OIDCSubjectClaim.GetString())
	})

	t.Run("case-insensitive-group-source", func(t *testing.T) {
		ResetConfig()
		SetBaseDefaultsInConfig(viper.GetViper())
		require.NoError(t, param.Issuer_GroupSource.Set("GitHub"))
		require.NoError(t, applyGitHubOAuthDefaults())
		assert.Equal(t, "https://github.com", param.OIDC_Issuer.GetString())
	})

	t.Run("user-set-issuer-not-overwritten", func(t *testing.T) {
		ResetConfig()
		SetBaseDefaultsInConfig(viper.GetViper())
		require.NoError(t, param.Issuer_GroupSource.Set("github"))
		require.NoError(t, param.OIDC_Issuer.Set("https://my-custom-oauth.example.com"))
		require.NoError(t, applyGitHubOAuthDefaults())
		assert.Equal(t, "https://my-custom-oauth.example.com", param.OIDC_Issuer.GetString())
	})

	t.Run("user-set-scopes-not-overwritten", func(t *testing.T) {
		ResetConfig()
		SetBaseDefaultsInConfig(viper.GetViper())
		require.NoError(t, param.Issuer_GroupSource.Set("github"))
		require.NoError(t, param.OIDC_Scopes.Set([]string{"user", "read:org", "repo"}))
		require.NoError(t, applyGitHubOAuthDefaults())
		assert.Equal(t, []string{"user", "read:org", "repo"}, param.OIDC_Scopes.GetStringSlice())
	})

	t.Run("user-set-auth-claim-not-overwritten", func(t *testing.T) {
		ResetConfig()
		SetBaseDefaultsInConfig(viper.GetViper())
		require.NoError(t, param.Issuer_GroupSource.Set("github"))
		require.NoError(t, param.Issuer_OIDCAuthenticationUserClaim.Set("email"))
		require.NoError(t, applyGitHubOAuthDefaults())
		assert.Equal(t, "email", param.Issuer_OIDCAuthenticationUserClaim.GetString())
	})
}


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
		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set("https://example.com/authorization"))
		get, err := GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, UnknownProvider, get)

		// CILogon
		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set("https://cilogon.org/api/v1.0/authorization"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// Globus
		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set("https://auth.globus.org/api/v1.0/authorization"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, Globus, get)
	})

	t.Run("issuer-endpoint-gives-correct-result", func(t *testing.T) {
		ResetConfig()
		require.NoError(t, param.OIDC_Issuer.Set("https://example.com"))
		get, err := GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, UnknownProvider, get)

		// CILogon
		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set("https://cilogon.org"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// CILogon no protocol
		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set("cilogon.org"))
		get, err = GetOIDCProvider()
		require.NoError(t, err)
		assert.Equal(t, CILogon, get)

		// Globus no protocol
		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set("auth.globus.org"))
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

		require.NoError(t, param.OIDC_AuthorizationEndpoint.Set(explicitAuthEndpoint))
		require.NoError(t, param.OIDC_TokenEndpoint.Set(explicitTokenEndpoint))
		require.NoError(t, param.OIDC_UserInfoEndpoint.Set(explicitUserInfoEndpoint))
		require.NoError(t, param.OIDC_DeviceAuthEndpoint.Set(explicitDeviceAuthEndpoint))

		// Set OIDC.Issuer to CILogon (which has OIDC discovery)
		// This should NOT override the explicitly set endpoints
		require.NoError(t, param.OIDC_Issuer.Set("https://cilogon.org"))

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
