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

package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// countPrefix returns how many entries across BOTH the federation section for
// discoveryURL and the legacy OSDF section carry the given prefix.
func countPrefix(cfg *CredentialConfig, discoveryURL, prefix string) (total int, osdf int, fed int) {
	for _, e := range cfg.OSDF.OauthClient {
		if e.Prefix == prefix {
			osdf++
		}
	}
	if fedCreds, ok := cfg.Federation[discoveryURL]; ok {
		for _, e := range fedCreds.OauthClient {
			if e.Prefix == prefix {
				fed++
			}
		}
	}
	return osdf + fed, osdf, fed
}

// TestUpsertPrefixEntry pins the upgrade-path behavior of UpsertPrefixEntry: a
// credential minted under the legacy top-level OSDF section (as pre-existing
// installs have) must be UPDATED IN PLACE, not shadowed by a fresh duplicate
// appended to the per-federation section. Getting this wrong silently orphans
// the OSDF entry (and its registration-access token) while a stale/duplicate
// entry accumulates -- a regression for any user upgrading into the new
// per-federation credential layout.
func TestUpsertPrefixEntry(t *testing.T) {
	const discoveryURL = "https://fed.example.com"

	writeInitial := func(t *testing.T, cfg *CredentialConfig) string {
		t.Helper()
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "credentials.yaml")
		require.NoError(t, SaveConfigContentsToFile(cfg, filePath, false))
		require.NoError(t, param.Client_CredentialFile.Set(filePath))
		require.NoError(t, param.ConfigBase.Set(tmpDir))
		return filePath
	}

	t.Run("updates a legacy OSDF entry in place", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		writeInitial(t, &CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/foo", ClientRegistration: ClientRegistration{ClientID: "old-client", ClientSecret: "old-secret"}},
				},
			},
		})

		err := UpsertPrefixEntry(discoveryURL, &PrefixEntry{
			Prefix:             "/foo",
			ClientRegistration: ClientRegistration{ClientID: "new-client", ClientSecret: "new-secret"},
		})
		require.NoError(t, err)

		got, err := GetCredentialConfigContents()
		require.NoError(t, err)

		total, osdf, fed := countPrefix(&got, discoveryURL, "/foo")
		assert.Equal(t, 1, total, "there must be exactly one /foo entry, not a duplicate")
		assert.Equal(t, 1, osdf, "the legacy OSDF /foo entry must be updated in place")
		assert.Equal(t, 0, fed, "no duplicate /foo entry may be appended to the federation section")
		require.Len(t, got.OSDF.OauthClient, 1)
		assert.Equal(t, "new-client", got.OSDF.OauthClient[0].ClientID, "the OSDF entry must carry the new client id")
		assert.Equal(t, "new-secret", got.OSDF.OauthClient[0].ClientSecret)
	})

	t.Run("appends a genuinely new prefix to the federation section", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		writeInitial(t, &CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/foo", ClientRegistration: ClientRegistration{ClientID: "old-client"}},
				},
			},
		})

		err := UpsertPrefixEntry(discoveryURL, &PrefixEntry{
			Prefix:             "/bar",
			ClientRegistration: ClientRegistration{ClientID: "bar-client"},
		})
		require.NoError(t, err)

		got, err := GetCredentialConfigContents()
		require.NoError(t, err)

		// The unrelated OSDF entry is untouched...
		_, osdfFoo, _ := countPrefix(&got, discoveryURL, "/foo")
		assert.Equal(t, 1, osdfFoo, "the pre-existing OSDF /foo entry must be left alone")
		// ...and the new prefix lands in the federation section, not OSDF.
		_, osdfBar, fedBar := countPrefix(&got, discoveryURL, "/bar")
		assert.Equal(t, 0, osdfBar, "a new prefix must not be written into the legacy OSDF section")
		assert.Equal(t, 1, fedBar, "a new prefix must be appended to the per-federation section")
	})
}
