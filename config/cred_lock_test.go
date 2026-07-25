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

// writeInitialCredentialFile writes cfg to a fresh credential file and points the
// config at it, for the merge-helper tests below.
func writeInitialCredentialFile(t *testing.T, cfg *CredentialConfig) {
	t.Helper()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "credentials.yaml")
	require.NoError(t, SaveConfigContentsToFile(cfg, filePath, false))
	require.NoError(t, param.Client_CredentialFile.Set(filePath))
	require.NoError(t, param.ConfigBase.Set(tmpDir))
}

// TestMutatePrefixEntryPreservesConcurrentWrites verifies that MutatePrefixEntry
// re-reads the wallet under the lock and applies only its delta, so updating one
// prefix does not clobber a concurrent writer's change to another prefix. This
// is the property that the credential-file lock exists to guarantee: the old
// read-modify-write-the-whole-file pattern would silently revert /b here.
func TestMutatePrefixEntryPreservesConcurrentWrites(t *testing.T) {
	const discoveryURL = "https://fed.example.com"
	ResetConfig()
	t.Cleanup(ResetConfig)

	writeInitialCredentialFile(t, &CredentialConfig{
		OSDF: FederationCredentials{
			OauthClient: []PrefixEntry{
				{Prefix: "/a", ClientRegistration: ClientRegistration{ClientID: "a-old"}},
				{Prefix: "/b", ClientRegistration: ClientRegistration{ClientID: "b-old"}},
			},
		},
	})

	// A concurrent writer (e.g. background refresh) updates /b on disk.
	require.NoError(t, MutatePrefixEntry(discoveryURL, "/b", func(e *PrefixEntry) {
		e.ClientID = "b-new"
	}))

	// Our update to /a must preserve /b's concurrent change.
	require.NoError(t, MutatePrefixEntry(discoveryURL, "/a", func(e *PrefixEntry) {
		e.ClientID = "a-new"
	}))

	got, err := GetCredentialConfigContents()
	require.NoError(t, err)
	_, aIdx := got.FindOauthClient(discoveryURL, "/a")
	_, bIdx := got.FindOauthClient(discoveryURL, "/b")
	require.GreaterOrEqual(t, aIdx, 0)
	require.GreaterOrEqual(t, bIdx, 0)
	assert.Equal(t, "a-new", got.OSDF.OauthClient[aIdx].ClientID, "our /a update must be applied")
	assert.Equal(t, "b-new", got.OSDF.OauthClient[bIdx].ClientID, "the concurrent /b update must not be clobbered")
	totalA, _, _ := countPrefix(&got, discoveryURL, "/a")
	totalB, _, _ := countPrefix(&got, discoveryURL, "/b")
	assert.Equal(t, 1, totalA, "no duplicate /a entry")
	assert.Equal(t, 1, totalB, "no duplicate /b entry")
}

// TestUpsertTransferServerEntryPreservesConcurrentWrites verifies the same
// re-read-and-merge property for transfer-server entries: updating one server's
// cached token must not revert a concurrent update to another server.
func TestUpsertTransferServerEntryPreservesConcurrentWrites(t *testing.T) {
	const discoveryURL = "https://fed.example.com"
	ResetConfig()
	t.Cleanup(ResetConfig)

	writeInitialCredentialFile(t, &CredentialConfig{
		OSDF: FederationCredentials{
			TransferServers: []TransferServerEntry{
				{ServerURL: "https://xfer-a.example.com", ClientRegistration: ClientRegistration{ClientID: "a-old"}},
				{ServerURL: "https://xfer-b.example.com", ClientRegistration: ClientRegistration{ClientID: "b-old"}},
			},
		},
	})

	require.NoError(t, UpsertTransferServerEntry(discoveryURL, "https://xfer-b.example.com", func(e *TransferServerEntry) {
		e.ClientID = "b-new"
	}))
	require.NoError(t, UpsertTransferServerEntry(discoveryURL, "https://xfer-a.example.com", func(e *TransferServerEntry) {
		e.ClientID = "a-new"
	}))

	got, err := GetCredentialConfigContents()
	require.NoError(t, err)
	_, aIdx := got.FindTransferServer(discoveryURL, "https://xfer-a.example.com")
	_, bIdx := got.FindTransferServer(discoveryURL, "https://xfer-b.example.com")
	require.GreaterOrEqual(t, aIdx, 0)
	require.GreaterOrEqual(t, bIdx, 0)
	assert.Equal(t, "a-new", got.OSDF.TransferServers[aIdx].ClientID, "our server-a update must be applied")
	assert.Equal(t, "b-new", got.OSDF.TransferServers[bIdx].ClientID, "the concurrent server-b update must not be clobbered")
	assert.Len(t, got.OSDF.TransferServers, 2, "no duplicate transfer-server entries")
}
