/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindCredential(t *testing.T) {
	entry := TransferServerEntry{
		ServerURL: "https://xfer.example.com",
		Credentials: []CredentialEntry{
			{
				IssuerURL:    "https://issuer.example.com",
				CredentialID: "read-cred",
				Scopes:       []string{"storage.read:/data"},
			},
			{
				IssuerURL:    "https://issuer.example.com",
				CredentialID: "write-cred",
				Scopes:       []string{"storage.read:/data", "storage.modify:/data", "storage.create:/data"},
			},
			{
				IssuerURL:    "https://other-issuer.example.com",
				CredentialID: "other-cred",
				Scopes:       []string{"storage.read:/"},
			},
		},
	}

	t.Run("find read credential", func(t *testing.T) {
		cred := entry.FindCredential("https://issuer.example.com", []string{"storage.read:/data"})
		assert.Equal(t, "read-cred", cred)
	})

	t.Run("find write credential skips read-only", func(t *testing.T) {
		cred := entry.FindCredential("https://issuer.example.com", []string{"storage.read:/data", "storage.modify:/data", "storage.create:/data"})
		assert.Equal(t, "write-cred", cred)
	})

	t.Run("wrong issuer returns empty", func(t *testing.T) {
		cred := entry.FindCredential("https://unknown.example.com", []string{"storage.read:/"})
		assert.Empty(t, cred)
	})

	t.Run("narrower scope path not found", func(t *testing.T) {
		cred := entry.FindCredential("https://issuer.example.com", []string{"storage.read:/other"})
		assert.Empty(t, cred)
	})

	t.Run("broader scope satisfies narrower request", func(t *testing.T) {
		cred := entry.FindCredential("https://other-issuer.example.com", []string{"storage.read:/"})
		assert.Equal(t, "other-cred", cred)
	})

	t.Run("empty credentials list", func(t *testing.T) {
		empty := TransferServerEntry{ServerURL: "https://empty.example.com"}
		cred := empty.FindCredential("https://issuer.example.com", []string{"storage.read:/"})
		assert.Empty(t, cred)
	})

	t.Run("root scope covers child path via hierarchy", func(t *testing.T) {
		cred := entry.FindCredential("https://other-issuer.example.com", []string{"storage.read:/data/subdir"})
		assert.Equal(t, "other-cred", cred)
	})

	t.Run("parent path covers child path", func(t *testing.T) {
		cred := entry.FindCredential("https://issuer.example.com", []string{"storage.read:/data/subdir"})
		assert.Equal(t, "read-cred", cred)
	})

	t.Run("storage.modify implies storage.create", func(t *testing.T) {
		cred := entry.FindCredential("https://issuer.example.com", []string{"storage.create:/data"})
		assert.Equal(t, "write-cred", cred)
	})
}

func TestScopesContainAll(t *testing.T) {
	tests := []struct {
		name     string
		have     []string
		required []string
		expected bool
	}{
		{
			name:     "exact match single scope",
			have:     []string{"storage.read:/data"},
			required: []string{"storage.read:/data"},
			expected: true,
		},
		{
			name:     "root scope covers child",
			have:     []string{"storage.read:/"},
			required: []string{"storage.read:/foo"},
			expected: true,
		},
		{
			name:     "parent path covers child path",
			have:     []string{"storage.read:/data"},
			required: []string{"storage.read:/data/subdir"},
			expected: true,
		},
		{
			name:     "child path does not cover parent",
			have:     []string{"storage.read:/data/subdir"},
			required: []string{"storage.read:/data"},
			expected: false,
		},
		{
			name:     "different action not covered",
			have:     []string{"storage.read:/data"},
			required: []string{"storage.modify:/data"},
			expected: false,
		},
		{
			name:     "storage.modify implies storage.create",
			have:     []string{"storage.modify:/data"},
			required: []string{"storage.create:/data"},
			expected: true,
		},
		{
			name:     "disjoint paths not covered",
			have:     []string{"storage.read:/data"},
			required: []string{"storage.read:/other"},
			expected: false,
		},
		{
			name:     "multiple requirements all satisfied",
			have:     []string{"storage.read:/", "storage.modify:/"},
			required: []string{"storage.read:/data", "storage.modify:/data"},
			expected: true,
		},
		{
			name:     "multiple requirements one missing",
			have:     []string{"storage.read:/"},
			required: []string{"storage.read:/data", "storage.modify:/data"},
			expected: false,
		},
		{
			name:     "empty required always satisfied",
			have:     []string{"storage.read:/"},
			required: []string{},
			expected: true,
		},
		{
			name:     "empty have fails any requirement",
			have:     []string{},
			required: []string{"storage.read:/"},
			expected: false,
		},
		{
			name:     "scope without colon treated as root resource",
			have:     []string{"storage.read"},
			required: []string{"storage.read:/"},
			expected: true,
		},
		{
			name:     "path boundary respected: /data does not cover /datadir",
			have:     []string{"storage.read:/data"},
			required: []string{"storage.read:/datadir"},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, scopesContainAll(tt.have, tt.required))
		})
	}
}

func TestGetPrefixEntryFallback(t *testing.T) {
	cfg := CredentialConfig{
		OSDF: FederationCredentials{
			OauthClient: []PrefixEntry{
				{Prefix: "/legacy-prefix", ClientRegistration: ClientRegistration{ClientID: "legacy-client"}},
			},
		},
		Federation: map[string]*FederationCredentials{
			"https://fed.example.com": {
				OauthClient: []PrefixEntry{
					{Prefix: "/fed-prefix", ClientRegistration: ClientRegistration{ClientID: "fed-client"}},
				},
			},
		},
	}

	t.Run("federation entry found directly", func(t *testing.T) {
		entry := cfg.GetPrefixEntry("https://fed.example.com", "/fed-prefix")
		assert.NotNil(t, entry)
		assert.Equal(t, "fed-client", entry.ClientID)
	})

	t.Run("falls back to OSDF when prefix not in federation", func(t *testing.T) {
		entry := cfg.GetPrefixEntry("https://fed.example.com", "/legacy-prefix")
		assert.NotNil(t, entry)
		assert.Equal(t, "legacy-client", entry.ClientID)
	})

	t.Run("empty discoveryURL searches OSDF directly", func(t *testing.T) {
		entry := cfg.GetPrefixEntry("", "/legacy-prefix")
		assert.NotNil(t, entry)
		assert.Equal(t, "legacy-client", entry.ClientID)
	})

	t.Run("unknown discoveryURL falls back to OSDF", func(t *testing.T) {
		entry := cfg.GetPrefixEntry("https://unknown.example.com", "/legacy-prefix")
		assert.NotNil(t, entry)
		assert.Equal(t, "legacy-client", entry.ClientID)
	})

	t.Run("federation overrides OSDF for same prefix", func(t *testing.T) {
		cfg2 := CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/shared", ClientRegistration: ClientRegistration{ClientID: "osdf-client"}},
				},
			},
			Federation: map[string]*FederationCredentials{
				"https://fed.example.com": {
					OauthClient: []PrefixEntry{
						{Prefix: "/shared", ClientRegistration: ClientRegistration{ClientID: "fed-client"}},
					},
				},
			},
		}
		entry := cfg2.GetPrefixEntry("https://fed.example.com", "/shared")
		assert.NotNil(t, entry)
		assert.Equal(t, "fed-client", entry.ClientID)
	})

	t.Run("returns nil when prefix not found anywhere", func(t *testing.T) {
		entry := cfg.GetPrefixEntry("https://fed.example.com", "/nonexistent")
		assert.Nil(t, entry)
	})
}

func TestGetTransferServerEntryFallback(t *testing.T) {
	cfg := CredentialConfig{
		OSDF: FederationCredentials{
			TransferServers: []TransferServerEntry{
				{ServerURL: "https://legacy-server.example.com"},
			},
		},
		Federation: map[string]*FederationCredentials{
			"https://fed.example.com": {
				TransferServers: []TransferServerEntry{
					{ServerURL: "https://fed-server.example.com"},
				},
			},
		},
	}

	t.Run("federation entry found directly", func(t *testing.T) {
		entry := cfg.GetTransferServerEntry("https://fed.example.com", "https://fed-server.example.com")
		assert.NotNil(t, entry)
		assert.Equal(t, "https://fed-server.example.com", entry.ServerURL)
	})

	t.Run("falls back to OSDF when server not in federation", func(t *testing.T) {
		entry := cfg.GetTransferServerEntry("https://fed.example.com", "https://legacy-server.example.com")
		assert.NotNil(t, entry)
		assert.Equal(t, "https://legacy-server.example.com", entry.ServerURL)
	})

	t.Run("empty discoveryURL searches OSDF directly", func(t *testing.T) {
		entry := cfg.GetTransferServerEntry("", "https://legacy-server.example.com")
		assert.NotNil(t, entry)
		assert.Equal(t, "https://legacy-server.example.com", entry.ServerURL)
	})

	t.Run("returns nil when server not found anywhere", func(t *testing.T) {
		entry := cfg.GetTransferServerEntry("https://fed.example.com", "https://nonexistent.example.com")
		assert.Nil(t, entry)
	})
}

func TestFindOauthClient(t *testing.T) {
	t.Run("found in federation section", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/osdf-only", ClientRegistration: ClientRegistration{ClientID: "osdf-client"}},
				},
			},
			Federation: map[string]*FederationCredentials{
				"https://fed.example.com": {
					OauthClient: []PrefixEntry{
						{Prefix: "/fed-prefix", ClientRegistration: ClientRegistration{ClientID: "fed-client"}},
					},
				},
			},
		}
		fc, idx := cfg.FindOauthClient("https://fed.example.com", "/fed-prefix")
		assert.Equal(t, 0, idx)
		assert.Equal(t, "fed-client", fc.OauthClient[idx].ClientID)
	})

	t.Run("falls back to OSDF", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/legacy", ClientRegistration: ClientRegistration{ClientID: "legacy-client"}},
				},
			},
			Federation: map[string]*FederationCredentials{
				"https://fed.example.com": {
					OauthClient: []PrefixEntry{},
				},
			},
		}
		fc, idx := cfg.FindOauthClient("https://fed.example.com", "/legacy")
		assert.Equal(t, 0, idx)
		assert.Equal(t, "legacy-client", fc.OauthClient[idx].ClientID)
		// fc should point to the OSDF section
		assert.Equal(t, &cfg.OSDF, fc)
	})

	t.Run("not found returns federation section and -1", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{},
		}
		fc, idx := cfg.FindOauthClient("https://fed.example.com", "/nonexistent")
		assert.Equal(t, -1, idx)
		// Should have created the federation section
		assert.NotNil(t, cfg.Federation["https://fed.example.com"])
		assert.Equal(t, cfg.Federation["https://fed.example.com"], fc)
	})

	t.Run("empty discoveryURL searches OSDF only", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/test", ClientRegistration: ClientRegistration{ClientID: "test-client"}},
				},
			},
		}
		fc, idx := cfg.FindOauthClient("", "/test")
		assert.Equal(t, 0, idx)
		assert.Equal(t, &cfg.OSDF, fc)
	})

	t.Run("federation overrides OSDF for same prefix", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{
				OauthClient: []PrefixEntry{
					{Prefix: "/shared", ClientRegistration: ClientRegistration{ClientID: "osdf-client"}},
				},
			},
			Federation: map[string]*FederationCredentials{
				"https://fed.example.com": {
					OauthClient: []PrefixEntry{
						{Prefix: "/shared", ClientRegistration: ClientRegistration{ClientID: "fed-client"}},
					},
				},
			},
		}
		fc, idx := cfg.FindOauthClient("https://fed.example.com", "/shared")
		assert.Equal(t, 0, idx)
		assert.Equal(t, "fed-client", fc.OauthClient[idx].ClientID)
	})

	t.Run("new entries append to federation section", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{},
		}
		fc, idx := cfg.FindOauthClient("https://fed.example.com", "/new")
		assert.Equal(t, -1, idx)
		// Append to the returned fc (federation section)
		fc.OauthClient = append(fc.OauthClient, PrefixEntry{Prefix: "/new"})
		assert.Equal(t, 1, len(cfg.Federation["https://fed.example.com"].OauthClient))
		assert.Equal(t, 0, len(cfg.OSDF.OauthClient))
	})
}

func TestFindTransferServer(t *testing.T) {
	t.Run("found in federation section", func(t *testing.T) {
		cfg := CredentialConfig{
			Federation: map[string]*FederationCredentials{
				"https://fed.example.com": {
					TransferServers: []TransferServerEntry{
						{ServerURL: "https://ts.example.com"},
					},
				},
			},
		}
		fc, idx := cfg.FindTransferServer("https://fed.example.com", "https://ts.example.com")
		assert.Equal(t, 0, idx)
		assert.Equal(t, "https://ts.example.com", fc.TransferServers[idx].ServerURL)
	})

	t.Run("falls back to OSDF", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{
				TransferServers: []TransferServerEntry{
					{ServerURL: "https://legacy-ts.example.com"},
				},
			},
			Federation: map[string]*FederationCredentials{
				"https://fed.example.com": {},
			},
		}
		fc, idx := cfg.FindTransferServer("https://fed.example.com", "https://legacy-ts.example.com")
		assert.Equal(t, 0, idx)
		assert.Equal(t, &cfg.OSDF, fc)
	})

	t.Run("not found returns federation section and -1", func(t *testing.T) {
		cfg := CredentialConfig{}
		fc, idx := cfg.FindTransferServer("https://fed.example.com", "https://nonexistent.example.com")
		assert.Equal(t, -1, idx)
		assert.NotNil(t, fc)
	})

	t.Run("trailing slash normalized", func(t *testing.T) {
		cfg := CredentialConfig{
			OSDF: FederationCredentials{
				TransferServers: []TransferServerEntry{
					{ServerURL: "https://ts.example.com/"},
				},
			},
		}
		fc, idx := cfg.FindTransferServer("https://fed.example.com", "https://ts.example.com")
		assert.Equal(t, 0, idx)
		assert.Equal(t, &cfg.OSDF, fc)
	})
}
