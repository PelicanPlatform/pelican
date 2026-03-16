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

package origin_serve

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// ---------------------------------------------------------------------------
// NewGlobusBackend construction
// ---------------------------------------------------------------------------

func TestNewGlobusBackend_NotActivated(t *testing.T) {
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID:  "coll-id-123",
		HTTPSServer:   "https://g-12345.data.globus.org",
		StoragePrefix: "/mydata",
	})

	assert.False(t, gb.IsActivated())
	assert.NotNil(t, gb.FileSystem())
	assert.Nil(t, gb.Checksummer())
}

func TestNewGlobusBackend_WithTokens(t *testing.T) {
	tok := &oauth2.Token{
		AccessToken:  "collection-access-token",
		RefreshToken: "collection-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID:    "coll-id-456",
		HTTPSServer:     "https://g-99999.data.globus.org",
		StoragePrefix:   "/prefix",
		CollectionToken: tok,
		TransferToken:   &oauth2.Token{AccessToken: "transfer-tok"},
	})

	assert.True(t, gb.IsActivated())
}

// ---------------------------------------------------------------------------
// CheckAvailability
// ---------------------------------------------------------------------------

func TestGlobusBackend_CheckAvailability_NotActivated(t *testing.T) {
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID: "coll-x",
		HTTPSServer:  "https://g-x.data.globus.org",
	})

	err := gb.CheckAvailability()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not activated")

	// Should return 503
	if httpErr, ok := err.(*globusUnavailableError); ok {
		assert.Equal(t, http.StatusServiceUnavailable, httpErr.HTTPStatusCode())
	}
}

func TestGlobusBackend_CheckAvailability_Activated(t *testing.T) {
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID: "coll-y",
		HTTPSServer:  "https://g-y.data.globus.org",
		CollectionToken: &oauth2.Token{
			AccessToken: "valid-tok",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	})

	// When activated, CheckAvailability() succeeds (no upstream probe needed)
	require.NoError(t, gb.CheckAvailability())
}

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

func TestGlobusBackend_Activate(t *testing.T) {
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID: "coll-activate",
		HTTPSServer:  "https://g-a.data.globus.org",
	})
	assert.False(t, gb.IsActivated())

	collTok := &oauth2.Token{
		AccessToken:  "coll-tok",
		RefreshToken: "coll-refresh",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	transTok := &oauth2.Token{
		AccessToken: "trans-tok",
		Expiry:      time.Now().Add(1 * time.Hour),
	}

	gb.Activate(collTok, transTok, "https://g-new.data.globus.org", nil)
	assert.True(t, gb.IsActivated())
	require.NoError(t, gb.CheckAvailability())
}

// ---------------------------------------------------------------------------
// RefreshTokens
// ---------------------------------------------------------------------------

func TestGlobusBackend_RefreshTokens_NotActivated(t *testing.T) {
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID: "coll-norefresh",
		HTTPSServer:  "https://g-nr.data.globus.org",
	})
	// RefreshTokens on a non-activated backend should be a no-op
	require.NoError(t, gb.RefreshTokens())
}

func TestGlobusBackend_RefreshTokens_NotExpiring(t *testing.T) {
	gb := NewGlobusBackend(GlobusBackendConfig{
		CollectionID: "coll-fresh",
		HTTPSServer:  "https://g-f.data.globus.org",
		CollectionToken: &oauth2.Token{
			AccessToken:  "fresh-col",
			RefreshToken: "refresh-col",
			Expiry:       time.Now().Add(2 * time.Hour), // not near expiry
		},
		TransferToken: &oauth2.Token{
			AccessToken:  "fresh-trans",
			RefreshToken: "refresh-trans",
			Expiry:       time.Now().Add(2 * time.Hour),
		},
		OAuth2Config: &oauth2.Config{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://auth.globus.org/v2/oauth2/token",
			},
		},
	})

	// Tokens far from expiry — RefreshTokens should be a no-op
	require.NoError(t, gb.RefreshTokens())
}

// ---------------------------------------------------------------------------
// globusUnavailableError
// ---------------------------------------------------------------------------

func TestGlobusUnavailableError(t *testing.T) {
	err := &globusUnavailableError{
		collectionID: "abc-123",
		msg:          "not ready",
	}
	assert.Equal(t, "Globus collection abc-123: not ready", err.Error())
	assert.Equal(t, http.StatusServiceUnavailable, err.HTTPStatusCode())
}

// ---------------------------------------------------------------------------
// GetGlobusBackends
// ---------------------------------------------------------------------------

func TestGetGlobusBackends_Empty(t *testing.T) {
	// Save and restore original
	origMap := globusBackends
	defer func() { globusBackends = origMap }()

	globusBackends = nil
	result := GetGlobusBackends()
	assert.Empty(t, result)
}

func TestGetGlobusBackends_WithEntries(t *testing.T) {
	origMap := globusBackends
	defer func() { globusBackends = origMap }()

	gb1 := NewGlobusBackend(GlobusBackendConfig{CollectionID: "c1", HTTPSServer: "https://g1.data.globus.org"})
	gb2 := NewGlobusBackend(GlobusBackendConfig{CollectionID: "c2", HTTPSServer: "https://g2.data.globus.org"})

	globusBackends = map[string]*globusBackend{
		"c1": gb1,
		"c2": gb2,
	}

	result := GetGlobusBackends()
	assert.Len(t, result, 2)
	assert.NotNil(t, result["c1"])
	assert.NotNil(t, result["c2"])
}

// ---------------------------------------------------------------------------
// GlobusBackendActivator interface conformance
// ---------------------------------------------------------------------------

func TestGlobusBackend_ImplementsActivator(t *testing.T) {
	var _ GlobusBackendActivator = (*globusBackend)(nil)
}
