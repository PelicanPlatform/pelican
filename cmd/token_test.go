//go:build client || server

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

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	pelican_url "github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestSplitClaim(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name          string
		claim         string
		expectedKey   string
		expectedValue string
		expectError   bool
	}{
		{
			name:          "valid claim",
			claim:         "foo=bar",
			expectedKey:   "foo",
			expectedValue: "bar",
			expectError:   false,
		},
		{
			name:          "valid claim, multiple '='",
			claim:         "foo=bar=baz",
			expectedKey:   "foo",
			expectedValue: "bar=baz",
			expectError:   false,
		},
		{
			name:          "invalid claim, no '='",
			claim:         "foobar",
			expectedKey:   "",
			expectedValue: "",
			expectError:   true,
		},
		{
			name:          "invalid claim, empty key",
			claim:         "=bar",
			expectedKey:   "",
			expectedValue: "",
			expectError:   true,
		},
		{
			name:          "invalid claim, empty value",
			claim:         "foo=",
			expectedKey:   "",
			expectedValue: "",
			expectError:   true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, value, err := splitClaim(tc.claim)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedKey, key)
				assert.Equal(t, tc.expectedValue, value)
			}
		})
	}
}

func TestIssuerMatchesKey(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name           string
		useMockIssuer  bool
		useValidKey    bool
		expectedResult bool
		expectError    bool
	}{
		{
			name:           "issuer DNE",
			useMockIssuer:  false,
			useValidKey:    false,
			expectedResult: false,
			expectError:    true,
		},
		{
			name:           "issuer exists, has matching key",
			useMockIssuer:  true,
			useValidKey:    true,
			expectedResult: true,
			expectError:    false,
		},
		{
			name:           "issuer exists, does not have matching key",
			useMockIssuer:  true,
			useValidKey:    false,
			expectedResult: false,
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwksStr, err := test_utils.GenerateJWKS()
			require.NoError(t, err)
			jwks, err := jwk.ParseString(jwksStr)
			require.NoError(t, err)

			var issuer string
			if tc.useMockIssuer {
				issuer = test_utils.MockIssuer(t, &jwks)
			} else {
				issuer = "https://i-do-not-exist.com"
			}

			var result bool
			var verificationErr error
			if tc.useValidKey {
				var kidSet = make(map[string]struct{})
				it := jwks.Keys(context.Background())
				for it.Next(context.Background()) {
					key := it.Pair().Value.(jwk.Key)
					kidSet[key.KeyID()] = struct{}{}
				}
				result, verificationErr = issuerMatchesKey(issuer, kidSet)
			} else {
				result, verificationErr = issuerMatchesKey(issuer, map[string]struct{}{"1234abcd": {}})
			}

			if tc.expectError {
				assert.Error(t, verificationErr)
			} else {
				assert.NoError(t, verificationErr)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestGetIssuer(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	jwksStr, err := test_utils.GenerateJWKS()
	require.NoError(t, err)
	jwks, err := jwk.ParseString(jwksStr)
	require.NoError(t, err)

	// Build kidSet from the generated JWKS
	kidSet := make(map[string]struct{})
	it := jwks.Keys(context.Background())
	for it.Next(context.Background()) {
		key := it.Pair().Value.(jwk.Key)
		kidSet[key.KeyID()] = struct{}{}
	}

	mockIssuerUrl := test_utils.MockIssuer(t, &jwks)
	mockIssuer, err := url.Parse(mockIssuerUrl)
	require.NoError(t, err)

	nonMatchingKidSet := map[string]struct{}{"notarealkid": {}}

	testCases := []struct {
		name         string
		issuers      []*url.URL
		kidSet       map[string]struct{}
		expectError  bool
		expectIssuer string
	}{
		{
			name:        "no issuers in director response",
			issuers:     []*url.URL{},
			kidSet:      kidSet,
			expectError: true,
		},
		{
			name:         "one issuer, matches key",
			issuers:      []*url.URL{mockIssuer},
			kidSet:       kidSet,
			expectError:  false,
			expectIssuer: mockIssuer.String(),
		},
		{
			name:        "one issuer, does not match key",
			issuers:     []*url.URL{mockIssuer},
			kidSet:      nonMatchingKidSet,
			expectError: true,
		},
		{
			name: "multiple issuers, one unreachable, one matches",
			issuers: []*url.URL{
				{Scheme: "https", Host: "i-do-not-exist.com"},
				mockIssuer,
			},
			kidSet:       kidSet,
			expectError:  false,
			expectIssuer: mockIssuer.String(),
		},
		{
			name: "multiple issuers, all unreachable",
			issuers: []*url.URL{
				{Scheme: "https", Host: "i-do-not-exist.com"},
				{Scheme: "https", Host: "also-not-real.com"},
			},
			kidSet:      kidSet,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			directorInfo := server_structs.DirectorResponse{}
			directorInfo.XPelAuthHdr.Issuers = tc.issuers

			issuer, err := getIssuer(directorInfo, tc.kidSet)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectIssuer, issuer)
			}
		})
	}
}

// mockDirectorNsEndpoint starts a test HTTP server that serves the Director UI
// namespaces endpoint (/api/v1.0/director_ui/namespaces) with the provided
// namespace ads. It injects the server URL directly into the federation config
// so that getNsAd can reach it, and resets federation state on cleanup.
func mockDirectorNsEndpoint(t *testing.T, nsAds []server_structs.NamespaceAdV2Response) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1.0/director_ui/namespaces" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(nsAds))
	}))
	t.Cleanup(func() {
		server.Close()
		config.ResetFederationForTest()
	})
	config.ResetFederationForTest()
	config.SetFederation(pelican_url.FederationDiscovery{
		DirectorEndpoint:  server.URL,
		DiscoveryEndpoint: server.URL,
	})
	return server.URL
}

func TestGetNsAd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(config.ResetFederationForTest)

	// A minimal namespace ad used across several cases.
	readNs := server_structs.NamespaceAdV2Response{
		Path: "/test/prefix",
		Caps: server_structs.Capabilities{Reads: true, Writes: false},
	}
	writeNs := server_structs.NamespaceAdV2Response{
		Path: "/write/prefix",
		Caps: server_structs.Capabilities{Reads: true, Writes: true},
	}
	publicNs := server_structs.NamespaceAdV2Response{
		Path: "/public/prefix",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	}

	testCases := []struct {
		name        string
		nsAds       []server_structs.NamespaceAdV2Response
		namespace   string // what the DirectorResponse reports as the namespace
		expectError bool
		expectCaps  server_structs.Capabilities
		expectPath  string
	}{
		{
			name:        "matching namespace found",
			nsAds:       []server_structs.NamespaceAdV2Response{readNs, writeNs},
			namespace:   "/test/prefix",
			expectError: false,
			expectCaps:  readNs.Caps,
			expectPath:  readNs.Path,
		},
		{
			name:        "matching namespace with trailing slash normalised",
			nsAds:       []server_structs.NamespaceAdV2Response{readNs},
			namespace:   "/test/prefix/",
			expectError: false,
			expectCaps:  readNs.Caps,
			expectPath:  readNs.Path,
		},
		{
			name:        "write-capable namespace found",
			nsAds:       []server_structs.NamespaceAdV2Response{writeNs},
			namespace:   "/write/prefix",
			expectError: false,
			expectCaps:  writeNs.Caps,
			expectPath:  writeNs.Path,
		},
		{
			name:        "public-read namespace found",
			nsAds:       []server_structs.NamespaceAdV2Response{publicNs},
			namespace:   "/public/prefix",
			expectError: false,
			expectCaps:  publicNs.Caps,
			expectPath:  publicNs.Path,
		},
		{
			name:        "namespace not in Director response",
			nsAds:       []server_structs.NamespaceAdV2Response{readNs},
			namespace:   "/does/not/exist",
			expectError: true,
		},
		{
			name:        "empty namespace list",
			nsAds:       []server_structs.NamespaceAdV2Response{},
			namespace:   "/test/prefix",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDirectorNsEndpoint(t, tc.nsAds)

			directorInfo := server_structs.DirectorResponse{}
			directorInfo.XPelNsHdr.Namespace = tc.namespace

			got, err := getNsAd(directorInfo)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectPath, got.Path)
				assert.Equal(t, tc.expectCaps, got.Caps)
			}
		})
	}
}

func TestGetNsAdHTTPErrors(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("director returns non-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(func() {
			server.Close()
			config.ResetFederationForTest()
		})
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{
			DirectorEndpoint:  server.URL,
			DiscoveryEndpoint: server.URL,
		})

		directorInfo := server_structs.DirectorResponse{}
		directorInfo.XPelNsHdr.Namespace = "/test/prefix"

		_, err := getNsAd(directorInfo)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("director returns invalid JSON", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not valid json"))
		}))
		t.Cleanup(func() {
			server.Close()
			config.ResetFederationForTest()
		})
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{
			DirectorEndpoint:  server.URL,
			DiscoveryEndpoint: server.URL,
		})

		directorInfo := server_structs.DirectorResponse{}
		directorInfo.XPelNsHdr.Namespace = "/test/prefix"

		_, err := getNsAd(directorInfo)
		require.Error(t, err)
	})

	t.Run("director unreachable", func(t *testing.T) {
		t.Cleanup(config.ResetFederationForTest)
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{
			DirectorEndpoint:  "http://127.0.0.1:1",
			DiscoveryEndpoint: "http://127.0.0.1:1",
		})

		directorInfo := server_structs.DirectorResponse{}
		directorInfo.XPelNsHdr.Namespace = "/test/prefix"

		_, err := getNsAd(directorInfo)
		require.Error(t, err)
	})
}

// newTokenCreateTestCmd builds a fresh `token create` command using the same
// flag-registration code as the real CLI (addTokenCreateFlags), so the test
// cannot drift from the actual command. Because the flags are registered on a
// fresh command (and no longer bind to shared package globals), flag state does
// not leak between test cases.
func newTokenCreateTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "create"}
	addTokenCreateFlags(cmd)
	return cmd
}

// setupTokenCmdTest isolates global config/viper state for a createToken test
// and quiets logging.
func setupTokenCmdTest(t *testing.T) {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	require.NoError(t, param.ConfigBase.Set(t.TempDir()))
}

// TestCreateTokenEarlyValidation covers the fast-feedback validation that
// happens before any network calls: profile parsing and --expiration handling.
func TestCreateTokenEarlyValidation(t *testing.T) {
	testCases := []struct {
		name       string
		profile    string
		expiration string
		expectErr  string
	}{
		{
			name:      "unknown profile",
			profile:   "not-a-profile",
			expectErr: "unable to parse token profile",
		},
		{
			name:       "malformed expiration",
			profile:    "wlcg",
			expiration: "tomorrow",
			expectErr:  "RFC3339",
		},
		{
			name:       "expiration in the past",
			profile:    "wlcg",
			expiration: "2000-01-01T00:00:00Z",
			expectErr:  "already in the past",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTokenCmdTest(t)
			cmd := newTokenCreateTestCmd()
			require.NoError(t, cmd.Flags().Set("profile", tc.profile))
			if tc.expiration != "" {
				require.NoError(t, cmd.Flags().Set("expiration", tc.expiration))
			}

			// The arg is never reached for these cases, but createToken expects one.
			err := createToken(cmd, []string{"pelican://example.com/foo/bar"})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectErr)
		})
	}
}

// TestCreateTokenDiscoveryFailure verifies that when the pelican URL cannot be
// parsed/discovered and the user supplies neither --issuer nor --scope-path,
// createToken surfaces the discovery failure rather than proceeding.
func TestCreateTokenDiscoveryFailure(t *testing.T) {
	setupTokenCmdTest(t)
	cmd := newTokenCreateTestCmd()
	require.NoError(t, cmd.Flags().Set("read", "true"))

	// A host-less pelican URL fails to parse without any network access.
	err := createToken(cmd, []string{"pelican:///no/host/path"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Failed to get director info")
}

// TestCreateTokenOfflineWithIssuer exercises the path where director discovery
// fails but the user provides enough information (--issuer + --scope-path) for
// createToken to mint a token without ever reaching a Director. The local
// signing key is matched against a mock issuer's JWKS.
func TestCreateTokenOfflineWithIssuer(t *testing.T) {
	setupTokenCmdTest(t)

	// Generate a local signing key and stand up a mock issuer that advertises it.
	kDir := filepath.Join(t.TempDir(), "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(kDir))
	pubJWKS, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	issuerUrl := test_utils.MockIssuer(t, &pubJWKS)

	cmd := newTokenCreateTestCmd()
	require.NoError(t, cmd.Flags().Set("read", "true"))
	require.NoError(t, cmd.Flags().Set("issuer", issuerUrl))
	require.NoError(t, cmd.Flags().Set("scope-path", "/foo"))
	require.NoError(t, cmd.Flags().Set("lifetime", "600"))

	// The URL fails to parse, so discovery is skipped and the supplied
	// --issuer/--scope-path are used instead.
	err = createToken(cmd, []string{"pelican:///no/host/path"})
	require.NoError(t, err)
}

func TestGetIssuerErrorMessages(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	jwksStr, err := test_utils.GenerateJWKS()
	require.NoError(t, err)
	jwks, err := jwk.ParseString(jwksStr)
	require.NoError(t, err)

	mockIssuerUrl := test_utils.MockIssuer(t, &jwks)
	mockIssuer, err := url.Parse(mockIssuerUrl)
	require.NoError(t, err)

	// A KID set that will never match the mock issuer's keys.
	nonMatchingKidSet := map[string]struct{}{"notarealkid": {}}

	t.Run("issuers found but none match key mentions issuers checked", func(t *testing.T) {
		directorInfo := server_structs.DirectorResponse{}
		directorInfo.XPelAuthHdr.Issuers = []*url.URL{mockIssuer}

		_, err := getIssuer(directorInfo, nonMatchingKidSet)
		require.Error(t, err)
		assert.Contains(t, err.Error(), mockIssuerUrl,
			"error should name the issuer(s) that were checked")
		assert.True(t,
			strings.Contains(err.Error(), "match") || strings.Contains(err.Error(), "signing key"),
			"error should indicate the key-mismatch nature of the failure")
	})

	t.Run("no issuers in director response mentions namespace", func(t *testing.T) {
		directorInfo := server_structs.DirectorResponse{}
		directorInfo.XPelNsHdr.Namespace = "/my/namespace"
		directorInfo.XPelAuthHdr.Issuers = []*url.URL{}

		_, err := getIssuer(directorInfo, nonMatchingKidSet)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/my/namespace")
	})
}
