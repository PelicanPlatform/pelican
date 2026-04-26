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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	pelican_url "github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
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

			var matched jwk.Key
			var verificationErr error
			if tc.useValidKey {
				matched, verificationErr = issuerMatchesKey(issuer, jwks)
			} else {
				strangerJWKSStr, err := test_utils.GenerateJWKS()
				require.NoError(t, err)
				strangerJWKS, err := jwk.ParseString(strangerJWKSStr)
				require.NoError(t, err)
				matched, verificationErr = issuerMatchesKey(issuer, strangerJWKS)
			}

			if tc.expectError {
				assert.Error(t, verificationErr)
			} else {
				assert.NoError(t, verificationErr)
				assert.Equal(t, tc.expectedResult, matched != nil)
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

	mockIssuerUrl := test_utils.MockIssuer(t, &jwks)
	mockIssuer, err := url.Parse(mockIssuerUrl)
	require.NoError(t, err)

	// A separate, unrelated JWKS used to exercise the "no match" case.
	nonMatchingJWKSStr, err := test_utils.GenerateJWKS()
	require.NoError(t, err)
	nonMatchingJWKS, err := jwk.ParseString(nonMatchingJWKSStr)
	require.NoError(t, err)

	testCases := []struct {
		name         string
		issuers      []*url.URL
		localKeys    jwk.Set
		expectError  bool
		expectIssuer string
	}{
		{
			name:        "no issuers in director response",
			issuers:     []*url.URL{},
			localKeys:   jwks,
			expectError: true,
		},
		{
			name:         "one issuer, matches key",
			issuers:      []*url.URL{mockIssuer},
			localKeys:    jwks,
			expectError:  false,
			expectIssuer: mockIssuer.String(),
		},
		{
			name:        "one issuer, does not match key",
			issuers:     []*url.URL{mockIssuer},
			localKeys:   nonMatchingJWKS,
			expectError: true,
		},
		{
			name: "multiple issuers, one unreachable, one matches",
			issuers: []*url.URL{
				{Scheme: "https", Host: "i-do-not-exist.com"},
				mockIssuer,
			},
			localKeys:    jwks,
			expectError:  false,
			expectIssuer: mockIssuer.String(),
		},
		{
			name: "multiple issuers, all unreachable",
			issuers: []*url.URL{
				{Scheme: "https", Host: "i-do-not-exist.com"},
				{Scheme: "https", Host: "also-not-real.com"},
			},
			localKeys:   jwks,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			directorInfo := server_structs.DirectorResponse{}
			directorInfo.XPelAuthHdr.Issuers = tc.issuers

			issuer, matched, err := getIssuer(directorInfo, tc.localKeys)
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, matched, "no matched key should be returned on error")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expectIssuer, issuer)
			require.NotNil(t, matched, "matched key must be returned on success")

			// On success, the matched key must come from the issuer's JWKS.
			// jwk.Equal compares by RFC 7638 thumbprint, so this verifies the
			// returned key's public material is one of the local set's keys.
			it := tc.localKeys.Keys(context.Background())
			matchFound := false
			for it.Next(context.Background()) {
				if jwk.Equal(matched, it.Pair().Value.(jwk.Key)) {
					matchFound = true
					break
				}
			}
			assert.True(t, matchFound, "returned matched key must equal a key in the local set by thumbprint")
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

	// A JWKS whose key material will never match the mock issuer's keys.
	// getIssuer compares by RFC 7638 thumbprint, so a freshly-generated
	// independent JWKS is guaranteed not to match.
	otherJWKSStr, err := test_utils.GenerateJWKS()
	require.NoError(t, err)
	nonMatchingJWKS, err := jwk.ParseString(otherJWKSStr)
	require.NoError(t, err)

	t.Run("issuers found but none match key mentions issuers checked", func(t *testing.T) {
		directorInfo := server_structs.DirectorResponse{}
		directorInfo.XPelAuthHdr.Issuers = []*url.URL{mockIssuer}

		_, _, err := getIssuer(directorInfo, nonMatchingJWKS)
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

		_, _, err := getIssuer(directorInfo, nonMatchingJWKS)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "/my/namespace")
	})
}

// writeRSAPEMKey writes a PKCS8-encoded RSA private key to the given path.
func writeRSAPEMKey(t *testing.T, path string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	require.NoError(t, err)
	defer f.Close()
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// buildIssuerJWKSWithCustomKid loads an RSA private key from the given PEM
// path, derives its public key, and returns a JWKS with that public key but
// with the KID forced to the supplied value (mimicking issuers that assign
// short, non-thumbprint KIDs like "c2a5").
func buildIssuerJWKSWithCustomKid(t *testing.T, pemPath, customKid string) jwk.Set {
	contents, err := os.ReadFile(pemPath)
	require.NoError(t, err)
	priv, err := jwk.ParseKey(contents, jwk.WithPEM(true))
	require.NoError(t, err)
	pub, err := jwk.PublicKeyOf(priv)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, customKid))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, "RS256"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pub))
	return set
}

// TestGetIssuerWithRSAKeyMaterialMatch is a regression test confirming that
// `pelican token create`'s public-key matching works with RSA keys when the
// remote issuer assigns the key a KID that differs from the SHA256 thumbprint.
//
// In the wild, OAuth2 issuers (e.g. Ory Hydra) publish RSA public keys with
// short, externally-assigned KIDs such as "c2a5". Pelican locally computes
// the KID via thumbprint (a long base64 SHA256). String-based KID comparison
// fails to match the same key, leaving the user with the misleading
// "provided issuer ... does not match the signing key" error and a token
// stamped with the wrong KID. The fix is to compare key material (RFC 7638
// thumbprints) rather than KID strings.
func TestGetIssuerWithRSAKeyMaterialMatch(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	tDir := t.TempDir()
	require.NoError(t, param.IssuerKeysDirectory.Set(tDir))
	require.NoError(t, param.ConfigBase.Set(t.TempDir()))

	rsaKeyPath := filepath.Join(tDir, "rsa-key.pem")
	writeRSAPEMKey(t, rsaKeyPath)

	// Build the issuer's JWKS with a short externally-assigned KID that does
	// not match the thumbprint Pelican computes locally.
	const externalKid = "c2a5"
	issuerJWKS := buildIssuerJWKSWithCustomKid(t, rsaKeyPath, externalKid)

	mockIssuerUrl := test_utils.MockIssuer(t, &issuerJWKS)
	mockIssuer, err := url.Parse(mockIssuerUrl)
	require.NoError(t, err)

	// Reproduce the client-side flow from cmd/token.go: load the same PEM
	// via the override path. Pelican computes the KID via thumbprint, so the
	// local JWKS will carry a long base64 KID, not "c2a5".
	clientJWKS, err := config.GetIssuerPublicJWKS(rsaKeyPath)
	require.NoError(t, err)

	it := clientJWKS.Keys(context.Background())
	for it.Next(context.Background()) {
		key := it.Pair().Value.(jwk.Key)
		require.NotEmpty(t, key.KeyID(), "client-side public key must have a KID")
		require.NotEqual(t, externalKid, key.KeyID(),
			"this regression test requires KIDs to differ between client and issuer")
	}

	directorInfo := server_structs.DirectorResponse{}
	directorInfo.XPelAuthHdr.Issuers = []*url.URL{mockIssuer}

	// The same RSA public key is on both sides; matching must succeed even
	// though the KID strings differ. The matched remote key must surface the
	// issuer's externally-assigned KID so callers can adopt it.
	issuer, matched, err := getIssuer(directorInfo, clientJWKS)
	require.NoError(t, err, "RSA key material must match issuer's JWKS even when KIDs differ")
	assert.Equal(t, mockIssuer.String(), issuer)
	require.NotNil(t, matched, "matched remote key must be returned for KID auto-detection")
	assert.Equal(t, externalKid, matched.KeyID(), "matched key must carry the issuer-assigned KID")

	// The single-issuer matcher used when --issuer is supplied directly must
	// also succeed and surface the issuer's KID.
	matchedDirect, err := issuerMatchesKey(mockIssuer.String(), clientJWKS)
	require.NoError(t, err)
	require.NotNil(t, matchedDirect, "issuerMatchesKey must accept matching key material with mismatched KIDs")
	assert.Equal(t, externalKid, matchedDirect.KeyID())

	// End-to-end: a token signed with the matched-but-rekid'd private key
	// must carry the issuer's externally-assigned KID in its JWS header,
	// without the user having to pass --kid.
	signingKey, err := config.GetIssuerPrivateJWK(rsaKeyPath)
	require.NoError(t, err)
	require.NoError(t, signingKey.Set(jwk.KeyIDKey, matched.KeyID()))

	tc, err := token.NewTokenConfig(token.WlcgProfile{})
	require.NoError(t, err)
	tc.AddAudiences("any")
	tc.Subject = "test"
	tc.Issuer = mockIssuer.String()
	tc.Lifetime = time.Minute

	tokStr, err := tc.CreateTokenWithKey(signingKey)
	require.NoError(t, err)

	msg, err := jws.ParseString(tokStr)
	require.NoError(t, err)
	require.Len(t, msg.Signatures(), 1)
	assert.Equal(t, externalKid, msg.Signatures()[0].ProtectedHeaders().KeyID(),
		"auto-detected KID must be stamped on the JWS protected header")
}

// TestTokenCreateKidFlag is a wiring-only check: it asserts the
// `pelican token create --kid` flag is registered with the expected type
// and default value, so a code change can't silently drop it. The
// end-to-end behavior (the override actually surfacing in the JWS header)
// is covered by TestTokenCreateKidFlagOverridesJWS.
func TestTokenCreateKidFlag(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	flag := tokenCreateCmd.Flags().Lookup("kid")
	require.NotNil(t, flag, "tokenCreateCmd must expose a --kid flag")
	assert.Equal(t, "string", flag.Value.Type())
	assert.Empty(t, flag.DefValue, "--kid must default to empty (no override)")
}

// TestTokenCreateKidFlagOverridesJWS exercises the full createToken flow with
// --kid set, against a mock issuer whose JWKS publishes the matching public
// key under a *different* KID. The user-supplied override must win — neither
// the auto-detected remote KID nor the locally-computed thumbprint may leak
// into the JWS protected header.
func TestTokenCreateKidFlagOverridesJWS(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	tDir := t.TempDir()
	require.NoError(t, param.IssuerKeysDirectory.Set(tDir))
	require.NoError(t, param.ConfigBase.Set(t.TempDir()))

	rsaKeyPath := filepath.Join(tDir, "rsa-key.pem")
	writeRSAPEMKey(t, rsaKeyPath)

	const remoteKid = "remote-kid-c2a5"
	issuerJWKS := buildIssuerJWKSWithCustomKid(t, rsaKeyPath, remoteKid)
	mockIssuerUrl := test_utils.MockIssuer(t, &issuerJWKS)

	const overrideKid = "user-supplied-kid"

	// Reset every flag we touch after the test so that leaked state doesn't
	// affect later tests.
	t.Cleanup(func() {
		for _, name := range []string{"kid", "issuer", "scope-path", "private-key", "read", "write", "modify", "stage"} {
			if f := tokenCreateCmd.Flags().Lookup(name); f != nil {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			}
		}
	})

	require.NoError(t, tokenCreateCmd.Flags().Set("kid", overrideKid))
	require.NoError(t, tokenCreateCmd.Flags().Set("issuer", mockIssuerUrl))
	require.NoError(t, tokenCreateCmd.Flags().Set("scope-path", "/foo"))
	require.NoError(t, tokenCreateCmd.Flags().Set("read", "true"))
	require.NoError(t, tokenCreateCmd.Flags().Set("private-key", rsaKeyPath))

	// Capture stdout to read the printed JWT.
	origStdout := os.Stdout
	r, w, pipeErr := os.Pipe()
	require.NoError(t, pipeErr)
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	createErr := createToken(tokenCreateCmd, []string{"pelican://invalid-url-for-this-test"})
	require.NoError(t, w.Close())
	os.Stdout = origStdout

	out, readErr := io.ReadAll(r)
	require.NoError(t, readErr)
	require.NoError(t, createErr)

	tokStr := strings.TrimSpace(string(out))
	require.NotEmpty(t, tokStr)

	msg, err := jws.ParseString(tokStr)
	require.NoError(t, err)
	require.Len(t, msg.Signatures(), 1)
	hdrKid := msg.Signatures()[0].ProtectedHeaders().KeyID()
	assert.Equal(t, overrideKid, hdrKid,
		"--kid override must win over the auto-detected remote KID")
	assert.NotEqual(t, remoteKid, hdrKid,
		"the matched remote KID must not leak into the JWS header when --kid is supplied")
}

// TestSignTokenWithKidOverride exercises the signing path the --kid flag
// uses: a private key gets its KID forcibly set, then CreateTokenWithKey
// must emit a JWT whose JWS header carries that KID (rather than the
// thumbprint AssignKeyID would normally compute).
func TestSignTokenWithKidOverride(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	tDir := t.TempDir()
	keyPath := filepath.Join(tDir, "rsa-key.pem")
	writeRSAPEMKey(t, keyPath)

	priv, err := config.GetIssuerPrivateJWK(keyPath)
	require.NoError(t, err)

	const overrideKid = "c2a5"
	require.NoError(t, priv.Set(jwk.KeyIDKey, overrideKid))

	tc, err := token.NewTokenConfig(token.WlcgProfile{})
	require.NoError(t, err)
	tc.AddAudiences("any")
	tc.Subject = "test"
	tc.Issuer = "https://issuer.example.com"
	tc.Lifetime = time.Minute

	tokStr, err := tc.CreateTokenWithKey(priv)
	require.NoError(t, err)

	msg, err := jws.ParseString(tokStr)
	require.NoError(t, err)
	require.Len(t, msg.Signatures(), 1)
	assert.Equal(t, overrideKid, msg.Signatures()[0].ProtectedHeaders().KeyID(),
		"--kid override must surface in the JWS protected header")
}
