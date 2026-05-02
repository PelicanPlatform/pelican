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
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
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

			issuer, _, err := getIssuer(directorInfo, tc.localKeys)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectIssuer, issuer)
			}
		})
	}
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
// with the kid forced to the supplied value (mimicking issuers that assign
// short, non-thumbprint kids like "c2a5").
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
// remote issuer assigns the key a kid that differs from the SHA256 thumbprint.
//
// In the wild, OAuth2 issuers (e.g. Ory Hydra) publish RSA public keys with
// short, externally-assigned kids such as "c2a5". Pelican locally computes
// the kid via thumbprint (a long base64 SHA256). String-based kid comparison
// fails to match the same key, leaving the user with the misleading
// "provided issuer ... does not match the signing key" error and a token
// stamped with the wrong kid. The fix is to compare key material (RFC 7638
// thumbprints) rather than kid strings.
func TestGetIssuerWithRSAKeyMaterialMatch(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	tDir := t.TempDir()
	require.NoError(t, param.IssuerKeysDirectory.Set(tDir))
	require.NoError(t, param.ConfigDir.Set(t.TempDir()))

	rsaKeyPath := filepath.Join(tDir, "rsa-key.pem")
	writeRSAPEMKey(t, rsaKeyPath)

	// Build the issuer's JWKS with a short externally-assigned kid that does
	// not match the thumbprint Pelican computes locally.
	const externalKid = "c2a5"
	issuerJWKS := buildIssuerJWKSWithCustomKid(t, rsaKeyPath, externalKid)

	mockIssuerUrl := test_utils.MockIssuer(t, &issuerJWKS)
	mockIssuer, err := url.Parse(mockIssuerUrl)
	require.NoError(t, err)

	// Reproduce the client-side flow from cmd/token.go: load the same PEM
	// via the override path. Pelican computes the kid via thumbprint, so the
	// local JWKS will carry a long base64 kid, not "c2a5".
	clientJWKS, err := config.GetIssuerPublicJWKS(rsaKeyPath)
	require.NoError(t, err)

	it := clientJWKS.Keys(context.Background())
	for it.Next(context.Background()) {
		key := it.Pair().Value.(jwk.Key)
		require.NotEmpty(t, key.KeyID(), "client-side public key must have a kid")
		require.NotEqual(t, externalKid, key.KeyID(),
			"this regression test requires kids to differ between client and issuer")
	}

	directorInfo := server_structs.DirectorResponse{}
	directorInfo.XPelAuthHdr.Issuers = []*url.URL{mockIssuer}

	// The same RSA public key is on both sides; matching must succeed even
	// though the kid strings differ. The matched remote key must surface the
	// issuer's externally-assigned kid so callers can adopt it.
	issuer, matched, err := getIssuer(directorInfo, clientJWKS)
	require.NoError(t, err, "RSA key material must match issuer's JWKS even when kids differ")
	assert.Equal(t, mockIssuer.String(), issuer)
	require.NotNil(t, matched, "matched remote key must be returned for kid auto-detection")
	assert.Equal(t, externalKid, matched.KeyID(), "matched key must carry the issuer-assigned kid")

	// The single-issuer matcher used when --issuer is supplied directly must
	// also succeed and surface the issuer's kid.
	matchedDirect, err := issuerMatchesKey(mockIssuer.String(), clientJWKS)
	require.NoError(t, err)
	require.NotNil(t, matchedDirect, "issuerMatchesKey must accept matching key material with mismatched kids")
	assert.Equal(t, externalKid, matchedDirect.KeyID())

	// End-to-end: a token signed with the matched-but-rekid'd private key
	// must carry the issuer's externally-assigned kid in its JWS header,
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
		"auto-detected kid must be stamped on the JWS protected header")
}

// TestTokenCreateKidFlag ensures the `pelican token create --kid` flag is
// wired up so users can override the JWS 'kid' header. This is an escape
// hatch when issuers publish keys under a kid that differs from the
// SHA256-thumbprint Pelican computes locally.
func TestTokenCreateKidFlag(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	flag := tokenCreateCmd.Flags().Lookup("kid")
	require.NotNil(t, flag, "tokenCreateCmd must expose a --kid flag")
	assert.Equal(t, "string", flag.Value.Type())
	assert.Empty(t, flag.DefValue, "--kid must default to empty (no override)")
}

// TestSignTokenWithKidOverride exercises the signing path the --kid flag
// uses: a private key gets its kid forcibly set, then CreateTokenWithKey
// must emit a JWT whose JWS header carries that kid (rather than the
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
