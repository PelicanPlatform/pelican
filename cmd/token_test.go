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

package main

import (
	"context"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestSplitClaim(t *testing.T) {
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
