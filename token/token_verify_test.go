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

package token

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	pelican_url "github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// MockAuthChecker is the mock implementation of AuthChecker.
type MockAuthChecker struct {
	FederationCheckFunc       func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error
	IssuerCheckFunc           func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error
	RegisteredServerCheckFunc func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error
}

func (m *MockAuthChecker) checkFederationIssuer(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
	return m.FederationCheckFunc(ctx, token, expectedScopes, allScope)
}

func (m *MockAuthChecker) checkLocalIssuer(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
	return m.IssuerCheckFunc(ctx, token, expectedScopes, allScope)
}

func (m *MockAuthChecker) checkRegisteredServer(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
	return m.RegisteredServerCheckFunc(ctx, token, expectedScopes, allScope)
}

// Helper function to create a gin context with different token sources
func createContextWithToken(cookieToken, headerToken, queryToken string) *gin.Context {
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	if cookieToken != "" {
		r.AddCookie(&http.Cookie{Name: "login", Value: cookieToken})
	}
	if headerToken != "" {
		r.Header.Add("Authorization", "Bearer "+headerToken)
	}
	if queryToken != "" {
		q := r.URL.Query()
		q.Add("authz", queryToken)
		r.URL.RawQuery = q.Encode()
	}

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = r

	return ctx
}

func TestVerify(t *testing.T) {
	// Use a mock instance of authChecker to simplify testing
	originalAuthChecker := authChecker
	defer func() { authChecker = originalAuthChecker }()

	// Create the mock for varioud checkers
	mock := &MockAuthChecker{
		FederationCheckFunc: func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
			if token != "" {
				ctx.Set("User", "Federation")
				return nil
			} else {
				return errors.New("No token is present")
			}
		},
		IssuerCheckFunc: func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
			if token != "" {
				ctx.Set("User", "Issuer")
				return nil
			} else {
				return errors.New("No token is present")
			}
		},
		RegisteredServerCheckFunc: func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
			if token != "" {
				ctx.Set("AuthMethod", "registered-server-token")
				return nil
			} else {
				return errors.New("No token is present")
			}
		},
	}

	authChecker = mock

	// Batch-create test cases, see "name" section for the purpose of each test case
	tests := []struct {
		name           string
		setupMock      func()
		tokenSetup     func() *gin.Context
		authOption     AuthOption
		expectedResult bool
		expectedStatus int
		expectedErr    error
	}{
		{
			name: "valid-token-from-cookie-source",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{FederationIssuer},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("valid-cookie-token", "", "")
			},
			expectedResult: true,
		},
		{
			name: "valid-token-from-header-source",
			authOption: AuthOption{
				Sources: []TokenSource{Header},
				Issuers: []TokenIssuer{FederationIssuer},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "valid-header-token", "")
			},
			expectedResult: true,
		},
		{
			name: "valid-token-from-authz-query-parameter",
			authOption: AuthOption{
				Sources: []TokenSource{Authz},
				Issuers: []TokenIssuer{FederationIssuer},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "", "valid-query-token")
			},
			expectedResult: true,
		},
		{
			name: "no-token-present",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie, Header, Authz},
				Issuers: []TokenIssuer{},
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "", "")
			},
			expectedResult: false,
			expectedStatus: 403, // Return 403 as RFC requires returning 401 with WWW-Authenticate response header and we don't have it
		},
		{
			name: "get-first-available-token-from-multiple-sources",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie, Header, Authz},
				Issuers: []TokenIssuer{FederationIssuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "valid-cookie" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Token is not from cookie: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("valid-cookie", "valid-header", "valid-authz")
			},
			expectedResult: true,
		},
		{
			name: "valid-token-with-single-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{FederationIssuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "valid-cookie" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Token is not from cookie: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("valid-cookie", "", "")
			},
			expectedResult: true,
		},
		{
			name: "invalid-token-with-single-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{FederationIssuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "valid-cookie" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("invalid-cookie", "", "")
			},
			expectedResult: false,
			expectedStatus: 403,
		},
		{
			name: "valid-token-with-multiple-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{FederationIssuer, LocalIssuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "for-federation" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
				mock.IssuerCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "for-issuer" {
						ctx.Set("User", "Issuer")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("for-issuer", "", "")
			},
			expectedResult: true,
		},
		{
			name: "invalid-token-with-multiple-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Cookie},
				Issuers: []TokenIssuer{FederationIssuer, LocalIssuer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "for-federation" {
						ctx.Set("User", "Federation")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
				mock.IssuerCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "for-issuer" {
						ctx.Set("User", "Issuer")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				// Set token in both cookie and header, but function should stop at the first valid source
				return createContextWithToken("for-nobody", "", "")
			},
			expectedResult: false,
			expectedStatus: 403,
		},
		{
			name: "valid-token-with-registered-server-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Header},
				Issuers: []TokenIssuer{RegisteredServer},
			},
			setupMock: func() {
				mock.RegisteredServerCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "valid-server-token" {
						ctx.Set("AuthMethod", "registered-server-token")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "valid-server-token", "")
			},
			expectedResult: true,
		},
		{
			name: "invalid-token-with-registered-server-issuer",
			authOption: AuthOption{
				Sources: []TokenSource{Header},
				Issuers: []TokenIssuer{RegisteredServer},
			},
			setupMock: func() {
				mock.RegisteredServerCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "valid-server-token" {
						ctx.Set("AuthMethod", "registered-server-token")
						return nil
					}
					return errors.New(fmt.Sprint("Invalid Token: ", token))
				}
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "invalid-server-token", "")
			},
			expectedResult: false,
			expectedStatus: 403,
		},
		{
			name: "valid-token-with-multiple-issuers-including-registered-server",
			authOption: AuthOption{
				Sources: []TokenSource{Header},
				Issuers: []TokenIssuer{FederationIssuer, LocalIssuer, RegisteredServer},
			},
			setupMock: func() {
				mock.FederationCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					return errors.New("Not a federation token")
				}
				mock.IssuerCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					return errors.New("Not a local issuer token")
				}
				mock.RegisteredServerCheckFunc = func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
					if token == "server-token" {
						ctx.Set("AuthMethod", "registered-server-token")
						return nil
					}
					return errors.New("Not a registered server token")
				}
			},
			tokenSetup: func() *gin.Context {
				return createContextWithToken("", "server-token", "")
			},
			expectedResult: true,
		},
	}

	// Batch-run the test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupMock != nil {
				// We might have different mocks to the checker function,
				// so we have this flexibility by calling setupmock if there is such function
				tc.setupMock()
			}
			require.NotNil(t, tc.tokenSetup, "tokenSetup function can't be nil")

			ctx := tc.tokenSetup()

			status, ok, err := Verify(ctx, tc.authOption)
			assert.Equal(t, ok, tc.expectedResult)
			if !ok {
				assert.Equal(t, tc.expectedStatus, status, "status code does not match expected")
				assert.NotNil(t, err)
			}
		})
	}

}

func TestGetAuthzEscaped(t *testing.T) {
	// Test passing a token via header with no bearer prefix
	req, err := http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "tokenstring")
	ctx := &gin.Context{Request: req}
	escapedToken := GetAuthzEscaped(ctx)
	assert.Equal(t, escapedToken, "tokenstring")

	// Test passing a token via query with no bearer prefix
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	ctx = &gin.Context{Request: req}
	escapedToken = GetAuthzEscaped(ctx)
	assert.Equal(t, escapedToken, "tokenstring")

	// Test passing the token via header with Bearer prefix
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	ctx = &gin.Context{Request: req}
	req.Header.Set("Authorization", "Bearer tokenstring")
	escapedToken = GetAuthzEscaped(ctx)
	assert.Equal(t, escapedToken, "tokenstring")

	// Test passing the token via URL with Bearer prefix and + encoded space
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=Bearer+tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	ctx = &gin.Context{Request: req}
	escapedToken = GetAuthzEscaped(ctx)
	assert.Equal(t, escapedToken, "tokenstring")

	// Finally, the same test as before, but test with %20 encoded space
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=Bearer%20tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	ctx = &gin.Context{Request: req}
	escapedToken = GetAuthzEscaped(ctx)
	assert.Equal(t, escapedToken, "tokenstring")
}

// makeTestKeyset generates a fresh ECDSA P-256 key pair for use in tests.
// It returns the private key (for signing) and a JWKS containing only the
// public key (for verification).
func makeTestKeyset(t *testing.T) (jwk.Key, jwk.Set) {
	t.Helper()
	privRaw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privKey, err := jwk.FromRaw(privRaw)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.ES256))

	pubKey, err := privKey.PublicKey()
	require.NoError(t, err)
	pubSet := jwk.NewSet()
	require.NoError(t, pubSet.AddKey(pubKey))
	return privKey, pubSet
}

// makeSignedToken creates a signed JWT with the given iat, nbf, and exp times.
func makeSignedToken(t *testing.T, privKey jwk.Key, iat, nbf, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		IssuedAt(iat).
		NotBefore(nbf).
		Expiration(exp).
		Subject("test-subject").
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
	require.NoError(t, err)
	return string(signed)
}

// makeSignedTokenWithIssuer creates a signed JWT with the given iat, nbf, exp times,
// and an explicit issuer.
func makeSignedTokenWithIssuer(t *testing.T, privKey jwk.Key, iat, nbf, exp time.Time, issuer string) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		IssuedAt(iat).
		NotBefore(nbf).
		Expiration(exp).
		Subject("test-subject").
		Issuer(issuer).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
	require.NoError(t, err)
	return string(signed)
}

// TestUnsafeParseClaims verifies that UnsafeParseClaims extracts claims
// from tokens whose time claims would normally fail validation.
func TestUnsafeParseClaims(t *testing.T) {
	privKey, _ := makeTestKeyset(t)
	now := time.Now()

	// Token with iat/nbf two hours in the future and exp two hours in the past.
	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(2*time.Hour),
		now.Add(2*time.Hour),
		now.Add(-2*time.Hour),
	)

	tok, err := UnsafeParseClaims(tokenStr)
	require.NoError(t, err, "UnsafeParseClaims should succeed regardless of time claims")
	assert.Equal(t, "test-subject", tok.Subject())
}

// TestVerifyWithKeyset_IatNbfWithinLeeway confirms that a token
// whose iat and nbf are in the future but within ClockSkewLeeway is accepted.
func TestVerifyWithKeyset_IatNbfWithinLeeway(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, err := VerifyWithKeyset(tokenStr, pubSet)
	assert.NoError(t, err, "token with iat/nbf within leeway should be accepted")
}

// TestVerifyWithKeyset_IatNbfExceedsLeeway confirms that a token
// whose iat and nbf exceed ClockSkewLeeway is rejected.
func TestVerifyWithKeyset_IatNbfExceedsLeeway(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway + 2*time.Minute // well beyond the acceptance window

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, err := VerifyWithKeyset(tokenStr, pubSet)
	assert.Error(t, err, "token with iat/nbf exceeding leeway should be rejected")
}

// TestVerifyWithKeyset_ExpWithinLeeway confirms that a token
// whose exp is in the past but within ClockSkewLeeway is accepted.
func TestVerifyWithKeyset_ExpWithinLeeway(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(-10*time.Minute),
		now.Add(-10*time.Minute),
		now.Add(-skew),
	)

	_, err := VerifyWithKeyset(tokenStr, pubSet)
	assert.NoError(t, err, "token expired within leeway should be accepted")
}

// TestVerifyWithKeyset_ExpExceedsLeeway confirms that a token
// whose exp exceeds ClockSkewLeeway in the past is rejected.
func TestVerifyWithKeyset_ExpExceedsLeeway(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway + 2*time.Minute // well beyond the acceptance window

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(-10*time.Minute),
		now.Add(-10*time.Minute),
		now.Add(-skew),
	)

	_, err := VerifyWithKeyset(tokenStr, pubSet)
	assert.Error(t, err, "token expired beyond leeway should be rejected")
}

// TestVerifyWithKeyset_CallerSkewCannotShrinkLeeway confirms that
// a caller passing WithAcceptableSkew(0) does not override ClockSkewLeeway —
// a token within ClockSkewLeeway must still be accepted.
func TestVerifyWithKeyset_CallerSkewCannotShrinkLeeway(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, err := VerifyWithKeyset(tokenStr, pubSet, jwt.WithAcceptableSkew(0))
	assert.NoError(t, err, "caller WithAcceptableSkew(0) must not reduce the effective leeway below ClockSkewLeeway")
}

// TestVerifyWithKeyset_CallerSkewCannotExpandLeeway confirms that
// a caller passing a large WithAcceptableSkew does not suppress a real rejection —
// a token beyond ClockSkewLeeway must still be rejected.
func TestVerifyWithKeyset_CallerSkewCannotExpandLeeway(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway + 2*time.Minute // well beyond the acceptance window

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, err := VerifyWithKeyset(tokenStr, pubSet, jwt.WithAcceptableSkew(2*time.Hour))
	assert.Error(t, err, "caller WithAcceptableSkew(2h) must not expand the effective leeway beyond ClockSkewLeeway")
}

// keysetVerifyFunctions lists the keyset-based verification helpers so that
// shared-behavior tests can exercise each in a single table-driven test.
// Tests where the helpers differ (e.g., skew tolerance) must remain separate;
// only behaviors that are identical across all helpers belong here.
var keysetVerifyFunctions = []struct {
	name string
	fn   func(string, jwk.Set, ...jwt.ValidateOption) (jwt.Token, error)
}{
	{"VerifyWithKeyset", VerifyWithKeyset},
	{"VerifyWithKeysetStrict", VerifyWithKeysetStrict},
}

// TestKeysetVerifyFunctions_AcceptValidToken confirms that all helpers
// accept a well-formed token with current timestamps.
func TestKeysetVerifyFunctions_AcceptValidToken(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	tokenStr := makeSignedToken(t, privKey, now, now, now.Add(10*time.Minute))

	for _, tc := range keysetVerifyFunctions {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn(tokenStr, pubSet)
			assert.NoError(t, err, "%s should accept a token with current timestamps", tc.name)
		})
	}
}

// TestKeysetVerifyFunctions_WrongKeyRejected confirms that all helpers
// reject a token signed with a key not in the provided JWKS,
// verifying that the signature check is active in each.
func TestKeysetVerifyFunctions_WrongKeyRejected(t *testing.T) {
	_, pubSet := makeTestKeyset(t)
	wrongPrivKey, _ := makeTestKeyset(t) // different key pair

	now := time.Now()
	tokenStr := makeSignedToken(t, wrongPrivKey, now, now, now.Add(10*time.Minute))

	for _, tc := range keysetVerifyFunctions {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn(tokenStr, pubSet)
			assert.Error(t, err, "%s should reject a token signed with a different key", tc.name)
		})
	}
}

// TestKeysetVerifyFunctions_CallerCannotShiftClock confirms that all helpers
// reject a caller-supplied backdated clock.
//
// The token has already expired (exp well beyond ClockSkewLeeway),
// and the caller passes a clock shifted back far enough that the token
// would appear unexpired if the caller's clock were honored.
// All helpers must reject because they override the clock with real time.
func TestKeysetVerifyFunctions_CallerCannotShiftClock(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	// Token issued and valid in the past;
	// expired 5 minutes ago, well beyond ClockSkewLeeway.
	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(-10*time.Minute),
		now.Add(-10*time.Minute),
		now.Add(-5*time.Minute),
	)
	// A clock shifted back 8 minutes: from its perspective, exp is in the future.
	backdatedClock := jwt.ClockFunc(func() time.Time {
		return now.Add(-8 * time.Minute)
	})

	for _, tc := range keysetVerifyFunctions {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn(tokenStr, pubSet, jwt.WithClock(backdatedClock))
			assert.Error(t, err, "%s should reject the expired token even with a backdated caller clock", tc.name)
		})
	}
}

// TestVerify_RejectsSkewedLocalToken confirms
// that Verify rejects a locally-issued token
// whose iat and nbf are slightly in the future (within ClockSkewLeeway)
// when the LocalIssuer check is used.
func TestVerify_RejectsSkewedLocalToken(t *testing.T) {
	// Set up an isolated config state.
	t.Cleanup(func() { config.ResetConfig() })
	config.ResetConfig()

	issuerURL := "https://issuer.example.com:8443"
	kDir := t.TempDir()

	require.NoError(t, param.Server_ExternalWebUrl.Set(issuerURL))
	require.NoError(t, param.IssuerKeysDirectory.Set(kDir))

	// Generate a real key in kDir so GetIssuerPublicJWKS can read it.
	privKey, err := config.GeneratePEM(kDir)
	require.NoError(t, err)

	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window (when not local)

	tokenStr := makeSignedTokenWithIssuer(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
		issuerURL,
	)

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	_, ok, _ := Verify(c, AuthOption{
		Sources: []TokenSource{Header},
		Issuers: []TokenIssuer{LocalIssuer},
	})
	assert.False(t, ok, "Verify should reject a locally-issued token with a future iat/nbf: no skew tolerance for self-signed tokens")
}

// TestVerify_AcceptsSkewedRegisteredServerToken confirms
// that Verify accepts a registered-server token
// whose iat and nbf are slightly in the future (within ClockSkewLeeway)
// when the RegisteredServer check is used.
func TestVerify_AcceptsSkewedRegisteredServerToken(t *testing.T) {
	t.Cleanup(func() {
		// Clear the resolver so other tests are not affected.
		RegisterServerJWKSResolver(nil)
		config.ResetConfig()
		config.ResetFederationForTest()
	})
	config.ResetConfig()
	config.ResetFederationForTest()

	registryURL := "https://registry.example.com:9999"
	privKey, pubSet := makeTestKeyset(t)

	// Register a JWKS resolver that returns our test public key for any server ID.
	RegisterServerJWKSResolver(func(_ *gin.Context, _ string) (jwk.Set, error) {
		return pubSet, nil
	})

	// Configure the federation so checkRegisteredServer can resolve the registry host.
	config.SetFederation(pelican_url.FederationDiscovery{
		RegistryEndpoint: registryURL,
	})

	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window

	// Build a token whose audience is the registry host:port.
	tok, err := jwt.NewBuilder().
		IssuedAt(now.Add(skew)).
		NotBefore(now.Add(skew)).
		Expiration(now.Add(10 * time.Minute)).
		Subject("test-server").
		Audience([]string{"registry.example.com:9999"}).
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
	require.NoError(t, err)
	tokenStr := string(signed)

	req, err := http.NewRequest(http.MethodGet, "/test", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenStr)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	_, ok, verifyErr := Verify(c, AuthOption{
		Sources: []TokenSource{Header},
		Issuers: []TokenIssuer{RegisteredServer},
	})
	assert.NoError(t, verifyErr, "Verify should not return an error for a token whose iat/nbf are within ClockSkewLeeway")
	assert.True(t, ok, "Verify should accept a registered-server token whose iat/nbf are within ClockSkewLeeway")
}

// TestVerifyWithKeysetStrict_RejectsSkewedIatNbf confirms that
// VerifyWithKeysetStrict rejects a token whose iat and nbf are in the future,
// even when the skew is within ClockSkewLeeway.
func TestVerifyWithKeysetStrict_RejectsSkewedIatNbf(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window (when not strict)

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, err := VerifyWithKeysetStrict(tokenStr, pubSet)
	assert.Error(t, err, "VerifyWithKeysetStrict should reject a token whose iat/nbf are in the future")
}

// TestVerifyWithKeysetStrict_RejectsSlightlyExpiredToken confirms that
// VerifyWithKeysetStrict rejects a token that expired a few moments ago,
// even when the gap is within ClockSkewLeeway.
func TestVerifyWithKeysetStrict_RejectsSlightlyExpiredToken(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	pastSkew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window (when not strict)

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(-2*time.Minute),
		now.Add(-2*time.Minute),
		now.Add(-pastSkew),
	)

	_, err := VerifyWithKeysetStrict(tokenStr, pubSet)
	assert.Error(t, err, "VerifyWithKeysetStrict should reject a token that has recently expired")
}

// TestVerifyWithKeysetStrict_CallerCannotAddSkew confirms that
// a caller passing jwt.WithAcceptableSkew(ClockSkewLeeway)
// to VerifyWithKeysetStrict does not widen the acceptance window.
func TestVerifyWithKeysetStrict_CallerCannotAddSkew(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway / 2 // half the leeway — safely inside the acceptance window (when not strict)

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, err := VerifyWithKeysetStrict(tokenStr, pubSet, jwt.WithAcceptableSkew(ClockSkewLeeway))
	assert.Error(t, err, "caller WithAcceptableSkew must not add skew tolerance to VerifyWithKeysetStrict")
}

// TestKeysetVerifyFunctions_CallerCannotResetValidators confirms that
// all helpers neutralize a caller-supplied WithResetValidators(true).
// If honored, that option would disable all default temporal validators,
// causing a clearly-expired token to be accepted.
func TestKeysetVerifyFunctions_CallerCannotResetValidators(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	// Token expired 5 minutes ago — clearly invalid even with ClockSkewLeeway.
	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(-10*time.Minute),
		now.Add(-10*time.Minute),
		now.Add(-5*time.Minute),
	)

	for _, tc := range keysetVerifyFunctions {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.fn(tokenStr, pubSet, jwt.WithResetValidators(true))
			assert.Error(t, err, "%s should reject expired token even when caller passes WithResetValidators(true)", tc.name)
		})
	}
}

// TestSkewedTokenAcceptedByVerifyWithKeysetButRejectedByStrict is the primary
// cross-path regression test for the clock-skew fix (issue #3254).
// It constructs a single token with iat/nbf in the near future (within ClockSkewLeeway)
// and asserts that:
//   - VerifyWithKeyset accepts it (cross-server skew tolerance), and
//   - VerifyWithKeysetStrict rejects it (self-issued, zero-skew path).
func TestSkewedTokenAcceptedByVerifyWithKeysetButRejectedByStrict(t *testing.T) {
	privKey, pubSet := makeTestKeyset(t)
	now := time.Now()
	skew := ClockSkewLeeway / 2 // within leeway for cross-server; out of tolerance for strict

	tokenStr := makeSignedToken(t,
		privKey,
		now.Add(skew),
		now.Add(skew),
		now.Add(10*time.Minute),
	)

	_, withSkewErr := VerifyWithKeyset(tokenStr, pubSet)
	assert.NoError(t, withSkewErr, "VerifyWithKeyset should accept a token within ClockSkewLeeway (cross-server path)")

	_, strictErr := VerifyWithKeysetStrict(tokenStr, pubSet)
	assert.Error(t, strictErr, "VerifyWithKeysetStrict should reject the same token (self-issued path, zero skew)")
}
