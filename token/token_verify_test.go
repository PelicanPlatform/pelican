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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/token_scopes"
)

// MockAuthChecker is the mock implementation of AuthChecker.
type MockAuthChecker struct {
	FederationCheckFunc func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error
	IssuerCheckFunc     func(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error
}

func (m *MockAuthChecker) checkFederationIssuer(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
	return m.FederationCheckFunc(ctx, token, expectedScopes, allScope)
}

func (m *MockAuthChecker) checkLocalIssuer(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScope bool) error {
	return m.IssuerCheckFunc(ctx, token, expectedScopes, allScope)
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
